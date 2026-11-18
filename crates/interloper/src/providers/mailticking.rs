//! mailticking.com: Gmail aliases handed out by the web client's endpoints.
//!
//! generate() asks /get-mailbox for an alias, activates it, then reads the
//! mailbox's 96-hex code off the home page, which renders it for whichever
//! address the `active_mailbox` cookie names. The listing takes the address
//! and that code and nothing else, so the code travels in Address::state and
//! is as good as a password for the inbox.
//!
//! A body is read by message code with the `active_mailbox` cookie. Its answer
//! carries empty sender and subject fields, so get() takes those from the
//! listing row.
//!
//! Only the Gmail types (1 dot, 2 plus, 3 googlemail) are requested; type 4 is
//! the site's own domain.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;
use scraper::{Html, Selector};
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::Transport;

const SITE: &str = "https://www.mailticking.com";
const GMAIL_TYPES: [&str; 3] = ["1", "2", "3"];

static ACTIVE: LazyLock<Selector> = LazyLock::new(|| Selector::parse("input#active-mail").unwrap());
static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]+$").unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::GmailAlias],
    sites: &["mailticking.com"],
    domains: &["gmail.com", "googlemail.com"],
    domain_count: 2,
    // Not measured.
    address_ttl: None,
    message_ttl: Some(days(1)),
    needs_state: true,
    // Answers 429 "Too many requests, please slow down" when hit fast.
    max_concurrency: 1,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "mailticking",
    caps: CAPS,
    build: |t| Arc::new(MailTicking { http: t }),
};

pub struct MailTicking {
    http: Transport,
}

fn mailbox_cookie(a: &Address) -> String {
    urlencoding::encode(&a.value).into_owned()
}

fn sender(r: &J<'_>) -> String {
    let (address, name) = (r.s("FromEmail"), r.s("FromName"));
    if !name.is_empty() && !address.is_empty() {
        format!("{name} <{address}>")
    } else {
        address
    }
}

fn row(r: &J<'_>) -> Result<MessageRow> {
    let id = r.req_id("Code")?;
    if id.is_empty() {
        return Err(r.drift("a non-empty 'Code'"));
    }
    let at = r.value().get("SendTime").and_then(parse_value_time);
    Ok(MessageRow::new(id, sender(r), r.s("Subject")).at(at))
}

/// The `#active-mail` input's code, provided the page shows `email`.
fn code_for(page: &str, email: &str) -> Option<String> {
    let doc = Html::parse_document(page);
    let input = doc.select(&ACTIVE).next()?.value();
    let code = input.attr("data-code").filter(|c| HEX.is_match(c))?;
    // The page renders whichever mailbox the cookie names; a different one
    // means the cookie was ignored and the code would open someone else's.
    (input.attr("value")? == email).then(|| code.to_string())
}

#[async_trait]
impl Provider for MailTicking {
    fn name(&self) -> &str {
        "mailticking"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "mailticking picks both the local part and the domain",
            ));
        }
        let box_ = self
            .http
            .post(format!("{SITE}/get-mailbox"))
            .json_body(&json!({"types": GMAIL_TYPES}))
            .json()
            .await?;
        let j = J::new("mailticking", &box_, "get-mailbox");
        let email = j.at("email")?.str()?;
        let token = j.at("activate_token")?.str()?;
        if email.is_empty() || token.is_empty() {
            return Err(j.drift("'email' and 'activate_token'"));
        }
        let activated = self
            .http
            .post(format!("{SITE}/activate-email"))
            .json_body(&json!({"email": email, "source": "homepage", "activate_token": token}))
            .json()
            .await?;
        if activated.get("success") != Some(&Value::Bool(true)) {
            return Err(Error::drift(
                "mailticking",
                "{\"success\": true} from activate",
                activated,
            ));
        }
        let address = Address::new(email, "mailticking");
        let page = self
            .http
            .get(format!("{SITE}/"))
            .cookie("active_mailbox", mailbox_cookie(&address))
            .text()
            .await?;
        let code = code_for(&page, email).ok_or_else(|| {
            Error::drift(
                "mailticking",
                format!("an #active-mail input for {email}"),
                clip(&page, 200),
            )
        })?;
        Ok(address.with_state(code))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let code = a.state.as_deref().ok_or_else(|| {
            Error::unsupported("mailticking needs the mailbox code issued by generate()")
        })?;
        let v = self
            .http
            .post(format!("{SITE}/get-emails"))
            .query("lang", "")
            .json_body(&json!({"email": a.value, "code": code}))
            .json()
            .await?;
        let j = J::new("mailticking", &v, "get-emails");
        // {"success": false, "needNewEmail": true} is an answer cowbird never
        // learned to read; it stays drift until someone sees what it means.
        if v.get("success") != Some(&Value::Bool(true)) {
            return Err(j.drift("\"success\": true"));
        }
        j.at("emails")?.items()?.iter().map(row).collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let Some(row) = self.list(a).await?.into_iter().find(|r| r.id == id) else {
            return Err(Error::gone("mailticking", id));
        };
        let resp = self
            .http
            .get(format!(
                "{SITE}/mail/gmail-content/{}",
                urlencoding::encode(id)
            ))
            .cookie("active_mailbox", mailbox_cookie(a))
            .send_json()
            .await?;
        if resp.status == 404 {
            return Err(Error::gone("mailticking", id));
        }
        let v = resp.json("mailticking")?;
        let j = J::new("mailticking", &v, "gmail-content");
        // A 403 means the mailbox cookie no longer proves ownership: the
        // protocol moved.
        let result = j.at("result")?;
        if resp.status != 200 || !result.value().is_object() {
            return Err(j.drift("a 'result' message object"));
        }
        Ok(Message::from_bodies(
            id,
            row.sender,
            row.subject,
            row.received_at,
            result.s("content"),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::Body;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mailticking");
    const MESSAGE_ID: &str = "2ef8c84c020fb20c53568171695fc8b4";
    const CODE: &str = "e43a6fad2f505badf8f6b9eeb28bbb87ec20356cb2d496f9f07532ec8594ed90a526cef14f0fb317970adf94721049b2";
    const HOME: &str = "GET https://www.mailticking.com/?";
    const MAILBOX: &str = "POST https://www.mailticking.com/get-mailbox";
    const EMAILS: &str = "POST https://www.mailticking.com/get-emails";
    const CONTENT: &str =
        "GET https://www.mailticking.com/mail/gmail-content/2ef8c84c020fb20c53568171695fc8b4";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        let page = |n| Reply::text(Fixtures::load_text(DIR, n));
        Fixtures::new()
            .route_seq(MAILBOX, [f("mailbox_1.json"), f("mailbox_2.json")])
            .route(
                "POST https://www.mailticking.com/activate-email",
                f("activate.json"),
            )
            .route_seq(HOME, [page("home_1.html"), page("home_2.html")])
            .route(EMAILS, f("emails.json"))
            .route(CONTENT, f("content.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(MailTicking {
            http: w.transport("mailticking", &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("arrogancepchzxp+kish@googlemail.com", "mailticking").with_state(CODE)
    }

    fn json_of(b: &Body) -> &Value {
        match b {
            Body::Json(v) => v,
            other => panic!("not a JSON body: {other:?}"),
        }
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_activates_the_mailbox_and_keeps_its_code_as_state() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, address().value);
        assert_eq!(a.state.as_deref(), Some(CODE));
        let seen = w.seen();
        let activate = seen
            .iter()
            .find(|r| r.url.ends_with("/activate-email"))
            .unwrap();
        let body = json_of(&activate.body);
        assert_eq!(body["email"], address().value);
        assert_eq!(
            body["activate_token"],
            Fixtures::load(DIR, "mailbox_1.json")["activate_token"]
        );
        let home = seen.iter().find(|r| r.url == format!("{SITE}/")).unwrap();
        assert_eq!(
            home.cookies,
            [(
                "active_mailbox".to_string(),
                "arrogancepchzxp%2Bkish%40googlemail.com".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn generate_asks_only_for_gmail_types() {
        let w = wire();
        build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(
            *json_of(&w.seen()[0].body),
            json!({"types": ["1", "2", "3"]})
        );
    }

    #[tokio::test]
    async fn a_page_showing_another_mailbox_is_drift() {
        // If the cookie were ignored, the page's code would read someone
        // else's inbox.
        let w = wire().route(HOME, Reply::text(Fixtures::load_text(DIR, "home_2.html")));
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_page_without_a_code_is_drift() {
        let w = wire().route(HOME, Reply::text("<html></html>"));
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_mailbox_answer_without_email_or_token_is_drift() {
        let w = wire().route(MAILBOX, Reply::json(json!({"success": true, "email": "x"})));
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_chosen_local_or_domain_is_refused() {
        let p = build(&wire());
        for opts in [
            GenerateOptions {
                local: Some("hello".into()),
                ..Default::default()
            },
            GenerateOptions {
                domain: Some("gmail.com".into()),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                p.generate(&opts).await,
                Err(Error::NotSupported(_))
            ));
        }
    }

    #[tokio::test]
    async fn list_sends_the_email_and_the_code_from_state() {
        let w = wire();
        let rows = build(&w).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MESSAGE_ID);
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d34b0ecc)");
        assert_eq!(
            rows[0].received_at,
            Some(jiff::Timestamp::from_second(1790251317).unwrap())
        );
        let req = w.seen().pop().unwrap();
        assert_eq!(
            *json_of(&req.body),
            json!({"email": address().value, "code": CODE})
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(
            EMAILS,
            Reply::json(Fixtures::load(DIR, "emails_empty.json")),
        );
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_without_the_code_is_refused() {
        let a = Address::new(address().value, "mailticking");
        assert!(matches!(
            build(&wire()).list(&a).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_listing_it_does_not_recognise_is_drift() {
        for answer in [
            json!({"success": false, "needNewEmail": true, "error": "expired"}),
            json!({"success": true, "emails": "changed"}),
            json!({"success": true, "emails": [{"Subject": "no code"}]}),
        ] {
            let w = wire().route(EMAILS, Reply::json(answer.clone()));
            assert!(
                matches!(
                    build(&w).list(&address()).await,
                    Err(Error::SchemaDrift { .. })
                ),
                "{answer}"
            );
        }
    }

    #[tokio::test]
    async fn get_reads_the_body_with_the_mailbox_cookie_and_the_headers_from_the_row() {
        let w = wire();
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        let req = w.seen().pop().unwrap();
        assert_eq!(req.url, format!("{SITE}/mail/gmail-content/{MESSAGE_ID}"));
        assert_eq!(
            req.cookies,
            [(
                "active_mailbox".to_string(),
                "arrogancepchzxp%2Bkish%40googlemail.com".to_string()
            )]
        );
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert_eq!(m.subject, "JoltMx test email (ref 01a0d34b0ecc)");
        assert_eq!(
            m.received_at,
            Some(jiff::Timestamp::from_second(1790251317).unwrap())
        );
        assert!(m.text.contains("everything is working as expected"));
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
    }

    #[tokio::test]
    async fn a_message_the_listing_no_longer_has_is_gone() {
        let w = wire().route(
            EMAILS,
            Reply::json(Fixtures::load(DIR, "emails_empty.json")),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_body_the_site_no_longer_has_is_gone() {
        let w = wire().route(
            CONTENT,
            Reply::json(Fixtures::load(DIR, "content_missing.json")).with_status(404),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_refused_body_is_drift() {
        // A 403 means the mailbox cookie no longer proves ownership: the
        // protocol moved.
        let w = wire().route(
            CONTENT,
            Reply::json(json!({"error": "You don't have permission to view this email"}))
                .with_status(403),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
