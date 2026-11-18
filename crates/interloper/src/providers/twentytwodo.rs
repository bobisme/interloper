//! 22.do: Gmail, Outlook and own-domain addresses from one backend.
//!
//! The server picks the kind at random whatever `type` is sent, so asking for
//! one kind means re-rolling. The message body is not in any JSON response:
//! the content page embeds it in an iframe served from /view/<token>.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use serde_json::{Value, json};

use super::util::no_custom_local;
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::{HttpResponse, Transport};

const NAME: &str = "22do";
const API: &str = "https://22.do";

/// gmail came back 2 times in 5 samples. Six tries fail about 1 time in 50 at
/// that rate; raise the bound, or pick from the homepage's prefilled address,
/// if gmail gets rarer.
pub const REROLLS: usize = 6;

static IFRAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)<iframe[^>]*\bsrc="([^"]*/view/[^"]+)""#).unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::GmailAlias, Kind::OutlookAlias, Kind::OwnDomain],
    sites: &["22.do"],
    domain_count: 3,
    address_ttl: Some(days(1)),
    message_ttl: Some(days(1)),
    needs_state: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(TwentyTwoDo { http: t }),
};

pub struct TwentyTwoDo {
    http: Transport,
}

fn kind_of(t: &str) -> Option<Kind> {
    match t {
        "gmail" => Some(Kind::GmailAlias),
        "microsoft" => Some(Kind::OutlookAlias),
        "domain" => Some(Kind::OwnDomain),
        _ => None,
    }
}

fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.time("time")
}

fn expired(a: &Address) -> Error {
    Error::AddressExpired(format!("22do: {} is no longer valid", a.value))
}

/// The `data` of a `{status, msg, data}` envelope. Status is checked before
/// the body is parsed, so a 401 or an HTML error page never reads as drift.
fn data(resp: HttpResponse, path: &str) -> Result<Value> {
    if resp.status >= 400 {
        return Err(Error::down(
            NAME,
            format!("{path} answered HTTP {}", resp.status),
        ));
    }
    let v = resp.json(NAME)?;
    let j = J::new(NAME, &v, path);
    if j.at("status")?.value() != &Value::Bool(true) {
        return Err(Error::down(
            NAME,
            format!("{path} refused: {:?}", j.s("msg")),
        ));
    }
    Ok(v.get("data").cloned().unwrap_or(Value::Null))
}

impl TwentyTwoDo {
    fn token<'a>(&self, a: &'a Address) -> Result<&'a str> {
        a.state
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::unsupported("22do needs the token issued by generate()"))
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(format!("{API}{path}"))
            .json_body(&body)
            .send_json()
            .await?;
        data(resp, path)
    }
}

#[async_trait]
impl Provider for TwentyTwoDo {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        no_custom_local(NAME, opts)?;
        if let Some(d) = &opts.domain {
            return Err(Error::unsupported(format!(
                "22do picks its own domain, not {d}"
            )));
        }
        let want = opts.kind;
        if let Some(k) = want
            && !CAPS.serves(k)
        {
            return Err(Error::unsupported(format!("22do does not issue {k}")));
        }
        let mut email = None;
        for _ in 0..REROLLS {
            let d = self
                .post("/action/mailbox/create", json!({"type": "random"}))
                .await?;
            let j = J::new(NAME, &d, "/action/mailbox/create.data");
            let value = j.at("email")?.str()?.to_string();
            let kind = kind_of(j.at("type")?.str()?);
            if want.is_none() || kind == want {
                email = Some(value);
                break;
            }
        }
        let Some(email) = email else {
            return Err(Error::down(
                NAME,
                format!("no {} address in {REROLLS} tries", want.expect("rerolled")),
            ));
        };
        let uuid = format!("{:032x}", rand::rng().random::<u128>());
        let d = self
            .post(
                "/action/mailbox/applyToken",
                json!({"email": email, "uuid": uuid}),
            )
            .await?;
        let token = J::new(NAME, &d, "/action/mailbox/applyToken.data")
            .at("token")?
            .str()?
            .to_string();
        Ok(Address::new(email, NAME)
            .with_state(token)
            .expiring(CAPS.address_ttl))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let path = "/action/mailbox/message";
        let resp = self
            .http
            .post(format!("{API}{path}"))
            .bearer(self.token(a)?)
            .json_body(&json!({"email": a.value, "lastime": 0}))
            .send_json()
            .await?;
        if resp.status == 401 {
            return Err(expired(a));
        }
        let d = data(resp, path)?;
        // An empty inbox is null, except an empty Outlook one, which is false.
        if matches!(d, Value::Null | Value::Bool(false)) {
            return Ok(vec![]);
        }
        J::new(NAME, &d, "/action/mailbox/message.data")
            .items()?
            .iter()
            .map(|r| {
                Ok(MessageRow::new(r.req_id("messageId")?, r.s("from"), r.s("subject")).at(at(r)))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let token = self.token(a)?;
        let page = self
            .http
            .get(format!("{API}/content/{}", urlencoding::encode(id)))
            .bearer(token)
            .send()
            .await?;
        match page.status {
            401 => return Err(expired(a)),
            404 => return Err(Error::gone(NAME, id)),
            s if s >= 400 => {
                return Err(Error::down(NAME, format!("content page answered HTTP {s}")));
            }
            _ => {}
        }
        let Some(src) = IFRAME.captures(&page.text).map(|c| c[1].to_string()) else {
            return Err(Error::drift(
                NAME,
                "an iframe to /view/ on the content page",
                crate::error::clip(&page.text, 200),
            ));
        };
        let src = if src.starts_with('/') {
            format!("{API}{src}")
        } else {
            src
        };
        let view = self.http.get(src).bearer(token).send().await?;
        if view.status == 401 {
            return Err(expired(a));
        }
        if view.status >= 400 {
            return Err(Error::down(
                NAME,
                format!("view page answered HTTP {}", view.status),
            ));
        }
        // The envelope is only in the listing.
        let row = self.list(a).await?.into_iter().find(|r| r.id == id);
        let (sender, subject, at) = match row {
            Some(r) => (r.sender, r.subject, r.received_at),
            None => (String::new(), String::new(), None),
        };
        Ok(Message::from_bodies(
            id, sender, subject, at, view.text, None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/twentytwodo");
    const MESSAGE_ID: &str = "21b69c071cebbd8fd65c30bfaf652eb7";

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn page(n: &str) -> Reply {
        Reply::text(Fixtures::load_text(DIR, n))
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route_seq(
                "/action/mailbox/create",
                [f("create_gmail.json"), f("create_domain.json")],
            )
            .route("/action/mailbox/applyToken", f("apply_token.json"))
            .route("/action/mailbox/message", f("messages.json"))
            .route("/content/", page("content.html"))
            .route("/view/", page("view.html"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TwentyTwoDo {
            http: w.transport(NAME, &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cb.fixture.one@gmail.com", NAME).with_state("fixture.jwt.token")
    }

    fn creates(w: &Fixtures) -> usize {
        w.seen()
            .iter()
            .filter(|r| r.url.contains("/create"))
            .count()
    }

    fn gmail() -> GenerateOptions {
        GenerateOptions {
            kind: Some(Kind::GmailAlias),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn it_rerolls_until_the_requested_kind_comes_back() {
        let w = wire().route_seq(
            "/action/mailbox/create",
            [
                f("create_domain.json"),
                f("create_domain.json"),
                f("create_gmail.json"),
            ],
        );
        let a = build(&w).generate(&gmail()).await.unwrap();
        assert_eq!(a.value, "cb.fixture.one@gmail.com");
        assert_eq!(a.state.as_deref(), Some("fixture.jwt.token"));
        assert!(a.expires_at.is_some());
        assert_eq!(creates(&w), 3);
    }

    #[tokio::test]
    async fn it_gives_up_after_a_bounded_number_of_rerolls() {
        let w = wire().route("/action/mailbox/create", f("create_domain.json"));
        assert!(matches!(
            build(&w).generate(&gmail()).await,
            Err(Error::ProviderDown { .. })
        ));
        assert_eq!(creates(&w), REROLLS);
    }

    #[tokio::test]
    async fn a_null_data_list_is_an_empty_inbox() {
        let w = wire().route("/action/mailbox/message", f("messages_empty.json"));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_empty_outlook_inbox_answers_false_and_is_still_empty() {
        // Recorded 2026-09-24: every empty Outlook inbox sampled answered
        // false, every empty Gmail and own-domain one answered null.
        let w = wire().route("/action/mailbox/message", f("messages_empty_outlook.json"));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn status_false_on_a_200_is_a_failure() {
        let refused = json!({"status": false, "msg": "Authentication required"});
        let w = wire().route("/action/mailbox/message", Reply::json(refused));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn the_body_comes_from_the_iframe_view() {
        let w = wire();
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.text.contains("482913"), "{}", m.text);
        assert_eq!(m.subject, "Your verification code");
        assert!(
            w.seen()
                .iter()
                .any(|r| r.url == "https://22.do/view/fixtureviewtoken")
        );
    }

    #[tokio::test]
    async fn a_404_content_page_is_gone() {
        let w = wire().route(
            "/content/",
            Reply::text("<html>404</html>").with_status(404),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_content_page_without_the_iframe_is_drift() {
        let w = wire().route("/content/", Reply::text("<html>redesigned</html>"));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_401_on_list_is_address_expired_not_drift() {
        let w = wire().route("/action/mailbox/message", Reply::status(401));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_401_with_html_body_is_address_expired() {
        let w = wire().route(
            "/action/mailbox/message",
            Reply::text("<html><body>Unauthorized</body></html>").with_status(401),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_failing_view_page_is_down() {
        // A 5xx on the view is retried by the transport, then reported down.
        let w = wire().route("/view/", Reply::text("<html>error</html>").with_status(500));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_non_object_row_in_messages_is_drift() {
        let bad = json!({"status": true, "data": [1]});
        let w = wire().route("/action/mailbox/message", Reply::json(bad));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_403_on_generate_does_not_quarantine() {
        let w = wire().route(
            "/action/mailbox/create",
            Reply::text("<html>blocked</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::ProviderDown { .. })
        ));
    }
}
