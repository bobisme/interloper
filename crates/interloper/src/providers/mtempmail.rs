//! mtempmail.com, a site running the Lobage temp-mail script.
//!
//! The inbox is the `email` cookie. POST /get_messages without it mints an
//! inbox and sets the cookie; with it, it lists that inbox, bodies included, so
//! get() never needs the /view page. A cookie that no longer names a live inbox
//! gets a new one back rather than an error, which is why list() checks the
//! mailbox it was answered with. On a shared jar the cookie from one generate()
//! would be sent with the next, so every request runs on a fresh session and
//! the cookie travels in Address::state.
//!
//! The captcha is off here, and get_messages does not check the CSRF token.
//! /change, which renames the current inbox to a chosen name and domain, does.
//! So a chosen address costs a home page load for the token plus a mint to have
//! an inbox to rename.
//!
//! cowbird also served zub.edu.pl (an `.edu.pl` name anyone can take, not a
//! university mailbox) and fraudfindez.com. Checked live on 2026-11-18: the
//! site offers only mtempmail.com, mints only on it, and /change answers 422
//! "problem in this domain" for zub.edu.pl, so both are dropped and the
//! provider no longer serves the edu kind.
//!
//! Inboxes are not private. /change hands anyone the inbox of any name they
//! type, /view/<id> serves a message with no cookie at all, and every answer
//! lists the other addresses minted from the same IP.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use rand::seq::IndexedRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::transport::{HttpResponse, Transport};

const BASE: &str = "https://mtempmail.com";
const DOMAINS: &[&str] = &["mtempmail.com"];
const LIFE: std::time::Duration = hours(24);
static CSRF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).unwrap());
// receivedAt is the site's wall clock, two hours ahead of the UTC it gives
// history times in.
// ponytail: fixed +02:00, so rows read an hour late if the server follows
// Warsaw onto winter time; derive it from Europe/Warsaw if that matters.
const SITE_OFFSET_HOURS: i8 = 2;

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mtempmail.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // "Every address and its messages are deleted 24 hours after the address
    // is created."
    address_ttl: Some(LIFE),
    message_ttl: Some(LIFE),
    custom_local: true,
    needs_state: true,
    max_concurrency: 1,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "mtempmail",
    caps: CAPS,
    build: |t| Arc::new(MTempMail { http: t }),
};

pub struct MTempMail {
    http: Transport,
}

#[derive(Serialize, Deserialize)]
struct State {
    email: String,
}

/// The domains `opts` allows, or `NotSupported` before any request.
fn allowed(opts: &GenerateOptions) -> Result<Vec<&'static str>> {
    if let Some(k) = opts.kind.filter(|k| !CAPS.serves(*k)) {
        return Err(Error::unsupported(format!("mtempmail does not serve {k}")));
    }
    let domains = DOMAINS;
    let Some(want) = &opts.domain else {
        return Ok(domains.to_vec());
    };
    match domains.iter().find(|d| d.eq_ignore_ascii_case(want)) {
        Some(d) => Ok(vec![*d]),
        None => Err(Error::unsupported(format!(
            "mtempmail does not serve {want} here; has {domains:?}"
        ))),
    }
}

fn received(m: &Value) -> Option<jiff::Timestamp> {
    let raw = m.get("receivedAt")?.as_str()?;
    let dt = jiff::civil::DateTime::strptime("%Y-%m-%d %H:%M:%S", raw).ok()?;
    let tz = jiff::tz::TimeZone::fixed(jiff::tz::Offset::constant(SITE_OFFSET_HOURS));
    tz.to_timestamp(dt).ok()
}

fn row(m: &Value) -> MessageRow {
    let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or_default();
    let (name, email) = (s("from"), s("from_email"));
    let sender = match (name.is_empty(), email.is_empty()) {
        (false, false) => format!("{name} <{email}>"),
        (false, true) => name.to_string(),
        _ => email.to_string(),
    };
    MessageRow::new(s("id"), sender, s("subject")).at(received(m))
}

/// A get_messages or /change answer, checked.
fn inbox(data: Value) -> Result<Value> {
    let ok = data.get("mailbox").is_some_and(Value::is_string)
        && data
            .get("messages")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().all(|m| {
                    m.get("id").is_some_and(Value::is_string)
                        && m.get("content").is_some_and(Value::is_string)
                })
            });
    if ok {
        Ok(data)
    } else {
        Err(Error::drift(
            "mtempmail",
            "a 'mailbox' and 'messages' with 'id' and 'content'",
            clip(&data.to_string(), 200),
        ))
    }
}

fn parse(resp: &HttpResponse) -> Result<Value> {
    inbox(resp.json("mtempmail")?)
}

fn address(data: &Value, resp: &HttpResponse) -> Result<Address> {
    let mailbox = data["mailbox"].as_str().unwrap_or_default();
    let cookie = resp
        .cookie("email")
        .ok_or_else(|| Error::drift("mtempmail", "an 'email' cookie", mailbox))?;
    let state = serde_json::to_string(&State { email: cookie }).expect("serializes");
    Ok(Address::new(mailbox, "mtempmail")
        .with_state(state)
        .expiring(Some(LIFE)))
}

fn cookie(a: &Address) -> Result<String> {
    a.state
        .as_deref()
        .and_then(|s| serde_json::from_str::<State>(s).ok())
        .map(|s| s.email)
        .ok_or_else(|| Error::unsupported("mtempmail needs the inbox cookie issued by generate()"))
}

impl MTempMail {
    async fn change(&self, local: &str, domain: &str, inbox_cookie: &str) -> Result<Address> {
        let home = self.http.get(format!("{BASE}/")).send().await?;
        // An error page (an origin or WAF refusing this IP) is an outage,
        // not a new page shape: it must not quarantine the adapter.
        if !home.is_success() {
            return Err(Error::down(
                "mtempmail",
                format!("/ answered HTTP {}", home.status),
            ));
        }
        let csrf = CSRF.captures(&home.text).map(|c| c[1].to_string());
        // Laravel names its session cookie `<app>_session`. It was
        // free_edu_com_temporary_mails_session when cowbird was written and
        // mtempmail_session on 2026-11-18, so it is found by the suffix.
        let session = home
            .cookies()
            .into_iter()
            .find(|(k, _)| k.ends_with("_session"));
        let (Some(token), Some((session_name, session))) = (csrf, session) else {
            return Err(Error::drift(
                "mtempmail",
                "a CSRF token and session from the home page",
                clip(&home.text, 200),
            ));
        };
        let resp = self
            .http
            .post(format!("{BASE}/change"))
            .json_body(&json!({"_token": token, "name": local, "domain": domain}))
            .header("X-Requested-With", "XMLHttpRequest")
            .header("X-CSRF-TOKEN", &token)
            .cookie(session_name, session)
            .cookie("email", inbox_cookie)
            .send_json()
            .await?;
        if resp.status == 422 {
            return Err(Error::unsupported(format!(
                "mtempmail refused {local}@{domain}: {}",
                clip(&resp.text, 200)
            )));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "mtempmail",
                format!("/change answered HTTP {}", resp.status),
            ));
        }
        address(&parse(&resp)?, &resp)
    }

    async fn messages(&self, a: &Address) -> Result<Vec<Value>> {
        let data = inbox(
            self.http
                .post(format!("{BASE}/get_messages"))
                .json_body(&json!({"_token": "", "captcha": ""}))
                .header("X-Requested-With", "XMLHttpRequest")
                .cookie("email", cookie(a)?)
                .json()
                .await?,
        )?;
        if data["mailbox"].as_str() != Some(a.value.as_str()) {
            return Err(Error::AddressExpired(format!(
                "mtempmail: {} is gone",
                a.value
            )));
        }
        Ok(data["messages"].as_array().cloned().unwrap_or_default())
    }
}

#[async_trait]
impl Provider for MTempMail {
    fn name(&self) -> &str {
        "mtempmail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let allowed = allowed(opts)?;
        let resp = self
            .http
            .post(format!("{BASE}/get_messages"))
            .json_body(&json!({"_token": "", "captcha": ""}))
            .header("X-Requested-With", "XMLHttpRequest")
            .send_json()
            .await?;
        let minted = address(&parse(&resp)?, &resp)?;
        let (local, domain) = minted
            .value
            .rsplit_once('@')
            .ok_or_else(|| Error::drift("mtempmail", "an address", &minted.value))?;
        let landed = allowed.iter().any(|d| d.eq_ignore_ascii_case(domain));
        if opts.local.is_none() && landed {
            return Ok(minted);
        }
        let target = if landed {
            domain.to_string()
        } else {
            allowed
                .choose(&mut rand::rng())
                .expect("allowed is never empty")
                .to_string()
        };
        let local = opts.local.as_deref().unwrap_or(local);
        self.change(local, &target, &cookie(&minted)?).await
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        Ok(self.messages(a).await?.iter().map(row).collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let rows = self.messages(a).await?;
        let Some(found) = rows.iter().find(|m| m["id"].as_str() == Some(id)) else {
            return Err(Error::gone("mtempmail", id));
        };
        let r = row(found);
        let content = found["content"].as_str().unwrap_or_default().to_string();
        // The site flags plain-text mail with `html: false`.
        let (html, text) = if found.get("html") == Some(&Value::Bool(false)) {
            (String::new(), Some(content))
        } else {
            (content, None)
        };
        Ok(Message::from_bodies(
            id,
            r.sender,
            r.subject,
            r.received_at,
            html,
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mtempmail");
    const MINT: &str = "POST https://mtempmail.com/get_messages";
    const INBOX_1: &str = "fixture-inbox-one";
    const INBOX_2: &str = "fixture-inbox-two";
    const INBOX_CHANGED: &str = "fixture-inbox-changed";
    const HOME: &str = "GET https://mtempmail.com/?";
    const CHANGE: &str = "POST https://mtempmail.com/change";
    // What the site named its Laravel session cookie on 2026-11-18.
    const SESSION: &str = "mtempmail_session";
    const CHANGED: &str = "cowbirdprobe9051@mtempmail.com";

    /// A listing is the mint request plus the inbox cookie. Routed on body
    /// and cookie together so it outranks MINT but not /change, which sends
    /// the cookie as well.
    fn listing(inbox: &str) -> String {
        format!(r#"{MINT}? {{"_token":"","captcha":""}} email={inbox}"#)
    }

    fn load(name: &str) -> Value {
        Fixtures::load(DIR, name)
    }

    /// The recorded mail, served for the first generated inbox.
    fn with_mail() -> Value {
        let mut v = load("messages_new_1.json");
        v["messages"] = load("messages_one.json")["messages"].clone();
        v
    }

    fn mail_id() -> String {
        with_mail()["messages"][0]["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route_seq(
                MINT,
                [
                    Reply::json(load("messages_new_1.json")).set_cookie("email", INBOX_1),
                    Reply::json(load("messages_new_2.json")).set_cookie("email", INBOX_2),
                ],
            )
            .route(&listing(INBOX_1), Reply::json(with_mail()))
            .route(&listing(INBOX_2), Reply::json(load("messages_new_2.json")))
            .route(
                HOME,
                Reply::text(Fixtures::load_text(DIR, "home.html"))
                    .set_cookie(SESSION, "fixture-session"),
            )
            .route(
                CHANGE,
                Reply::json(change()).set_cookie("email", INBOX_CHANGED),
            )
    }

    /// The recorded /change answer, renamed onto the one domain still served
    /// (it was recorded for zub.edu.pl).
    fn change() -> Value {
        let mut v = load("change.json");
        v["mailbox"] = json!(CHANGED);
        v
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(MTempMail {
            http: w.transport("mtempmail", &CAPS),
        })
    }

    fn inbox_at(value: &str, cookie: &str) -> Address {
        Address::new(value, "mtempmail").with_state(
            serde_json::to_string(&State {
                email: cookie.into(),
            })
            .unwrap(),
        )
    }

    fn first() -> Address {
        inbox_at(
            load("messages_new_1.json")["mailbox"].as_str().unwrap(),
            INBOX_1,
        )
    }

    fn second() -> Address {
        inbox_at(
            load("messages_new_2.json")["mailbox"].as_str().unwrap(),
            INBOX_2,
        )
    }

    fn sent(w: &Fixtures, method: &str, path: &str) -> Vec<HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url == format!("{BASE}{path}"))
            .collect()
    }

    fn body(r: &HttpRequest) -> Value {
        match &r.body {
            Body::Json(v) => v.clone(),
            other => panic!("not json: {other:?}"),
        }
    }

    fn state_of(a: &Address) -> String {
        serde_json::from_str::<State>(a.state.as_deref().unwrap())
            .unwrap()
            .email
    }

    fn opts(local: Option<&str>, domain: Option<&str>, kind: Option<Kind>) -> GenerateOptions {
        GenerateOptions {
            local: local.map(Into::into),
            domain: domain.map(Into::into),
            kind,
        }
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn it_runs_each_request_on_a_fresh_session() {
        // On a shared jar a second generate() would send the first inbox's
        // cookie and get the first address back.
        const { assert!(CAPS.fresh_session) };
        const { assert!(CAPS.needs_state) };
    }

    #[test]
    fn it_no_longer_serves_the_edu_pl_domain() {
        // Gone from the site's domain list and refused by /change (2026-11-18).
        assert!(!CAPS.serves(Kind::Edu));
        assert!(!CAPS.domains.contains(&"zub.edu.pl"));
    }

    #[tokio::test]
    async fn generate_keeps_the_inbox_cookie_in_state() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, load("messages_new_1.json")["mailbox"]);
        assert_eq!(state_of(&a), INBOX_1);
        assert!(a.expires_at.is_some());
        let mint = sent(&w, "POST", "/get_messages");
        assert_eq!(mint.len(), 1);
        assert!(mint[0].cookies.is_empty());
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn list_and_get_replay_the_inbox_cookie() {
        let w = wire();
        let p = build(&w);
        p.list(&first()).await.unwrap();
        p.get(&first(), &mail_id()).await.unwrap();
        let replays = sent(&w, "POST", "/get_messages");
        assert_eq!(replays.len(), 2);
        for r in replays {
            assert_eq!(r.cookies, vec![("email".to_string(), INBOX_1.to_string())]);
        }
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        assert!(build(&wire()).list(&second()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_reads_the_row() {
        let rows = build(&wire()).list(&first()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, mail_id());
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d79f4181)");
        // receivedAt is the site's local time, two hours ahead of UTC.
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T08:12:13Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn get_reads_the_body_the_listing_carries() {
        let m = build(&wire()).get(&first(), &mail_id()).await.unwrap();
        assert_eq!(m.id, mail_id());
        assert_eq!(m.subject, "JoltMx test email (ref 01a0d79f4181)");
        assert!(m.html.starts_with("<!DOCTYPE html>"));
        assert!(m.text.contains("This is a test email from JoltMx"));
        assert!(m.links.iter().any(|l| l == "https://joltmx.com"));
    }

    #[tokio::test]
    async fn a_plain_text_message_is_read_as_text() {
        // Synthetic: the recorded row with the site's `html: false` flag.
        let mut v = with_mail();
        v["messages"][0]["html"] = Value::Bool(false);
        v["messages"][0]["content"] = json!("code 123456");
        let w = wire().route(&listing(INBOX_1), Reply::json(v));
        let m = build(&w).get(&first(), &mail_id()).await.unwrap();
        assert_eq!(m.text, "code 123456");
        assert_eq!(m.html, "");
    }

    #[tokio::test]
    async fn a_message_the_listing_no_longer_has_is_gone() {
        assert!(matches!(
            build(&wire()).get(&first(), "no-such-id").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_cookie_the_site_answers_with_another_inbox_is_expired() {
        // A cookie that no longer names a live inbox gets a freshly minted one.
        let stale = inbox_at("gone@zub.edu.pl", INBOX_2);
        assert!(matches!(
            build(&wire()).list(&stale).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_listing_it_does_not_recognise_is_drift() {
        let mut none = load("messages_new_1.json");
        none["messages"] = json!("none");
        let mut no_id = load("messages_new_1.json");
        no_id["messages"] = json!([{"subject": "no id"}]);
        let mut null_content = load("messages_new_1.json");
        null_content["messages"] = json!([{"id": "1", "content": null}]);
        for answer in [
            Reply::json(json!({"status": false})),
            Reply::json(none),
            Reply::json(no_id),
            Reply::json(null_content),
            Reply::text("<html>maintenance</html>"),
        ] {
            let w = wire().route(&listing(INBOX_1), answer);
            let got = build(&w).list(&first()).await;
            assert!(matches!(got, Err(Error::SchemaDrift { .. })), "{got:?}");
        }
    }

    #[tokio::test]
    async fn a_mint_without_the_inbox_cookie_is_drift() {
        let w = wire().route(MINT, Reply::json(load("messages_new_1.json")));
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn list_without_usable_state_is_refused() {
        let p = build(&wire());
        for bad in [None, Some(""), Some("not json"), Some(r#"{"cookie": "x"}"#)] {
            let a = Address {
                state: bad.map(String::from),
                ..first()
            };
            assert!(
                matches!(p.list(&a).await, Err(Error::NotSupported(_))),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_chosen_local_part_and_domain_go_through_change() {
        let w = wire();
        let a = build(&w)
            .generate(&opts(Some("cowbirdprobe9051"), Some("mtempmail.com"), None))
            .await
            .unwrap();
        assert_eq!(a.value, CHANGED);
        assert_eq!(state_of(&a), INBOX_CHANGED);
        let change = sent(&w, "POST", "/change");
        assert_eq!(change.len(), 1);
        let token = "0".repeat(40);
        assert_eq!(
            body(&change[0]),
            json!({"_token": token, "name": "cowbirdprobe9051", "domain": "mtempmail.com"})
        );
        assert_eq!(change[0].header("X-CSRF-TOKEN"), Some(token.as_str()));
        assert_eq!(
            change[0].cookies,
            vec![
                (SESSION.to_string(), "fixture-session".to_string()),
                ("email".to_string(), INBOX_1.to_string())
            ]
        );
    }

    #[tokio::test]
    async fn a_domain_the_mint_already_landed_on_needs_no_change() {
        let w = wire();
        let minted = load("messages_new_1.json")["mailbox"]
            .as_str()
            .unwrap()
            .to_string();
        let domain = minted.split_once('@').unwrap().1;
        let a = build(&w)
            .generate(&opts(None, Some(domain), None))
            .await
            .unwrap();
        assert_eq!(a.value, minted);
        assert!(sent(&w, "POST", "/change").is_empty());
    }

    #[tokio::test]
    async fn a_mint_on_a_domain_no_longer_served_is_moved_to_one_that_is() {
        // The second recorded mint landed on zub.edu.pl, no longer offered.
        let w = wire();
        let p = build(&w);
        p.generate(&GenerateOptions::default()).await.unwrap();
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(a.value, CHANGED);
        let change = sent(&w, "POST", "/change");
        assert_eq!(change.len(), 1);
        let minted = load("messages_new_2.json")["mailbox"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(body(&change[0])["name"], minted.split_once('@').unwrap().0);
        assert_eq!(body(&change[0])["domain"], "mtempmail.com");
    }

    #[tokio::test]
    async fn the_session_cookie_is_found_by_its_suffix() {
        // The name cowbird recorded; the site has been renamed since.
        let w = wire().route(
            HOME,
            Reply::text(Fixtures::load_text(DIR, "home.html"))
                .set_cookie("free_edu_com_temporary_mails_session", "old"),
        );
        build(&w)
            .generate(&opts(Some("abc"), None, None))
            .await
            .unwrap();
        let change = sent(&w, "POST", "/change");
        assert_eq!(
            change[0].cookies[0],
            (
                "free_edu_com_temporary_mails_session".to_string(),
                "old".to_string()
            )
        );
    }

    #[tokio::test]
    async fn what_it_does_not_serve_is_refused_before_any_request() {
        for o in [
            opts(None, Some("gmail.com"), None),
            opts(None, None, Some(Kind::GmailAlias)),
            opts(None, None, Some(Kind::Edu)),
            opts(None, Some("zub.edu.pl"), None),
        ] {
            let w = wire();
            assert!(matches!(
                build(&w).generate(&o).await,
                Err(Error::NotSupported(_))
            ));
            assert!(w.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn a_name_the_site_rejects_is_not_supported() {
        let w = wire().route(
            CHANGE,
            Reply::json(load("change_bad_domain.json")).with_status(422),
        );
        assert!(matches!(
            build(&w)
                .generate(&opts(Some("x1"), Some("mtempmail.com"), None))
                .await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_change_answer_it_does_not_recognise_is_drift() {
        // "return" is what /change answers a session holding no inbox.
        for answer in [
            Reply::text("return"),
            Reply::json(json!({"message": "CSRF token mismatch."})),
        ] {
            let w = wire().route(CHANGE, answer);
            assert!(matches!(
                build(&w)
                    .generate(&opts(Some("abc"), Some("mtempmail.com"), None))
                    .await,
                Err(Error::SchemaDrift { .. })
            ));
        }
    }

    #[tokio::test]
    async fn a_home_page_without_a_csrf_token_is_drift() {
        let w = wire().route(HOME, Reply::text("<html></html>"));
        assert!(matches!(
            build(&w).generate(&opts(Some("abc"), None, None)).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
