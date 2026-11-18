//! smailpro.com — Gmail and Outlook aliases, behind a Cloudflare Turnstile.
//!
//! Creating an alias and reading a message body each need a fresh Turnstile
//! token in `x-captcha`; tokens are single-use, so every such call costs one
//! solve. Listing the inbox needs none. No csrf token, session cookie or XHR
//! header is checked: each call stands alone.
//!
//! The inbox is opened by `{address, timestamp, key}` from create, so
//! timestamp and key travel in Address::state; the key is as good as a
//! password for the box. /app/inbox answers with a re-signed key each time,
//! but the original keeps working, so state never has to change. A key the
//! site refuses comes back as `key: null, payload: null`, which its own page
//! reports as "This email expired!".
//!
//! A sender is only a display name: api.sonjj.com drops the address from its
//! listing, and the body answer carries no headers.
//!
//! smailpro only brokers: it signs a payload that api.sonjj.com, a separate
//! host, redeems for the listing or the body. A message body is fetched by
//! address and message id alone, without the key.
//!
//! Only the free tier is requested: `username=random`, `type=alias`, and
//! server 1. A chosen local part, a "real" account and servers 2+ are
//! premium. Asking for hotmail.com or any other Microsoft domain on the free
//! tier returns an outlook.com address, so outlook.com is the only one
//! claimed.

use std::sync::Arc;

use async_trait::async_trait;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::transport::Transport;

const NAME: &str = "smailpro";
const SITE: &str = "https://smailpro.com";
const PAGE: &str = "https://smailpro.com/temporary-email";
const SITEKEY: &str = "0x4AAAAAAABIS_gEec2IwOhI";
const SONJJ: &str = "https://api.sonjj.com/v1";

/// Domain -> the api.sonjj.com service that reads it.
const SERVICES: &[(&str, &str)] = &[
    ("gmail.com", "temp_gmail"),
    ("googlemail.com", "temp_gmail"),
    ("outlook.com", "temp_outlook"),
];

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::GmailAlias, Kind::OutlookAlias],
    sites: &["smailpro.com"],
    domains: &["gmail.com", "googlemail.com", "outlook.com"],
    domain_count: 3,
    // Not measured. The key carries its creation time, so it may age out.
    address_ttl: None,
    message_ttl: None,
    needs_state: true,
    needs_solver: true,
    // Every create and body read waits on a solve (4.7-9.7s observed).
    max_concurrency: 2,
    poll_interval: std::time::Duration::from_secs(10),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(SmailPro { http: t }),
};

pub struct SmailPro {
    http: Transport,
}

/// Field order is the wire order: state is compact JSON, timestamp first.
#[derive(Serialize, Deserialize)]
struct State {
    timestamp: i64,
    key: String,
}

fn at(v: Option<&Value>) -> Option<Timestamp> {
    jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(v?.as_str()?)
        .ok()
}

/// smailpro answers a Turnstile token it will not accept with
/// `{"code": 403, "msg": "Captcha is invalid"}`. That is the solver's fault,
/// not a change in smailpro's API, so it must not quarantine the provider.
fn refused_token(data: &Value) -> Result<()> {
    let msg = match data.get("msg") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => return Ok(()),
    };
    if msg.to_lowercase().contains("captcha") {
        return Err(Error::SolverUnavailable(format!(
            "{NAME} refused the Turnstile token: {msg}"
        )));
    }
    Ok(())
}

fn domain(opts: &GenerateOptions) -> Result<String> {
    if opts.local.is_some() {
        return Err(Error::unsupported(
            "smailpro picks the local part on its free tier",
        ));
    }
    let default = match opts.kind {
        None | Some(Kind::GmailAlias) => "gmail.com",
        Some(Kind::OutlookAlias) => "outlook.com",
        Some(k) => return Err(Error::unsupported(format!("{NAME} does not serve {k}"))),
    };
    let domain = opts.domain.as_deref().unwrap_or(default);
    if !SERVICES.iter().any(|(d, _)| *d == domain) {
        return Err(Error::unsupported(format!(
            "{NAME} does not serve {domain}"
        )));
    }
    if let Some(k) = opts.kind
        && (domain == "outlook.com") != (k == Kind::OutlookAlias)
    {
        return Err(Error::unsupported(format!("{domain} is not a {k} address")));
    }
    Ok(domain.to_string())
}

fn service(a: &Address) -> &'static str {
    let domain = a.domain().to_lowercase();
    SERVICES
        .iter()
        .find(|(d, _)| *d == domain)
        .map_or("temp_gmail", |(_, s)| s)
}

impl SmailPro {
    async fn captcha(&self) -> Result<String> {
        self.http
            .turnstile_solver()?
            .turnstile(PAGE, SITEKEY, None, None)
            .await
    }

    async fn payload(&self, a: &Address) -> Result<String> {
        let st: State = a
            .state
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .ok_or_else(|| {
                Error::unsupported("smailpro needs the timestamp and key issued by generate()")
            })?;
        let data = self
            .http
            .post(format!("{SITE}/app/inbox"))
            .json_body(&json!([{"address": a.value, "timestamp": st.timestamp, "key": st.key}]))
            .json()
            .await?;
        let entry = data
            .get(0)
            .and_then(Value::as_object)
            .filter(|e| e.contains_key("payload"));
        let Some(entry) = entry else {
            return Err(Error::drift(NAME, "[{'payload': ...}] from inbox", data));
        };
        match &entry["payload"] {
            Value::Null => Err(Error::AddressExpired(format!(
                "smailpro refused the key for {}",
                a.value
            ))),
            Value::String(p) => Ok(p.clone()),
            _ => Err(Error::drift(NAME, "a string payload from inbox", data)),
        }
    }
}

#[async_trait]
impl Provider for SmailPro {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = domain(opts)?;
        let token = self.captcha().await?;
        let data = self
            .http
            .get(format!("{SITE}/app/create"))
            .query("username", "random")
            .query("type", "alias")
            .query("domain", &domain)
            .query("server", "1")
            .header("x-captcha", token)
            .json()
            .await?;
        refused_token(&data)?;
        let address = data
            .get("address")
            .and_then(Value::as_str)
            .filter(|a| a.contains('@'));
        let timestamp = data.get("timestamp").and_then(Value::as_i64);
        let key = data
            .get("key")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty());
        let (Some(address), Some(timestamp), Some(key)) = (address, timestamp, key) else {
            return Err(Error::drift(
                NAME,
                "'address', 'timestamp', 'key' from create",
                data,
            ));
        };
        let state = serde_json::to_string(&State {
            timestamp,
            key: key.to_string(),
        })
        .expect("serializes");
        Ok(Address::new(address, NAME).with_state(state))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let payload = self.payload(a).await?;
        let data = self
            .http
            .get(format!("{SONJJ}/{}/inbox", service(a)))
            .query("payload", payload)
            .json()
            .await?;
        let rows = data.get("messages").and_then(Value::as_array);
        let ok = rows.is_some_and(|rows| {
            rows.iter().all(|r| {
                r.get("mid")
                    .and_then(Value::as_str)
                    .is_some_and(|m| !m.is_empty())
            })
        });
        let (true, Some(rows)) = (ok, rows) else {
            return Err(Error::drift(NAME, "'messages' rows with 'mid'", data));
        };
        let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Ok(rows
            .iter()
            .map(|r| {
                MessageRow::new(s(r, "mid"), s(r, "textFrom").trim(), s(r, "textSubject"))
                    .at(at(r.get("textDate")))
            })
            .collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        // The body answer carries no headers, so they come from the listing,
        // which costs no solve and spares one for an id that is already gone.
        let row = self
            .list(a)
            .await?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| Error::gone(NAME, id))?;
        let token = self.captcha().await?;
        let resp = self
            .http
            .get(format!("{SITE}/app/message"))
            .query("email", &a.value)
            .query("mid", id)
            .header("x-captcha", token)
            .send_json()
            .await?;
        let payload = resp.text.trim();
        if resp.status == 403 {
            // A non-JSON 403 falls through to drift.
            if let Ok(v) = serde_json::from_str::<Value>(payload) {
                refused_token(&v)?;
            }
        }
        if resp.status != 200 || payload.is_empty() {
            return Err(Error::drift(
                NAME,
                "a signed payload from message",
                clip(&resp.text, 200),
            ));
        }
        let data = self
            .http
            .get(format!("{SONJJ}/{}/message", service(a)))
            .query("payload", payload)
            .json()
            .await?;
        if data
            .pointer("/detail/error/message")
            .and_then(Value::as_str)
            == Some("Message not found!")
        {
            return Err(Error::gone(NAME, id));
        }
        let Some(html) = data.get("body").and_then(Value::as_str) else {
            return Err(Error::drift(NAME, "a 'body' from message", data));
        };
        Ok(Message::from_bodies(
            id,
            row.sender,
            row.subject,
            row.received_at,
            html,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::Solver;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/smailpro");
    const MID: &str = "1a0d4b40fe403564";
    const GMAIL: &str = "p.ool.acc.ount.one@gmail.com";
    const STATE: &str = r#"{"timestamp":1790274915,"key":"KEY-PLACEHOLDER"}"#;

    const CREATE: &str = "GET https://smailpro.com/app/create";
    const INBOX: &str = "POST https://smailpro.com/app/inbox";
    const MESSAGE: &str = "GET https://smailpro.com/app/message";
    const GMAIL_INBOX: &str = "GET https://api.sonjj.com/v1/temp_gmail/inbox";
    const GMAIL_MESSAGE: &str = "GET https://api.sonjj.com/v1/temp_gmail/message";
    const OUTLOOK_INBOX: &str = "GET https://api.sonjj.com/v1/temp_outlook/inbox";

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn wire() -> Arc<Fixtures> {
        let first = load("create_gmail.json");
        let mut second = first.clone();
        second["address"] = json!("other.alias@gmail.com");
        Fixtures::new()
            // Two answers so the contract's two generates get two addresses.
            .route_seq(CREATE, [Reply::json(first), Reply::json(second)])
            .route(INBOX, Reply::json(load("inbox.json")))
            .route(GMAIL_INBOX, Reply::json(load("sonjj_inbox.json")))
            .route(OUTLOOK_INBOX, Reply::json(load("sonjj_inbox_empty.json")))
            .route(
                MESSAGE,
                Reply::text(Fixtures::load_text(DIR, "message_payload.txt")),
            )
            .route(GMAIL_MESSAGE, Reply::json(load("sonjj_message.json")))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport(NAME, &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(SmailPro { http: t })
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new(GMAIL, NAME).with_state(STATE)
    }

    /// Requests whose method and URL match `prefix` exactly (query aside).
    fn sent(w: &Fixtures, prefix: &str) -> Vec<HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url == url)
            .collect()
    }

    fn query(r: &HttpRequest) -> Vec<(&str, &str)> {
        r.query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    /// (url, sitekey) of every solve asked for.
    fn solves(s: &Fixtures) -> Vec<(String, String)> {
        s.seen()
            .iter()
            .map(|r| match &r.body {
                Body::Json(v) => (
                    v["url"].as_str().unwrap().to_string(),
                    v["sitekey"].as_str().unwrap().to_string(),
                ),
                _ => panic!("solver body"),
            })
            .collect()
    }

    #[tokio::test]
    async fn create_sends_a_turnstile_token_in_x_captcha() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(solves(&s), [(PAGE.to_string(), SITEKEY.to_string())]);
        assert_eq!(sent(&w, CREATE)[0].header("x-captcha"), Some("fake-token"));
    }

    #[tokio::test]
    async fn generate_carries_timestamp_and_key_in_compact_state() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, GMAIL);
        assert_eq!(a.state.as_deref(), Some(STATE));
    }

    #[tokio::test]
    async fn each_message_read_solves_its_own_token() {
        let (w, s) = (wire(), solver_wire());
        let p = build_with(&w, Some(&s));
        p.get(&address(), MID).await.unwrap();
        p.get(&address(), MID).await.unwrap();
        assert_eq!(s.seen().len(), 2);
        let reads = sent(&w, MESSAGE);
        assert!(
            reads
                .iter()
                .all(|r| r.header("x-captcha") == Some("fake-token"))
        );
        assert_eq!(query(&reads[0]), [("email", GMAIL), ("mid", MID)]);
    }

    #[tokio::test]
    async fn the_inbox_call_carries_no_captcha_and_replays_the_state() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s)).list(&address()).await.unwrap();
        assert!(s.seen().is_empty());
        let inbox = sent(&w, INBOX);
        assert!(inbox.iter().all(|r| r.header("x-captcha").is_none()));
        assert_eq!(
            inbox[0].body,
            Body::Json(
                json!([{"address": GMAIL, "timestamp": 1790274915, "key": "KEY-PLACEHOLDER"}])
            )
        );
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MID);
        assert_eq!(rows[0].sender, "Xeramail Test");
        assert_eq!(rows[0].subject, "Your Email Test is Successful!");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-24T18:36:04Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn get_reads_the_body() {
        let m = build(&wire()).get(&address(), MID).await.unwrap();
        assert_eq!(m.id, MID);
        assert_eq!(m.subject, "Your Email Test is Successful!");
        assert!(
            m.text
                .contains("your email address is working successfully"),
            "{}",
            m.text
        );
        assert!(m.html.trim_start().starts_with("<div"));
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let r = build_with(&wire(), None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_solver_get_is_solver_unavailable() {
        let r = build_with(&wire(), None).get(&address(), MID).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn solver_unavailable_propagates_unchanged() {
        let w = wire();
        let s = Fixtures::new().route("/turnstile", Reply::status(500));
        let r = build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, CREATE).is_empty());
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(GMAIL_INBOX, Reply::json(load("sonjj_inbox_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_message_the_backend_no_longer_has_is_gone() {
        let w = wire().route(
            GMAIL_MESSAGE,
            Reply::json(load("sonjj_message_gone.json")).with_status(400),
        );
        let r = build(&w).get(&address(), MID).await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn a_message_not_in_the_listing_is_gone_without_a_solve() {
        let s = solver_wire();
        let r = build_with(&wire(), Some(&s))
            .get(&address(), "ffffffffffffffff")
            .await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn a_rejected_key_is_an_expired_address() {
        let w = wire().route(INBOX, Reply::json(load("inbox_rejected.json")));
        let r = build(&w).list(&address()).await;
        assert!(matches!(r, Err(Error::AddressExpired(_))), "{r:?}");
    }

    #[tokio::test]
    async fn list_without_state_is_not_supported() {
        let r = build(&wire()).list(&Address::new(GMAIL, NAME)).await;
        assert!(matches!(r, Err(Error::NotSupported(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_malformed_answer_is_drift() {
        for (route, answer) in [
            (INBOX, json!({"x": 1})),
            (GMAIL_INBOX, json!({"x": 1})),
            (
                GMAIL_INBOX,
                json!({"messages": [{"textSubject": "no mid"}]}),
            ),
            (GMAIL_MESSAGE, json!({"x": 1})),
        ] {
            let w = wire().route(route, Reply::json(answer));
            let r = build(&w).get(&address(), MID).await;
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{route}: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_outlook_kind_asks_for_outlook_and_reads_its_inbox() {
        let w = wire().route(CREATE, Reply::json(load("create_outlook.json")));
        let p = build(&w);
        let a = p
            .generate(&GenerateOptions {
                kind: Some(Kind::OutlookAlias),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(a.value.ends_with("@outlook.com"));
        assert!(query(&sent(&w, CREATE)[0]).contains(&("domain", "outlook.com")));
        assert!(p.list(&a).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn googlemail_can_be_chosen_by_domain() {
        let w = wire();
        build(&w)
            .generate(&GenerateOptions {
                domain: Some("googlemail.com".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(
            query(&sent(&w, CREATE)[0]),
            [
                ("username", "random"),
                ("type", "alias"),
                ("domain", "googlemail.com"),
                ("server", "1"),
            ]
        );
    }

    #[tokio::test]
    async fn what_the_free_tier_cannot_do_is_refused_before_a_solve() {
        let o = |kind: Option<Kind>, local: Option<&str>, domain: Option<&str>| GenerateOptions {
            kind,
            local: local.map(String::from),
            domain: domain.map(String::from),
        };
        for opts in [
            o(None, Some("me"), None),
            o(None, None, Some("yahoo.com")),
            o(Some(Kind::OutlookAlias), None, Some("gmail.com")),
            o(Some(Kind::Edu), None, None),
        ] {
            let s = solver_wire();
            let r = build_with(&wire(), Some(&s)).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}: {r:?}");
            assert!(s.seen().is_empty());
        }
    }

    /// A refused Turnstile token says nothing about smailpro's API, so it must
    /// not quarantine the provider.
    #[tokio::test]
    async fn a_token_smailpro_rejects_is_the_solvers_fault_not_drift() {
        for route in [CREATE, MESSAGE] {
            let w = wire().route(
                route,
                Reply::json(load("captcha_invalid.json")).with_status(403),
            );
            let p = build(&w);
            let r = if route == CREATE {
                p.generate(&GenerateOptions::default()).await.map(|_| ())
            } else {
                p.get(&address(), MID).await.map(|_| ())
            };
            assert!(
                matches!(r, Err(Error::SolverUnavailable(_))),
                "{route}: {r:?}"
            );
        }
    }
}
