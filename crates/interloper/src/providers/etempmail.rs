//! etempmail.com: .edu.pl addresses behind a Cloudflare Turnstile.
//!
//! Creating an address costs one Turnstile solve, sent as the form field
//! `cf_token` to /getEmailAddress. A call without a valid token either gets a
//! 403 "Bot detected!" or, with no token at all, a decoy
//! `never.gonna.give.you.up...` address; both mean the token was refused, so
//! both are the solver's fault.
//!
//! The inbox is keyed on the CodeIgniter `ci_session` cookie: on a shared jar
//! a second create hands back the first address. So every request runs on a
//! fresh session and the cookie travels in Address::state; whoever holds it
//! reads the mail. A session the site no longer knows gets an empty body from
//! /getInbox.
//!
//! /getInbox answers with every message in full (`subject`, `from`, `date`,
//! `body`) and no id; the site's own /email?id=N is a 1-based index into it
//! that renders the body into an iframe behind Cloudflare's address
//! obfuscation. get() reads the listing instead, and ids are a hash of the
//! row, so they do not shift when new mail arrives. Reading mail never costs a
//! solve.
//!
//! The domain is the site's pick: its /changeEmailAddress answers 404.

use std::sync::Arc;

use async_trait::async_trait;
use jiff::Timestamp;
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::transport::Transport;

const NAME: &str = "etempmail";
const SITE: &str = "https://etempmail.com";
const PAGE: &str = "https://etempmail.com/";
const SITEKEY: &str = "0x4AAAAAADgCwAbwHVdgg5az";
const COOKIE: &str = "ci_session";
const DOMAINS: &[&str] = &["temporarmail.edu.pl", "mats.edu.pl", "securemail.edu.pl"];
/// The page counts an address down from `creation_time` over `data-minutes`.
const LIFE_MINUTES: u64 = 20;
/// Row dates are Istanbul wall-clock time, which has no DST.
const SITE_UTC_OFFSET_HOURS: i8 = 3;
const DECOY: &str = "never.gonna.give.you.up";
const ROW_FIELDS: [&str; 4] = ["subject", "from", "date", "body"];

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::Edu],
    sites: &["etempmail.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    address_ttl: Some(minutes(LIFE_MINUTES)),
    // Mail lives as long as its inbox.
    message_ttl: None,
    needs_state: true,
    needs_solver: true,
    fresh_session: true,
    // Every create waits on a solve (~7s).
    max_concurrency: 2,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(ETempMail { http: t }),
};

pub struct ETempMail {
    http: Transport,
}

fn at(value: &str) -> Option<Timestamp> {
    let dt = jiff::civil::DateTime::strptime("%d/%m/%Y %H:%M:%S", value).ok()?;
    jiff::tz::Offset::constant(SITE_UTC_OFFSET_HOURS)
        .to_timestamp(dt)
        .ok()
}

/// A row's id, as cowbird derived it: the first 16 hex digits of SHA-1 over
/// Python's `json.dumps([subject, from, date, body], ensure_ascii=False)`.
/// serde_json escapes a string exactly as that does; only the separator
/// differs (`", "`, not `","`), so the array is joined by hand.
fn row_id(r: &Value) -> String {
    let fields: Vec<String> = ROW_FIELDS
        .iter()
        .map(|k| serde_json::to_string(&r[*k]).expect("serializes"))
        .collect();
    let raw = format!("[{}]", fields.join(", "));
    crate::hash::sha1_hex(raw.as_bytes(), 16)
}

fn s(r: &Value, k: &str) -> String {
    r[k].as_str().unwrap_or("").to_string()
}

fn row(r: &Value) -> MessageRow {
    MessageRow::new(row_id(r), s(r, "from"), s(r, "subject")).at(at(&s(r, "date")))
}

impl ETempMail {
    async fn rows(&self, a: &Address) -> Result<Vec<Value>> {
        let session = a
            .state
            .as_deref()
            .and_then(|st| serde_json::from_str::<Value>(st).ok())
            .and_then(|v| v.get(COOKIE).and_then(Value::as_str).map(String::from))
            .ok_or_else(|| {
                Error::unsupported("etempmail needs the session cookie issued by generate()")
            })?;
        let body = self
            .http
            .post(format!("{SITE}/getInbox"))
            .cookie(COOKIE, session)
            .text()
            .await?;
        if body.trim().is_empty() {
            return Err(Error::AddressExpired(format!(
                "etempmail: {} is gone",
                a.value
            )));
        }
        let Ok(rows) = serde_json::from_str::<Value>(&body) else {
            return Err(Error::drift(NAME, "JSON from inbox", clip(&body, 200)));
        };
        let ok = rows.as_array().is_some_and(|rows| {
            rows.iter().all(|r| {
                ROW_FIELDS
                    .iter()
                    .all(|k| r.get(*k).is_some_and(Value::is_string))
            })
        });
        match rows {
            Value::Array(rows) if ok => Ok(rows),
            other => Err(Error::drift(
                NAME,
                "inbox rows with subject, from, date and body",
                other,
            )),
        }
    }
}

#[async_trait]
impl Provider for ETempMail {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "etempmail picks both the local part and the domain",
            ));
        }
        let token = self
            .http
            .turnstile_solver()?
            .turnstile(PAGE, SITEKEY, None, None)
            .await?;
        let resp = self
            .http
            .post(format!("{SITE}/getEmailAddress"))
            .form([("cf_token", token)])
            .send_json()
            .await?;
        let Ok(data) = serde_json::from_str::<Value>(&resp.text) else {
            return Err(Error::drift(
                NAME,
                "JSON from create",
                clip(&resp.text, 200),
            ));
        };
        if resp.status == 403 && data.get("success") == Some(&json!(false)) {
            return Err(Error::SolverUnavailable(format!(
                "etempmail refused the Turnstile token: {}",
                s(&data, "message")
            )));
        }
        let address = data.get("address").and_then(Value::as_str);
        if address.is_some_and(|a| a.starts_with(DECOY)) {
            return Err(Error::SolverUnavailable(
                "etempmail answered with its decoy address: token refused".into(),
            ));
        }
        let created = data
            .get("creation_time")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|c| c.parse::<i64>().ok())
            .and_then(|c| Timestamp::from_second(c).ok());
        let session = resp.cookie(COOKIE).filter(|c| !c.is_empty());
        let (200, Some(address), Some(created), Some(session)) = (
            resp.status,
            address.filter(|a| a.contains('@')),
            created,
            session,
        ) else {
            return Err(Error::drift(
                NAME,
                "'address', 'creation_time' and a ci_session cookie from create",
                data,
            ));
        };
        let mut a = Address::new(address, NAME)
            .with_state(serde_json::to_string(&json!({COOKIE: session})).expect("serializes"));
        a.expires_at = created
            .checked_add(jiff::SignedDuration::from_mins(LIFE_MINUTES as i64))
            .ok();
        Ok(a)
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        Ok(self.rows(a).await?.iter().map(row).collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let rows = self.rows(a).await?;
        let found = rows
            .iter()
            .find(|r| row_id(r) == id)
            .ok_or_else(|| Error::gone(NAME, id))?;
        let head = row(found);
        Ok(Message::from_bodies(
            id,
            head.sender,
            head.subject,
            head.received_at,
            s(found, "body"),
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

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/etempmail");
    const EMAIL: &str = "hivxwx3mdh@temporarmail.edu.pl";
    const SESSION: &str = "SESSION-PLACEHOLDER";

    const CREATE: &str = "POST https://etempmail.com/getEmailAddress";
    const INBOX: &str = "POST https://etempmail.com/getInbox";

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn created(fields: Value) -> Reply {
        let mut v = load("create.json");
        for (k, x) in fields.as_object().unwrap() {
            v[k] = x.clone();
        }
        Reply::json(v).set_cookie(COOKIE, SESSION)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            // Two answers so the contract's two generates get two addresses.
            .route_seq(
                CREATE,
                [
                    created(json!({})),
                    created(json!({"address": "other1234@mats.edu.pl"})),
                ],
            )
            .route(INBOX, Reply::text(load("inbox.json").to_string()))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport(NAME, &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(ETempMail { http: t })
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new(EMAIL, NAME).with_state(json!({"ci_session": SESSION}).to_string())
    }

    fn sent(w: &Fixtures, prefix: &str) -> Vec<HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url == url)
            .collect()
    }

    fn with_inbox(body: &str) -> Arc<dyn Provider> {
        build(&wire().route(INBOX, Reply::text(body)))
    }

    #[test]
    fn caps_need_a_solver_and_a_fresh_session_per_request() {
        const { assert!(CAPS.needs_solver && CAPS.fresh_session && CAPS.needs_state) };
        assert_eq!(CAPS.kind, [Kind::Edu]);
    }

    #[tokio::test]
    async fn create_posts_one_turnstile_token_as_cf_token() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let solves = s.seen();
        assert_eq!(solves.len(), 1);
        let Body::Json(ask) = &solves[0].body else {
            panic!()
        };
        assert_eq!(ask["url"], PAGE);
        assert_eq!(ask["sitekey"], SITEKEY);
        assert_eq!(
            sent(&w, CREATE)[0].body,
            Body::Form(vec![("cf_token".into(), "fake-token".into())])
        );
    }

    #[tokio::test]
    async fn generate_carries_the_session_cookie_in_state_and_expires_in_20_minutes() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, EMAIL);
        let st: Value = serde_json::from_str(a.state.as_deref().unwrap()).unwrap();
        assert_eq!(st, json!({"ci_session": SESSION}));
        assert_eq!(
            a.expires_at,
            Some(Timestamp::from_second(1790306080 + 20 * 60).unwrap())
        );
    }

    #[tokio::test]
    async fn the_inbox_replays_the_cookie_without_a_solve() {
        let (w, s) = (wire(), solver_wire());
        let p = build_with(&w, Some(&s));
        p.list(&address()).await.unwrap();
        let id = p.list(&address()).await.unwrap()[0].id.clone();
        p.get(&address(), &id).await.unwrap();
        assert!(s.seen().is_empty());
        let inbox = sent(&w, INBOX);
        assert_eq!(inbox.len(), 3);
        assert!(
            inbox
                .iter()
                .all(|r| r.cookies == [(COOKIE.to_string(), SESSION.to_string())])
        );
    }

    #[tokio::test]
    async fn every_request_runs_on_a_fresh_session() {
        let w = wire();
        let p = build(&w);
        p.generate(&GenerateOptions::default()).await.unwrap();
        p.list(&address()).await.unwrap();
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d68f70c2)");
        // The site prints Istanbul time (UTC+3); JoltMx stamped this 03:15:19
        // UTC.
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T03:15:19Z".parse().unwrap())
        );
    }

    #[test]
    fn ids_match_cowbird_byte_for_byte() {
        // Expected values from cowbird's `_id` (sha1 of json.dumps with
        // ensure_ascii=False, first 16 hex digits), run in Python.
        assert_eq!(row_id(&load("inbox.json")[0]), "9d53407fb64a7169");
        let tricky = json!({
            "subject": "Привет \"q\" \\ 日本\u{2028}",
            "from": "a\u{1}b\u{7f}",
            "date": "25/09/2026 06:15:19",
            "body": "x\r\n\t\u{8}\u{c}</p>",
        });
        assert_eq!(row_id(&tricky), "aadd4920e0a2b8e4");
    }

    #[tokio::test]
    async fn ids_are_stable_when_new_mail_shifts_the_listing() {
        let r = load("inbox.json")[0].clone();
        let mut other = r.clone();
        other["subject"] = json!("newer");
        other["date"] = json!("25/09/2026 06:20:00");
        let first = with_inbox(&json!([r]).to_string())
            .list(&address())
            .await
            .unwrap();
        let later = with_inbox(&json!([other, r]).to_string())
            .list(&address())
            .await
            .unwrap();
        assert_eq!(first[0].id, later[1].id);
        assert_ne!(later[0].id, later[1].id);
    }

    #[tokio::test]
    async fn get_reads_the_body_from_the_listing() {
        let p = build(&wire());
        let r = p.list(&address()).await.unwrap().remove(0);
        let m = p.get(&address(), &r.id).await.unwrap();
        assert_eq!(m.id, r.id);
        assert_eq!(m.subject, r.subject);
        assert!(m.html.starts_with("<!DOCTYPE html>"));
        assert!(m.text.contains("This is a test email from JoltMx"));
        assert!(m.links.iter().any(|l| l.starts_with("https://joltmx.com")));
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let w = wire();
        let r = build_with(&w, None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, CREATE).is_empty());
    }

    #[tokio::test]
    async fn solver_unavailable_propagates_before_any_request() {
        let w = wire();
        let s = Fixtures::new().route("/turnstile", Reply::status(500));
        let r = build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, CREATE).is_empty());
    }

    #[tokio::test]
    async fn a_refused_token_is_the_solvers_fault_not_drift() {
        let w = wire().route(
            CREATE,
            Reply::json(load("bot_detected.json")).with_status(403),
        );
        let err = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::SolverUnavailable(m) if m.contains("Bot detected")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn the_decoy_address_means_the_token_was_refused() {
        // A call the site does not trust gets a joke address rather than an
        // error.
        let w = wire().route(CREATE, Reply::json(load("decoy.json")));
        let err = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::SolverUnavailable(m) if m.contains("decoy")),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        assert!(with_inbox("[]").list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_session_the_site_no_longer_knows_is_an_expired_address() {
        let r = with_inbox("").list(&address()).await;
        assert!(matches!(r, Err(Error::AddressExpired(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_message_no_longer_listed_is_gone() {
        let r = with_inbox("[]").get(&address(), "0123456789abcdef").await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn list_without_state_is_not_supported() {
        let r = build(&wire()).list(&Address::new(EMAIL, NAME)).await;
        assert!(matches!(r, Err(Error::NotSupported(_))), "{r:?}");
    }

    #[tokio::test]
    async fn choices_the_site_cannot_honor_are_refused_before_a_solve() {
        for opts in [
            GenerateOptions {
                local: Some("me".into()),
                ..Default::default()
            },
            GenerateOptions {
                domain: Some("mats.edu.pl".into()),
                ..Default::default()
            },
        ] {
            let s = solver_wire();
            let r = build_with(&wire(), Some(&s)).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}");
            assert!(s.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn a_malformed_create_is_drift() {
        for answer in [
            created(json!({"address": null})),
            created(json!({"creation_time": "soon"})),
            Reply::json(load("create.json")), // no session cookie
            Reply::text("<html>"),
        ] {
            let w = wire().route(CREATE, answer);
            let r = build(&w).generate(&GenerateOptions::default()).await;
            assert!(matches!(r, Err(Error::SchemaDrift { .. })), "{r:?}");
        }
    }

    #[tokio::test]
    async fn a_malformed_inbox_is_drift() {
        for answer in [r#"{"x": 1}"#, r#"[{"subject": "no body"}]"#, "<html>"] {
            let r = with_inbox(answer).list(&address()).await;
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{answer}: {r:?}"
            );
        }
    }
}
