//! vanishinbox.com — nine domains, three of them .edu.pl, behind Cloudflare
//! Turnstile.
//!
//! The page makes addresses up in the browser: the server keeps no record of
//! them and receives mail for any local part on its domains. So generate()
//! picks the address itself, with a random hex local part rather than the
//! site's adjective-animal-number, because any verified visitor can read any
//! inbox by name and the site's names are guessable.
//!
//! Reading needs a pass. A Turnstile token POSTed to /api/verify-turnstile
//! earns an HttpOnly `vi_hv` cookie, `<unix expiry>.<hmac>`, good for two
//! hours for every address; a token is single-use. Without the cookie the
//! inbox answers `403 {"error": "verification_required"}`. So there is one
//! solve per two-hour window per process, not one per address. The cookie
//! travels in Address::state (treat it as a secret) so another process can
//! read without solving; state is optional, since list() earns a pass itself
//! when it has none.
//!
//! The listing carries whole messages, body included; there is no
//! per-message endpoint, so a message the site has dropped is one no longer
//! listed. Deleting on the page only hides a message in the browser.

use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use rand::Rng;
use rand::seq::IndexedRandom;
use regex::Regex;
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::parse_value_time;
use crate::transport::{HttpResponse, Transport};

const NAME: &str = "vanishinbox";
const SITE: &str = "https://vanishinbox.com";
const PAGE: &str = "https://vanishinbox.com/";
const SITEKEY: &str = "0x4AAAAAADyGrnNGqa-_Rg6x";
const COOKIE: &str = "vi_hv";
const OWN_DOMAINS: &[&str] = &[
    "myerly.com",
    "fommie.com",
    "whoopza.org",
    "fommie.online",
    "fommie.store",
    "whoopza.store",
];
const EDU_DOMAINS: &[&str] = &["reason.edu.pl", "realize.edu.pl", "remind.edu.pl"];
const DOMAINS: &[&str] = &[
    "myerly.com",
    "fommie.com",
    "whoopza.org",
    "fommie.online",
    "fommie.store",
    "whoopza.store",
    "reason.edu.pl",
    "realize.edu.pl",
    "remind.edu.pl",
];
static LOCAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,63}$").unwrap());
/// A pass this close to its expiry is renewed rather than sent.
const MARGIN_SECS: i64 = 60;

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain, Kind::Edu],
    sites: &["vanishinbox.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // Any local part receives, so the address itself never lapses. The site
    // says mail is deleted after ten minutes; not measured.
    address_ttl: None,
    message_ttl: Some(minutes(10)),
    custom_local: true,
    needs_solver: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(VanishInbox::new(t)),
};

pub struct VanishInbox {
    http: Transport,
    // The pass this process holds, shared by every address.
    pass: Mutex<Option<String>>,
    // Held across a solve, so concurrent readers wait for one pass instead of
    // each paying for one.
    solving: tokio::sync::Mutex<()>,
}

fn live(cookie: &str) -> bool {
    let (expiry, _) = cookie.split_once('.').unwrap_or((cookie, ""));
    !expiry.is_empty()
        && expiry.bytes().all(|b| b.is_ascii_digit())
        && expiry
            .parse::<i64>()
            .is_ok_and(|e| e > jiff::Timestamp::now().as_second() + MARGIN_SECS)
}

fn from_state(a: &Address) -> Option<String> {
    let v: Value = serde_json::from_str(a.state.as_deref()?).ok()?;
    let cookie = v.get(COOKIE)?.as_str()?;
    live(cookie).then(|| cookie.to_string())
}

fn body(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.text).unwrap_or_else(|_| Value::String(clip(&resp.text, 200)))
}

fn address(opts: &GenerateOptions) -> Result<String> {
    let (allowed, pool) = match opts.kind {
        None => (DOMAINS, OWN_DOMAINS),
        Some(Kind::OwnDomain) => (OWN_DOMAINS, OWN_DOMAINS),
        Some(Kind::Edu) => (EDU_DOMAINS, EDU_DOMAINS),
        Some(k) => return Err(Error::unsupported(format!("{NAME} does not serve {k}"))),
    };
    let domain = match &opts.domain {
        Some(d) => d.as_str(),
        None => pool.choose(&mut rand::rng()).expect("non-empty"),
    };
    if !allowed.contains(&domain) {
        let kind = opts.kind.map_or("any kind".to_string(), |k| k.to_string());
        return Err(Error::unsupported(format!(
            "{NAME} does not serve {domain} for {kind}"
        )));
    }
    let local = match &opts.local {
        Some(l) => l.clone(),
        None => {
            let n: u64 = rand::rng().random();
            format!("{:012x}", n & 0xffff_ffff_ffff)
        }
    };
    if !LOCAL.is_match(&local) {
        return Err(Error::unsupported(format!(
            "{NAME} cannot use the local part {local:?}"
        )));
    }
    Ok(format!("{local}@{domain}"))
}

impl VanishInbox {
    pub fn new(http: Transport) -> Self {
        VanishInbox {
            http,
            pass: Mutex::new(None),
            solving: tokio::sync::Mutex::new(()),
        }
    }

    fn held(&self) -> Option<String> {
        self.pass.lock().unwrap().clone().filter(|p| live(p))
    }

    /// A live pass, earning one only if none is held (or the held one is
    /// `stale`).
    async fn verify(&self, stale: Option<&str>) -> Result<String> {
        let _one_at_a_time = self.solving.lock().await;
        if let Some(p) = self.held()
            && Some(p.as_str()) != stale
        {
            return Ok(p);
        }
        let token = self
            .http
            .turnstile_solver()?
            .turnstile(PAGE, SITEKEY, None, None)
            .await?;
        let resp = self
            .http
            .post(format!("{SITE}/api/verify-turnstile"))
            .json_body(&json!({"token": token}))
            .send_json()
            .await?;
        let data = body(&resp);
        match data.get("success").and_then(Value::as_bool) {
            // A token the site will not accept is the solver's fault.
            Some(false) => Err(Error::SolverUnavailable(format!(
                "{NAME} refused the Turnstile token: {data}"
            ))),
            Some(true) => {
                let Some(cookie) = resp.cookie(COOKIE).filter(|c| !c.is_empty()) else {
                    return Err(Error::drift(
                        NAME,
                        "success and a vi_hv cookie from verify",
                        data,
                    ));
                };
                *self.pass.lock().unwrap() = Some(cookie.clone());
                Ok(cookie)
            }
            None => Err(Error::drift(
                NAME,
                "success and a vi_hv cookie from verify",
                data,
            )),
        }
    }

    async fn inbox(&self, a: &Address) -> Result<Vec<Value>> {
        let url = format!("{SITE}/api/inbox/{}", urlencoding::encode(&a.value));
        let cookie = match self.held().or_else(|| from_state(a)) {
            Some(c) => c,
            None => self.verify(None).await?,
        };
        let mut resp = self
            .http
            .get(&url)
            .cookie(COOKIE, &cookie)
            .send_json()
            .await?;
        if resp.status == 403 {
            // Revoked or rejected early: earn a fresh pass once and retry.
            let fresh = self.verify(Some(&cookie)).await?;
            resp = self
                .http
                .get(&url)
                .cookie(COOKIE, fresh)
                .send_json()
                .await?;
        }
        let data = body(&resp);
        let ok = resp.status == 200
            && data
                .get("emails")
                .and_then(Value::as_array)
                .is_some_and(|e| e.iter().all(|r| r.get("id").is_some_and(Value::is_string)));
        if !ok {
            return Err(Error::drift(
                NAME,
                "'emails' rows with 'id' from inbox",
                data,
            ));
        }
        let Value::Object(mut m) = data else {
            unreachable!("checked")
        };
        let Some(Value::Array(emails)) = m.remove("emails") else {
            unreachable!("checked")
        };
        Ok(emails)
    }
}

/// `str(e.get(k) or "")`.
fn s(r: &Value, k: &str) -> String {
    match r.get(k) {
        None | Some(Value::Null) | Some(Value::Bool(false)) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn row(e: &Value) -> MessageRow {
    MessageRow::new(s(e, "id"), s(e, "from"), s(e, "subject"))
        .at(e.get("receivedAt").and_then(parse_value_time))
}

#[async_trait]
impl Provider for VanishInbox {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let value = address(opts)?;
        let cookie = self.verify(None).await?;
        let state = serde_json::to_string(&json!({COOKIE: cookie})).expect("serializes");
        Ok(Address::new(value, NAME).with_state(state))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        Ok(self.inbox(a).await?.iter().map(row).collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let emails = self.inbox(a).await?;
        let e = emails
            .iter()
            .find(|e| e["id"] == id)
            .ok_or_else(|| Error::gone(NAME, id))?;
        let Some(html) = e.get("body").and_then(Value::as_str) else {
            return Err(Error::drift(
                NAME,
                "a string 'body' in the inbox row",
                e.clone(),
            ));
        };
        let text = e.get("bodyText").and_then(Value::as_str).map(String::from);
        let head = row(e);
        Ok(Message::from_bodies(
            id,
            head.sender,
            head.subject,
            head.received_at,
            html,
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::Solver;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/vanishinbox");
    const ADDR: &str = "swiftwren234@fommie.com";
    const MID: &str = "babe3949-61f1-4e8d-ac37-eee80a990dbb";

    const VERIFY: &str = "POST https://vanishinbox.com/api/verify-turnstile";
    const INBOX: &str = "GET https://vanishinbox.com/api/inbox/";

    // vi_hv is "<unix expiry>.<hmac>"; the hmac here is a placeholder.
    fn live_pass() -> String {
        format!(
            "{}.COOKIE-PLACEHOLDER",
            jiff::Timestamp::now().as_second() + 3600
        )
    }

    fn old_pass() -> String {
        format!(
            "{}.OLD-COOKIE-PLACEHOLDER",
            jiff::Timestamp::now().as_second() - 60
        )
    }

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn verified() -> Reply {
        Reply::json(load("verify_ok.json")).set_cookie(COOKIE, &live_pass())
    }

    fn unverified() -> Reply {
        Reply::json(load("inbox_unverified.json")).with_status(403)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(VERIFY, verified())
            .route(INBOX, Reply::json(load("inbox.json")))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport(NAME, &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(VanishInbox::new(t))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn state(cookie: &str) -> String {
        json!({"vi_hv": cookie}).to_string()
    }

    fn address() -> Address {
        Address::new(ADDR, NAME).with_state(state(&live_pass()))
    }

    fn sent(w: &Fixtures, prefix: &str) -> Vec<HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url.starts_with(url))
            .collect()
    }

    fn cookie_of(r: &HttpRequest) -> Option<&str> {
        r.cookies
            .iter()
            .find(|(k, _)| k == COOKIE)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn generate_posts_one_solved_token_to_verify() {
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
        let verifies = sent(&w, VERIFY);
        assert_eq!(verifies.len(), 1);
        assert_eq!(verifies[0].body, Body::Json(json!({"token": "fake-token"})));
    }

    #[tokio::test]
    async fn generate_carries_the_pass_cookie_in_state() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let st: Value = serde_json::from_str(a.state.as_deref().unwrap()).unwrap();
        assert!(live(st["vi_hv"].as_str().unwrap()));
        assert!(
            st["vi_hv"]
                .as_str()
                .unwrap()
                .ends_with(".COOKIE-PLACEHOLDER")
        );
    }

    #[tokio::test]
    async fn one_pass_serves_every_address_until_it_expires() {
        let (w, s) = (wire(), solver_wire());
        let p = build_with(&w, Some(&s));
        let first = p.generate(&GenerateOptions::default()).await.unwrap();
        let second = p.generate(&GenerateOptions::default()).await.unwrap();
        p.list(&first).await.unwrap();
        p.list(&second).await.unwrap();
        assert_eq!(s.seen().len(), 1);
        assert_eq!(sent(&w, VERIFY).len(), 1);
    }

    #[tokio::test]
    async fn list_sends_the_pass_as_a_cookie_on_an_escaped_address() {
        let w = wire();
        let a = address();
        build(&w).list(&a).await.unwrap();
        let inbox = sent(&w, INBOX);
        assert_eq!(inbox.len(), 1);
        assert_eq!(cookie_of(&inbox[0]), Some(from_state(&a).unwrap().as_str()));
        assert_eq!(
            inbox[0].url,
            "https://vanishinbox.com/api/inbox/swiftwren234%40fommie.com"
        );
    }

    #[tokio::test]
    async fn list_from_state_alone_needs_no_solve() {
        let s = solver_wire();
        let rows = build_with(&wire(), Some(&s))
            .list(&address())
            .await
            .unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MID]
        );
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn list_without_state_solves_once() {
        let (w, s) = (wire(), solver_wire());
        let p = build_with(&w, Some(&s));
        p.list(&Address::new(ADDR, NAME)).await.unwrap();
        p.list(&Address::new(ADDR, NAME)).await.unwrap();
        assert_eq!(s.seen().len(), 1);
        let inbox = sent(&w, INBOX);
        assert!(inbox.iter().all(|r| cookie_of(r).is_some_and(live)));
    }

    #[tokio::test]
    async fn an_expired_pass_in_state_is_not_sent() {
        let (w, s) = (wire(), solver_wire());
        let old = old_pass();
        build_with(&w, Some(&s))
            .list(&Address::new(ADDR, NAME).with_state(state(&old)))
            .await
            .unwrap();
        assert_eq!(s.seen().len(), 1);
        let sent_cookie = cookie_of(&sent(&w, INBOX)[0]).unwrap().to_string();
        assert_ne!(sent_cookie, old);
        assert!(live(&sent_cookie));
    }

    #[tokio::test]
    async fn a_revoked_pass_is_renewed_once_and_the_read_retried() {
        let w = wire().route_seq(INBOX, [unverified(), Reply::json(load("inbox.json"))]);
        let s = solver_wire();
        let rows = build_with(&w, Some(&s)).list(&address()).await.unwrap();
        assert_eq!(rows[0].id, MID);
        assert_eq!(s.seen().len(), 1);
        assert_eq!(sent(&w, INBOX).len(), 2);
    }

    #[tokio::test]
    async fn a_pass_refused_right_after_verifying_is_drift() {
        let w = wire().route(INBOX, unverified());
        let s = solver_wire();
        let r = build_with(&w, Some(&s)).list(&address()).await;
        assert!(matches!(r, Err(Error::SchemaDrift { .. })), "{r:?}");
        assert_eq!(s.seen().len(), 1);
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MID);
        assert_eq!(rows[0].sender, "test@sendtest.joltmx.com");
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d68d9059)");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T03:13:17.944Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn get_reads_the_body_from_the_listing() {
        let m = build(&wire()).get(&address(), MID).await.unwrap();
        assert_eq!(m.id, MID);
        assert!(m.html.starts_with("<!DOCTYPE html>"));
        assert!(m.text.starts_with("This is a test email from JoltMx."));
        assert!(m.links.iter().any(|l| l.starts_with("https://joltmx.com")));
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(INBOX, Reply::json(load("inbox_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_message_no_longer_listed_is_gone() {
        // There is no per-message endpoint: the listing carries the bodies,
        // and a message the site has dropped is simply absent from it.
        let w = wire().route(INBOX, Reply::json(load("inbox_empty.json")));
        let r = build(&w).get(&address(), MID).await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let r = build_with(&wire(), None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_solver_list_without_a_pass_is_solver_unavailable() {
        let r = build_with(&wire(), None)
            .list(&Address::new(ADDR, NAME))
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_solver_a_pass_in_state_still_reads() {
        let rows = build_with(&wire(), None).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn a_token_the_site_refuses_is_the_solvers_fault_not_drift() {
        let w = wire().route(
            VERIFY,
            Reply::json(load("verify_refused.json")).with_status(403),
        );
        let r = build(&w).generate(&GenerateOptions::default()).await;
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
        assert!(sent(&w, VERIFY).is_empty());
    }

    #[tokio::test]
    async fn a_malformed_answer_is_drift() {
        let cases = [
            // success but no cookie
            (VERIFY, Reply::json(load("verify_ok.json"))),
            (
                VERIFY,
                Reply::json(json!({"x": 1})).set_cookie(COOKIE, &live_pass()),
            ),
            (INBOX, Reply::json(json!({"x": 1}))),
            (
                INBOX,
                Reply::json(json!({"emails": [{"subject": "no id"}]})),
            ),
            (
                INBOX,
                Reply::json(json!({"emails": [{"id": MID, "body": null}]})),
            ),
        ];
        for (route, answer) in cases {
            let p = build(&wire().route(route, answer));
            let r = p.get(&Address::new(ADDR, NAME), MID).await;
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{route}: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_edu_kind_gives_an_edu_pl_address() {
        let a = build(&wire())
            .generate(&GenerateOptions {
                kind: Some(Kind::Edu),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(EDU_DOMAINS.contains(&a.domain()));
    }

    #[tokio::test]
    async fn a_chosen_local_part_and_domain_are_kept() {
        let a = build(&wire())
            .generate(&GenerateOptions {
                local: Some("me.test".into()),
                domain: Some("remind.edu.pl".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(a.value, "me.test@remind.edu.pl");
    }

    #[tokio::test]
    async fn what_the_site_cannot_do_is_refused_before_a_solve() {
        let o = |kind: Option<Kind>, domain: Option<&str>| GenerateOptions {
            kind,
            domain: domain.map(String::from),
            ..Default::default()
        };
        for opts in [
            o(None, Some("gmail.com")),
            o(Some(Kind::GmailAlias), None),
            o(Some(Kind::Edu), Some("fommie.com")),
        ] {
            let s = solver_wire();
            let r = build_with(&wire(), Some(&s)).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}");
            assert!(s.seen().is_empty());
        }
    }
}
