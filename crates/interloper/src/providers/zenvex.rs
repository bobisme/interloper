//! zenvex.dev — choosable local parts on six domains, behind a Cloudflare
//! Turnstile.
//!
//! There is no create call: an inbox is any address on a served domain, keyed
//! by the address alone, so anyone who knows it can read it.
//!
//! The API only answers what looks like the site's own fetch(): Sec-Fetch-*
//! of a same-origin request, plus the `zvx_csrf` cookie echoed in
//! X-Zenvex-CSRF. The home page sets that cookie. The inbox then answers 403
//! until the session has passed Turnstile once through POST
//! /turnstile/verify; the pass lives on the session cookie, so one solve
//! serves every address on the same Transport until the site drops it, and a
//! 403 then triggers one fresh solve.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::parse_value_time;
use crate::transport::{Method, Transport};

const NAME: &str = "zenvex";
const SITE: &str = "https://zenvex.dev";
const PAGE: &str = "https://zenvex.dev/";
const SITEKEY: &str = "0x4AAAAAADCsh7evwKvOsjm5";
const DOMAINS: &[&str] = &[
    "encg.edu.pl",
    "ensam.edu.pl",
    "ofppt.edu.pl",
    "souss.dev",
    "zenvex.edu.pl",
    "znvx.me",
];
const FETCH: &[(&str, &str)] = &[
    ("Sec-Fetch-Site", "same-origin"),
    ("Sec-Fetch-Mode", "cors"),
    ("Sec-Fetch-Dest", "empty"),
];
/// What the site's own input normalizes a local part to.
static LOCAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9_-][a-z0-9._-]{0,63}$").unwrap());
const LOCAL_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain, Kind::Edu],
    sites: &["zenvex.dev"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    address_ttl: None,
    message_ttl: None,
    custom_local: true,
    needs_solver: true,
    max_concurrency: 2,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(Zenvex::new(t)),
};

pub struct Zenvex {
    http: Transport,
    csrf: Mutex<Option<String>>,
    // Bumped on every pass, so concurrent readers refused by the same lapsed
    // session wait for one solve instead of each paying for one.
    passes: AtomicU64,
    solving: tokio::sync::Mutex<()>,
}

fn is_edu(domain: &str) -> bool {
    domain.ends_with(".edu.pl")
}

/// 403 ProxyError "Use the Zenvex website" is what a session without a
/// Turnstile pass (or without the csrf header) gets from every API route.
fn refused(status: u16, body: &Value) -> bool {
    status == 403
        && body
            .pointer("/error/message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("website"))
}

impl Zenvex {
    pub fn new(http: Transport) -> Self {
        Zenvex {
            http,
            csrf: Mutex::new(None),
            passes: AtomicU64::new(0),
            solving: tokio::sync::Mutex::new(()),
        }
    }

    async fn home(&self) -> Result<String> {
        let resp = self.http.get(PAGE).send_json().await?;
        // Only a first visit, or one after the cookie lapsed, re-issues it.
        let mut csrf = self.csrf.lock().unwrap();
        if let Some(fresh) = resp.cookie("zvx_csrf").filter(|c| !c.is_empty()) {
            *csrf = Some(fresh);
        }
        match csrf.clone() {
            Some(c) => Ok(c),
            None => {
                let mut names: Vec<String> = resp.cookies().into_iter().map(|(k, _)| k).collect();
                names.sort();
                Err(Error::drift(NAME, "a zvx_csrf cookie from /", json!(names)))
            }
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<(u16, Value)> {
        let held = self.csrf.lock().unwrap().clone();
        let csrf = match held {
            Some(c) => c,
            None => self.home().await?,
        };
        let mut req = self
            .http
            .request(method, format!("{SITE}{path}"))
            .header("X-Zenvex-CSRF", csrf);
        for (k, v) in FETCH {
            req = req.header(k, *v);
        }
        for (k, v) in query {
            req = req.query(*k, v);
        }
        if let Some(b) = &body {
            req = req.json_body(b);
        }
        let resp = req.send_json().await?;
        match serde_json::from_str::<Value>(&resp.text) {
            Ok(v) if v.get("success").is_some_and(Value::is_boolean) => Ok((resp.status, v)),
            _ => Err(Error::drift(
                NAME,
                format!("a success envelope from {path}"),
                clip(&resp.text, 200),
            )),
        }
    }

    async fn domains(&self) -> Result<(Vec<String>, String)> {
        let (_, body) = self.call(Method::Get, "/api/domains", &[], None).await?;
        let result = body.get("result");
        let domains: Option<Vec<String>> = result
            .and_then(|r| r.get("domains"))
            .and_then(Value::as_array)
            .filter(|d| !d.is_empty())
            .and_then(|d| d.iter().map(|x| x.as_str().map(String::from)).collect());
        let Some(domains) = domains else {
            return Err(Error::drift(NAME, "'domains' from /api/domains", body));
        };
        let default = result
            .and_then(|r| r.get("default"))
            .and_then(Value::as_str)
            .filter(|d| domains.iter().any(|x| x == d))
            .map_or_else(|| domains[0].clone(), String::from);
        Ok((domains, default))
    }

    async fn verify(&self, seen: u64) -> Result<()> {
        let solver = self.http.turnstile_solver()?;
        let _one_at_a_time = self.solving.lock().await;
        let current = self.passes.load(Ordering::SeqCst);
        if current != seen {
            return Ok(()); // another reader already renewed the pass
        }
        if current > 0 {
            self.home().await?; // renewing: the csrf cookie may have lapsed too
        }
        let token = solver.turnstile(PAGE, SITEKEY, None, None).await?;
        let (_, body) = self
            .call(
                Method::Post,
                "/turnstile/verify",
                &[],
                Some(json!({"token": token})),
            )
            .await?;
        if body["success"] != json!(true) {
            // A token zenvex will not take is the solver's fault, not drift.
            let message = body.pointer("/error/message").and_then(Value::as_str);
            if message == Some("Verification failed") {
                return Err(Error::SolverUnavailable(format!(
                    "zenvex refused the Turnstile token: {}",
                    message.unwrap_or_default()
                )));
            }
            return Err(Error::drift(NAME, "success from /turnstile/verify", body));
        }
        self.passes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn read(&self, path: &str, query: &[(&str, &str)]) -> Result<(u16, Value)> {
        let seen = self.passes.load(Ordering::SeqCst);
        let (status, body) = self.call(Method::Get, path, query, None).await?;
        if !refused(status, &body) {
            return Ok((status, body));
        }
        self.verify(seen).await?;
        let (status, body) = self.call(Method::Get, path, query, None).await?;
        if refused(status, &body) {
            return Err(Error::drift(
                NAME,
                format!("{path} to answer a verified session"),
                body,
            ));
        }
        Ok((status, body))
    }
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

#[async_trait]
impl Provider for Zenvex {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        // An address nobody can read is no use.
        self.http.turnstile_solver()?;
        if let Some(k) = opts.kind.filter(|k| !CAPS.serves(*k)) {
            return Err(Error::unsupported(format!("zenvex does not serve {k}")));
        }
        if let Some(l) = opts.local.as_deref().filter(|l| !LOCAL.is_match(l)) {
            return Err(Error::unsupported(format!(
                "zenvex would rewrite the local part {l:?}"
            )));
        }
        let (mut domains, mut default) = self.domains().await?;
        match opts.kind {
            Some(Kind::Edu) => {
                domains.retain(|d| is_edu(d));
                default = domains.first().cloned().unwrap_or_default();
            }
            Some(Kind::OwnDomain) => {
                domains.retain(|d| !is_edu(d));
                if !domains.contains(&default) {
                    default = domains.first().cloned().unwrap_or_default();
                }
            }
            _ => {}
        }
        let domain = opts.domain.clone().unwrap_or(default);
        if !domains.contains(&domain) {
            let what = if domain.is_empty() {
                opts.kind.map(|k| k.to_string()).unwrap_or_default()
            } else {
                domain
            };
            return Err(Error::unsupported(format!(
                "zenvex does not serve {what} here; has {domains:?}"
            )));
        }
        let local = opts.local.clone().unwrap_or_else(|| {
            let mut rng = rand::rng();
            (0..10)
                .map(|_| LOCAL_CHARS[rng.random_range(0..LOCAL_CHARS.len())] as char)
                .collect()
        });
        Ok(Address::new(format!("{local}@{domain}"), NAME))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let path = format!("/api/emails/{}", urlencoding::encode(&a.value));
        let (_, body) = self
            .read(&path, &[("limit", "50"), ("offset", "0")])
            .await?;
        let ok = body
            .get("result")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().all(|r| {
                    r.get("id")
                        .and_then(Value::as_str)
                        .is_some_and(|id| !id.is_empty())
                })
            });
        if !ok {
            return Err(Error::drift(NAME, "a list of rows with 'id'", body));
        }
        Ok(body["result"]
            .as_array()
            .expect("checked")
            .iter()
            .map(|r| {
                MessageRow::new(s(r, "id"), s(r, "from_address"), s(r, "subject"))
                    .at(r.get("received_at").and_then(parse_value_time))
            })
            .collect())
    }

    async fn get(&self, _a: &Address, id: &str) -> Result<Message> {
        let path = format!("/api/inbox/{}", urlencoding::encode(id));
        let (status, body) = self.read(&path, &[]).await?;
        if status == 404 && body.pointer("/error/name").and_then(Value::as_str) == Some("NotFound")
        {
            return Err(Error::gone(NAME, id));
        }
        let mail = body
            .get("result")
            .filter(|m| m.get("html_content").is_some() || m.get("text_content").is_some());
        let (200, Some(mail)) = (status, mail) else {
            return Err(Error::drift(NAME, "a message with html/text_content", body));
        };
        Ok(Message::from_bodies(
            id,
            s(mail, "from_address"),
            s(mail, "subject"),
            mail.get("received_at").and_then(parse_value_time),
            s(mail, "html_content"),
            Some(s(mail, "text_content")),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::Solver;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Backend, Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/zenvex");
    const CSRF: &str = "CSRF-PLACEHOLDER";

    const HOME: &str = "GET https://zenvex.dev/?";
    const DOMAINS_ROUTE: &str = "GET https://zenvex.dev/api/domains";
    const VERIFY: &str = "POST https://zenvex.dev/turnstile/verify";
    const EMAILS: &str = "GET https://zenvex.dev/api/emails/";
    const INBOX: &str = "GET https://zenvex.dev/api/inbox/";
    const MID: &str = "h7439esj8qgjdgwj2t5avopt";

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn unverified() -> Reply {
        Reply::json(load("unverified.json")).with_status(403)
    }

    fn home() -> Reply {
        Reply::text("<!doctype html>")
            .set_cookie("zvx_sid", "SID-PLACEHOLDER")
            .set_cookie("zvx_csrf", CSRF)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(HOME, home())
            .route(DOMAINS_ROUTE, Reply::json(load("domains.json")))
            .route(VERIFY, Reply::json(load("verify_ok.json")))
            .route(EMAILS, Reply::json(load("emails.json")))
            .route(INBOX, Reply::json(load("message.json")))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport(NAME, &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(Zenvex::new(t))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbb15c6d7c@souss.dev", NAME)
    }

    fn sent(w: &Fixtures, prefix: &str) -> Vec<HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url.starts_with(url))
            .collect()
    }

    fn home_visits(w: &Fixtures) -> usize {
        w.seen().iter().filter(|r| r.url == PAGE).count()
    }

    #[tokio::test]
    async fn the_first_read_passes_turnstile_and_sends_the_token_to_verify() {
        let w = wire().route_seq(EMAILS, [unverified(), Reply::json(load("emails.json"))]);
        let s = solver_wire();
        let rows = build_with(&w, Some(&s)).list(&address()).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MID]
        );
        let solves = s.seen();
        assert_eq!(solves.len(), 1);
        let Body::Json(ask) = &solves[0].body else {
            panic!()
        };
        assert_eq!(ask["url"], PAGE);
        assert_eq!(ask["sitekey"], SITEKEY);
        let v = &sent(&w, VERIFY)[0];
        assert_eq!(v.body, Body::Json(json!({"token": "fake-token"})));
        assert_eq!(v.header("X-Zenvex-CSRF"), Some(CSRF));
    }

    #[tokio::test]
    async fn one_solve_serves_every_address_on_the_transport() {
        let w = wire().route_seq(
            EMAILS,
            [unverified(), Reply::json(load("emails_empty.json"))],
        );
        let s = solver_wire();
        let p = build_with(&w, Some(&s));
        p.list(&address()).await.unwrap();
        p.list(&Address::new("other01@znvx.me", NAME))
            .await
            .unwrap();
        p.get(&address(), MID).await.unwrap();
        assert_eq!(s.seen().len(), 1);
    }

    /// A solver backend that takes a moment, so two readers overlap.
    struct Slow(Arc<Fixtures>);

    #[async_trait]
    impl Backend for Slow {
        async fn send(
            &self,
            req: HttpRequest,
            fresh: bool,
        ) -> std::result::Result<crate::transport::HttpResponse, String> {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            self.0.send(req, fresh).await
        }
    }

    #[tokio::test]
    async fn concurrent_reads_on_an_unverified_session_share_one_solve() {
        let w = wire().route_seq(
            EMAILS,
            [
                unverified(),
                unverified(),
                Reply::json(load("emails_empty.json")),
            ],
        );
        let s = solver_wire();
        let t = w.transport(NAME, &CAPS).solver(Some(Solver::with_backend(
            "http://solver.test",
            Arc::new(Slow(s.clone())),
        )));
        let p = Zenvex::new(t);
        let a = address();
        let (x, y) = tokio::join!(p.list(&a), p.list(&a));
        x.unwrap();
        y.unwrap();
        assert_eq!(s.seen().len(), 1);
    }

    #[tokio::test]
    async fn a_lapsed_verification_is_renewed_once_with_a_fresh_home_visit() {
        let emails = || Reply::json(load("emails.json"));
        let w = wire().route_seq(EMAILS, [unverified(), emails(), unverified(), emails()]);
        let s = solver_wire();
        let p = build_with(&w, Some(&s));
        p.list(&address()).await.unwrap();
        assert!(!p.list(&address()).await.unwrap().is_empty());
        assert_eq!(s.seen().len(), 2);
        assert_eq!(home_visits(&w), 2);
    }

    #[tokio::test]
    async fn a_session_refused_right_after_verifying_is_drift() {
        let w = wire().route(EMAILS, unverified());
        let s = solver_wire();
        let r = build_with(&w, Some(&s)).list(&address()).await;
        assert!(matches!(r, Err(Error::SchemaDrift { .. })), "{r:?}");
        assert_eq!(s.seen().len(), 1);
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows[0].sender, "test@sendtest.joltmx.com");
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d65c6e06)");
        assert_eq!(
            rows[0].received_at,
            Some(jiff::Timestamp::from_second(1790302778).unwrap())
        );
    }

    #[tokio::test]
    async fn list_asks_for_the_address_it_was_given() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        let r = &sent(&w, EMAILS)[0];
        assert_eq!(
            r.url,
            "https://zenvex.dev/api/emails/cbb15c6d7c%40souss.dev"
        );
        assert_eq!(
            r.query,
            [("limit".into(), "50".into()), ("offset".into(), "0".into())]
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(EMAILS, Reply::json(load("emails_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_reads_the_body() {
        let m = build(&wire()).get(&address(), MID).await.unwrap();
        assert_eq!(m.id, MID);
        assert_eq!(m.sender, "test@sendtest.joltmx.com");
        assert_eq!(m.subject, "JoltMx test email (ref 01a0d65c6e06)");
        assert_eq!(
            m.received_at,
            Some(jiff::Timestamp::from_second(1790302778).unwrap())
        );
        assert!(m.html.starts_with("<!DOCTYPE html>"));
        assert!(m.text.starts_with("This is a test email from JoltMx."));
    }

    #[tokio::test]
    async fn a_message_zenvex_no_longer_has_is_gone() {
        let w = wire().route(
            INBOX,
            Reply::json(load("message_gone.json")).with_status(404),
        );
        let r = build(&w).get(&address(), MID).await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn a_malformed_answer_is_drift() {
        let cases = [
            (
                EMAILS,
                Reply::json(json!({"success": true, "result": {"x": 1}})),
            ),
            (
                EMAILS,
                Reply::json(json!({"success": true, "result": [{"subject": "no id"}]})),
            ),
            (EMAILS, Reply::text("<html>not json</html>")),
            (
                INBOX,
                Reply::json(json!({"success": true, "result": {"id": MID}})),
            ),
            (
                INBOX,
                Reply::json(json!({"success": false, "error": {"name": "ValidationError"}}))
                    .with_status(400),
            ),
        ];
        for (route, answer) in cases {
            let p = build(&wire().route(route, answer));
            let r = if route == INBOX {
                p.get(&address(), MID).await.map(|_| ())
            } else {
                p.list(&address()).await.map(|_| ())
            };
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{route}: {r:?}"
            );
        }
    }

    #[tokio::test]
    async fn generate_uses_the_sites_default_domain_and_costs_no_solve() {
        let s = solver_wire();
        let a = build_with(&wire(), Some(&s))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.domain(), "souss.dev");
        assert!(a.local().len() >= 8);
        assert!(a.local().chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn api_calls_carry_the_csrf_cookie_as_a_header_and_look_like_fetch() {
        let w = wire();
        build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let r = &sent(&w, DOMAINS_ROUTE)[0];
        assert_eq!(r.header("X-Zenvex-CSRF"), Some(CSRF));
        assert_eq!(r.header("Sec-Fetch-Site"), Some("same-origin"));
        assert_eq!(r.header("Sec-Fetch-Mode"), Some("cors"));
    }

    #[tokio::test]
    async fn the_home_page_is_fetched_once_per_transport() {
        let w = wire();
        let p = build(&w);
        p.generate(&GenerateOptions::default()).await.unwrap();
        p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(home_visits(&w), 1);
    }

    #[tokio::test]
    async fn a_chosen_local_and_domain_are_kept() {
        let a = build(&wire())
            .generate(&GenerateOptions {
                local: Some("qa.bot-1".into()),
                domain: Some("znvx.me".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(a.value, "qa.bot-1@znvx.me");
    }

    #[tokio::test]
    async fn the_edu_kind_picks_an_edu_pl_domain() {
        let a = build(&wire())
            .generate(&GenerateOptions {
                kind: Some(Kind::Edu),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(a.value.ends_with(".edu.pl"));
    }

    #[tokio::test]
    async fn what_zenvex_cannot_serve_is_refused() {
        let o = |kind: Option<Kind>, domain: Option<&str>| GenerateOptions {
            kind,
            domain: domain.map(String::from),
            ..Default::default()
        };
        for opts in [
            o(None, Some("gmail.com")),
            o(Some(Kind::GmailAlias), None),
            o(Some(Kind::Edu), Some("souss.dev")),
        ] {
            let r = build(&wire()).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}: {r:?}");
        }
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let r = build_with(&wire(), None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_home_page_without_a_csrf_cookie_is_drift() {
        let w = wire().route(HOME, Reply::text("<!doctype html>"));
        let r = build(&w).generate(&GenerateOptions::default()).await;
        assert!(matches!(r, Err(Error::SchemaDrift { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn malformed_domains_are_drift() {
        let w = wire().route(
            DOMAINS_ROUTE,
            Reply::json(json!({"success": true, "result": {"x": 1}})),
        );
        let r = build(&w).generate(&GenerateOptions::default()).await;
        assert!(matches!(r, Err(Error::SchemaDrift { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn without_a_solver_list_is_solver_unavailable() {
        let w = wire().route(EMAILS, unverified());
        let r = build_with(&w, None).list(&address()).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_token_zenvex_refuses_is_the_solvers_fault_not_drift() {
        let w = wire().route(EMAILS, unverified()).route(
            VERIFY,
            Reply::json(load("verify_refused.json")).with_status(403),
        );
        let r = build(&w).list(&address()).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn solver_unavailable_propagates_unchanged() {
        let w = wire().route(EMAILS, unverified());
        let s = Fixtures::new().route("/turnstile", Reply::status(500));
        let r = build_with(&w, Some(&s)).list(&address()).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, VERIFY).is_empty());
    }
}
