//! The only thing in interloper that touches a network.
//!
//! Providers receive a [`Transport`] and never build a client themselves, so
//! browser impersonation, proxying, the per-backend concurrency gate, retries,
//! anti-bot detection and Cloudflare clearance are fixed in one place for
//! every provider at once.
//!
//! The wire itself sits behind [`Backend`]. Production uses [`WreqBackend`]
//! (BoringSSL with a real Chrome TLS/HTTP2 fingerprint); tests use
//! `testing::Fixtures`. Because the fixture replaces only the wire, the retry,
//! 429, 5xx and challenge logic below runs unchanged under test — cowbird's
//! fake replaced the whole transport and re-implemented those rules.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::error::{Error, Result, clip};
use crate::solver::{Clearance, Solver};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Empty,
    Json(Value),
    Form(Vec<(String, String)>),
    Raw { content_type: String, data: String },
}

/// A request as the wire sees it. Plain data, so a fixture can match on it.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    pub body: Body,
    /// Follow 3xx like a browser. Off for the rare request whose answer is
    /// the redirect itself (a cookie set on a 302).
    pub follow_redirects: bool,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn set_header(&mut self, name: &str, value: String) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value));
    }

    /// The URL with its query string, as it goes on the wire.
    pub fn full_url(&self) -> String {
        if self.query.is_empty() {
            return self.url.clone();
        }
        let qs = encode_pairs(&self.query);
        let sep = if self.url.contains('?') { '&' } else { '?' };
        format!("{}{sep}{qs}", self.url)
    }
}

pub(crate) fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub text: String,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Name/value pairs from every `Set-Cookie`.
    pub fn cookies(&self) -> Vec<(String, String)> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| {
                let pair = v.split(';').next()?;
                let (name, value) = pair.split_once('=')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect()
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        self.cookies()
            .into_iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parse the body as JSON, or report drift naming the provider.
    pub fn json(&self, provider: &str) -> Result<Value> {
        serde_json::from_str(&self.text)
            .map_err(|_| Error::drift(provider, "a JSON body", clip(&self.text, 200)))
    }
}

/// The wire. `fresh_session` asks for a request with no cookie jar shared
/// with any other request.
#[async_trait]
pub trait Backend: Send + Sync {
    async fn send(
        &self,
        req: HttpRequest,
        fresh_session: bool,
    ) -> std::result::Result<HttpResponse, String>;
}

/// How a transport talks to the outside world.
#[derive(Debug, Clone)]
pub struct NetConfig {
    pub proxy: Option<String>,
    pub timeout: Duration,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            proxy: None,
            timeout: Duration::from_secs(60),
        }
    }
}

impl NetConfig {
    /// `INTERLOPER_PROXY` (falling back to `COWBIRD_PROXY`).
    pub fn from_env() -> Self {
        let proxy = ["INTERLOPER_PROXY", "COWBIRD_PROXY"]
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()));
        NetConfig {
            proxy,
            ..Default::default()
        }
    }
}

/// Real HTTP with a Chrome TLS and HTTP/2 fingerprint.
pub struct WreqBackend {
    shared: wreq::Client,
    config: NetConfig,
}

impl WreqBackend {
    pub fn new(config: NetConfig) -> Result<Self> {
        let shared = Self::client(&config, true)?;
        Ok(WreqBackend { shared, config })
    }

    fn client(config: &NetConfig, cookies: bool) -> Result<wreq::Client> {
        let mut b = wreq::Client::builder()
            .emulation(wreq_util::Emulation::Chrome149)
            .cookie_store(cookies)
            // Follow redirects like the browser being impersonated (and like
            // cowbird's curl_cffi). Without this a backend moving hosts with a
            // 301 surfaced as a non-JSON body and quarantined a correct adapter.
            .redirect(wreq::redirect::Policy::limited(10))
            .timeout(config.timeout);
        if let Some(p) = &config.proxy {
            b = b.proxy(wreq::Proxy::all(p.as_str()).map_err(|e| Error::down("transport", e))?);
        }
        b.build().map_err(|e| Error::down("transport", e))
    }
}

#[async_trait]
impl Backend for WreqBackend {
    async fn send(
        &self,
        req: HttpRequest,
        fresh: bool,
    ) -> std::result::Result<HttpResponse, String> {
        // A throwaway client is one TLS handshake per request. Only the few
        // backends that key inboxes on a session cookie pay for it.
        let fresh_client;
        let client = if fresh {
            fresh_client = Self::client(&self.config, false).map_err(|e| e.to_string())?;
            &fresh_client
        } else {
            &self.shared
        };
        let method = match req.method {
            Method::Get => wreq::Method::GET,
            Method::Post => wreq::Method::POST,
            Method::Put => wreq::Method::PUT,
            Method::Patch => wreq::Method::PATCH,
            Method::Delete => wreq::Method::DELETE,
        };
        let mut rb = client.request(method, req.full_url());
        if !req.follow_redirects {
            rb = rb.redirect(wreq::redirect::Policy::none());
        }
        for (k, v) in &req.headers {
            rb = rb.header(k.as_str(), v.as_str());
        }
        if !req.cookies.is_empty() {
            let jar = req
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            rb = rb.header("Cookie", jar);
        }
        rb = match &req.body {
            Body::Empty => rb,
            Body::Json(v) => rb.json(v),
            Body::Form(pairs) => rb.form(pairs),
            Body::Raw { content_type, data } => rb
                .header("Content-Type", content_type.as_str())
                .body(data.clone()),
        };
        let resp = rb.send().await.map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let text = resp.text().await.map_err(|e| e.to_string())?;
        Ok(HttpResponse {
            status,
            headers,
            text,
        })
    }
}

// Cloudflare's interstitial is HTML served with a 403 or 503. These markers
// are stable across its variants.
const CHALLENGE_MARKERS: &[&str] = &[
    "just a moment",
    "cf-browser-verification",
    "challenge-platform",
    "__cf_chl",
];

fn is_challenge(resp: &HttpResponse) -> bool {
    if resp.status != 403 && resp.status != 503 {
        return false;
    }
    if resp.header("cf-mitigated").is_some() {
        return true;
    }
    let head: String = resp
        .text
        .chars()
        .take(2000)
        .collect::<String>()
        .to_lowercase();
    CHALLENGE_MARKERS.iter().any(|m| head.contains(m))
}

fn retry_after(resp: &HttpResponse) -> Option<Duration> {
    resp.header("retry-after")?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

/// One backend's view of the network.
pub struct Transport {
    provider: String,
    backend: Arc<dyn Backend>,
    gate: Semaphore,
    retries: u32,
    backoff: Duration,
    fresh_session: bool,
    solver: Option<Solver>,
    // Keyed by lowercased host. One clearance serves every address on a host:
    // it certifies the egress, not the inbox.
    clearances: Mutex<HashMap<String, Arc<Clearance>>>,
    solving: tokio::sync::Mutex<()>,
}

impl Transport {
    pub fn new(provider: impl Into<String>, backend: Arc<dyn Backend>) -> Self {
        Transport {
            provider: provider.into(),
            backend,
            gate: Semaphore::new(4),
            retries: 2,
            backoff: Duration::from_millis(250),
            fresh_session: false,
            solver: None,
            clearances: Mutex::new(HashMap::new()),
            solving: tokio::sync::Mutex::new(()),
        }
    }

    pub fn max_concurrency(mut self, n: usize) -> Self {
        self.gate = Semaphore::new(n.max(1));
        self
    }

    pub fn retries(mut self, n: u32) -> Self {
        self.retries = n;
        self
    }

    pub fn backoff(mut self, base: Duration) -> Self {
        self.backoff = base;
        self
    }

    pub fn fresh_session(mut self, yes: bool) -> Self {
        self.fresh_session = yes;
        self
    }

    pub fn solver(mut self, solver: Option<Solver>) -> Self {
        self.solver = solver;
        self
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// The Cloudflare solver, for adapters that need a Turnstile token.
    pub fn turnstile_solver(&self) -> Result<&Solver> {
        self.solver.as_ref().ok_or_else(|| {
            Error::SolverUnavailable(format!("{} needs a solver; none configured", self.provider))
        })
    }

    pub fn request(&self, method: Method, url: impl Into<String>) -> Req<'_> {
        Req {
            t: self,
            req: HttpRequest {
                method,
                url: url.into(),
                query: Vec::new(),
                headers: Vec::new(),
                cookies: Vec::new(),
                body: Body::Empty,
                follow_redirects: true,
            },
        }
    }

    pub fn get(&self, url: impl Into<String>) -> Req<'_> {
        self.request(Method::Get, url)
    }

    pub fn post(&self, url: impl Into<String>) -> Req<'_> {
        self.request(Method::Post, url)
    }

    pub fn put(&self, url: impl Into<String>) -> Req<'_> {
        self.request(Method::Put, url)
    }

    pub fn delete(&self, url: impl Into<String>) -> Req<'_> {
        self.request(Method::Delete, url)
    }

    async fn execute(&self, req: HttpRequest) -> Result<HttpResponse> {
        let _permit = self.gate.acquire().await.expect("gate never closes");
        let host = url::Url::parse(&req.url)
            .ok()
            .and_then(|u| Some((u.scheme().to_string(), u.host_str()?.to_lowercase())));
        let used = host.as_ref().and_then(|(_, h)| self.clearance_for(h));
        match self.attempts(cleared(&req, used.as_deref())).await {
            Err(Error::Challenge { .. }) if self.solver.is_some() && host.is_some() => {
                let (scheme, host) = host.expect("checked");
                let fresh = self
                    .refresh_clearance(&scheme, &host, used.as_ref())
                    .await?;
                let result = self.attempts(cleared(&req, Some(&fresh))).await;
                if matches!(result, Err(Error::Challenge { .. })) {
                    // Solved and still challenged: the clearance does not work
                    // from here. At most one solve per request; no loop.
                    let mut map = self.clearances.lock().unwrap();
                    if map.get(&host).is_some_and(|c| Arc::ptr_eq(c, &fresh)) {
                        map.remove(&host);
                    }
                }
                result
            }
            other => other,
        }
    }

    fn clearance_for(&self, host: &str) -> Option<Arc<Clearance>> {
        self.clearances.lock().unwrap().get(host).cloned()
    }

    async fn refresh_clearance(
        &self,
        scheme: &str,
        host: &str,
        used: Option<&Arc<Clearance>>,
    ) -> Result<Arc<Clearance>> {
        let _one_at_a_time = self.solving.lock().await;
        if let Some(current) = self.clearance_for(host)
            && used.is_none_or(|u| !Arc::ptr_eq(u, &current))
        {
            return Ok(current); // a concurrent request already re-solved
        }
        let solver = self.solver.as_ref().expect("checked by caller");
        // The origin, not the request URL: the solver's browser must not GET
        // a POST-only API route.
        let fresh = Arc::new(solver.clearance(&format!("{scheme}://{host}/")).await?);
        self.clearances
            .lock()
            .unwrap()
            .insert(host.to_string(), fresh.clone());
        Ok(fresh)
    }

    async fn attempts(&self, req: HttpRequest) -> Result<HttpResponse> {
        let mut last = None;
        for attempt in 0..=self.retries {
            match self.backend.send(req.clone(), self.fresh_session).await {
                Err(e) => last = Some(Error::down(&self.provider, e)),
                Ok(resp) => {
                    if is_challenge(&resp) {
                        return Err(Error::Challenge {
                            provider: self.provider.clone(),
                            status: resp.status,
                        });
                    }
                    if resp.status == 429 {
                        return Err(Error::RateLimited {
                            provider: self.provider.clone(),
                            retry_after: retry_after(&resp),
                        });
                    }
                    if resp.status < 500 {
                        return Ok(resp);
                    }
                    last = Some(Error::down(&self.provider, format!("HTTP {}", resp.status)));
                }
            }
            if attempt < self.retries {
                let base = self.backoff * 2u32.pow(attempt);
                let jitter = rand::rng().random_range(0..=self.backoff.as_millis() as u64);
                tokio::time::sleep(base + Duration::from_millis(jitter)).await;
            }
        }
        Err(last.unwrap_or_else(|| Error::down(&self.provider, "request failed")))
    }
}

fn cleared(req: &HttpRequest, clearance: Option<&Clearance>) -> HttpRequest {
    let mut req = req.clone();
    if let Some(c) = clearance {
        req.cookies.extend(c.cookies.iter().cloned());
        // The clearance's User-Agent wins: the cookie is void under any other.
        req.set_header("User-Agent", c.user_agent.clone());
    }
    req
}

/// A request being built against a [`Transport`].
#[must_use = "a request does nothing until sent"]
pub struct Req<'a> {
    t: &'a Transport,
    req: HttpRequest,
}

impl Req<'_> {
    pub fn query(mut self, k: impl Into<String>, v: impl ToString) -> Self {
        self.req.query.push((k.into(), v.to_string()));
        self
    }

    pub fn header(mut self, k: impl AsRef<str>, v: impl Into<String>) -> Self {
        self.req.set_header(k.as_ref(), v.into());
        self
    }

    /// Answer with the 3xx itself instead of following it.
    pub fn no_redirect(mut self) -> Self {
        self.req.follow_redirects = false;
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("Authorization", format!("Bearer {token}"))
    }

    pub fn cookie(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.req.cookies.push((k.into(), v.into()));
        self
    }

    pub fn json_body(mut self, body: &impl Serialize) -> Self {
        self.req.body = Body::Json(serde_json::to_value(body).expect("request bodies serialize"));
        self
    }

    pub fn form<K: Into<String>, V: ToString>(
        mut self,
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        self.req.body = Body::Form(
            pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.to_string()))
                .collect(),
        );
        self
    }

    pub fn raw_body(mut self, content_type: &str, data: impl Into<String>) -> Self {
        self.req.body = Body::Raw {
            content_type: content_type.into(),
            data: data.into(),
        };
        self
    }

    /// The raw response, for adapters that branch on status. Any 4xx is the
    /// caller's to interpret; 429, 5xx and challenges are already errors.
    pub async fn send(self) -> Result<HttpResponse> {
        self.t.execute(self.req).await
    }

    /// Like [`send`](Self::send) with `Accept: application/json` pinned
    /// (unless set): a browser's default Accept content-negotiates, and some
    /// APIs hand an impersonating client HTML or XML instead.
    pub async fn send_json(mut self) -> Result<HttpResponse> {
        if self.req.header("Accept").is_none() {
            self.req.set_header("Accept", "application/json".into());
        }
        self.send().await
    }

    /// The body parsed as JSON. A non-JSON body on a 4xx is reported as the
    /// provider being down (an error page), not drift: a transient WAF block
    /// must not quarantine an adapter that is still correct.
    pub async fn json(self) -> Result<Value> {
        let provider = self.t.provider.clone();
        let resp = self.send_json().await?;
        match serde_json::from_str(&resp.text) {
            Ok(v) => Ok(v),
            // An error page or an unfollowed redirect: an outage, not drift.
            Err(_) if resp.status >= 300 => {
                Err(Error::down(&provider, format!("HTTP {}", resp.status)))
            }
            Err(_) => Err(Error::drift(
                &provider,
                "a JSON body",
                clip(&resp.text, 200),
            )),
        }
    }

    /// The body deserialized into `T`; a mismatch is drift.
    pub async fn json_as<T: DeserializeOwned>(self) -> Result<T> {
        let provider = self.t.provider.clone();
        let v = self.json().await?;
        serde_json::from_value(v.clone()).map_err(|e| {
            Error::drift(
                &provider,
                format!("{} ({e})", std::any::type_name::<T>()),
                v,
            )
        })
    }

    pub async fn text(self) -> Result<String> {
        Ok(self.send().await?.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    fn transport(f: &Arc<Fixtures>) -> Transport {
        Transport::new("p", f.clone())
            .retries(2)
            .backoff(Duration::from_millis(1))
    }

    #[tokio::test]
    async fn retries_5xx_then_reports_down() {
        let f = Fixtures::new().route("GET https://x.test/", Reply::status(502));
        let err = transport(&f)
            .get("https://x.test/")
            .send()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ProviderDown { .. }), "{err}");
        assert_eq!(f.seen().len(), 3);
    }

    #[tokio::test]
    async fn recovers_after_one_5xx() {
        let f = Fixtures::new().route_seq(
            "GET https://x.test/",
            [
                Reply::status(503),
                Reply::json(serde_json::json!({"ok": 1})),
            ],
        );
        let v = transport(&f).get("https://x.test/").json().await.unwrap();
        assert_eq!(v["ok"], 1);
    }

    #[tokio::test]
    async fn rate_limit_is_not_retried_and_carries_retry_after() {
        let f = Fixtures::new().route("x.test", Reply::status(429).header("Retry-After", "7"));
        let err = transport(&f)
            .get("https://x.test/")
            .send()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::RateLimited { retry_after: Some(d), .. } if d.as_secs() == 7));
        assert_eq!(f.seen().len(), 1);
    }

    #[tokio::test]
    async fn challenge_is_detected_by_header_or_body() {
        let f = Fixtures::new()
            .route(
                "a.test",
                Reply::status(403).header("cf-mitigated", "challenge"),
            )
            .route(
                "b.test",
                Reply::text("<title>Just a moment...</title>").with_status(503),
            );
        let t = transport(&f);
        assert!(matches!(
            t.get("https://a.test/").send().await,
            Err(Error::Challenge { .. })
        ));
        assert!(matches!(
            t.get("https://b.test/").send().await,
            Err(Error::Challenge { .. })
        ));
    }

    #[tokio::test]
    async fn json_pins_accept_and_drift_on_garbage() {
        let f = Fixtures::new().route("x.test", Reply::text("<html>"));
        let err = transport(&f)
            .get("https://x.test/")
            .json()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }));
        assert_eq!(f.seen()[0].header("accept"), Some("application/json"));
    }

    #[tokio::test]
    async fn non_json_error_page_is_down_not_drift() {
        let f = Fixtures::new().route("x.test", Reply::text("<html>blocked").with_status(403));
        let err = transport(&f)
            .get("https://x.test/")
            .json()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ProviderDown { .. }), "{err}");
    }

    #[tokio::test]
    async fn unfollowed_redirect_is_down_not_drift() {
        let f = Fixtures::new().route(
            "x.test",
            Reply::text("<a href=/>moved</a>").with_status(301),
        );
        let err = transport(&f)
            .get("https://x.test/")
            .json()
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ProviderDown { .. }), "{err}");
    }

    #[tokio::test]
    async fn challenge_triggers_one_solve_then_replays_with_clearance() {
        let solver_wire = Fixtures::new().route(
            "/iuam",
            Reply::json(serde_json::json!({"headers": {"Cookie": "cf_clearance=abc; other=1", "User-Agent": "UA/1"}})),
        );
        let f = Fixtures::new()
            .route(
                "cf_clearance=abc",
                Reply::json(serde_json::json!({"ok": true})),
            )
            .route(
                "x.test",
                Reply::status(403).header("cf-mitigated", "challenge"),
            );
        let t = transport(&f).solver(Some(Solver::with_backend(
            "http://solver.test",
            solver_wire.clone(),
        )));
        let v = t.get("https://x.test/api").json().await.unwrap();
        assert_eq!(v["ok"], true);
        let last = f.seen().last().unwrap().clone();
        assert_eq!(last.header("user-agent"), Some("UA/1"));
        // Second request reuses the clearance without another solve.
        t.get("https://x.test/api").json().await.unwrap();
        assert_eq!(solver_wire.seen().len(), 1);
    }

    #[tokio::test]
    async fn concurrency_gate_holds() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Slow(AtomicUsize, AtomicUsize);
        #[async_trait]
        impl Backend for Slow {
            async fn send(
                &self,
                _: HttpRequest,
                _: bool,
            ) -> std::result::Result<HttpResponse, String> {
                let now = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                self.1.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.0.fetch_sub(1, Ordering::SeqCst);
                Ok(HttpResponse {
                    status: 200,
                    headers: vec![],
                    text: "{}".into(),
                })
            }
        }
        let wire = Arc::new(Slow(AtomicUsize::new(0), AtomicUsize::new(0)));
        let t = Arc::new(Transport::new("p", wire.clone()).max_concurrency(2));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let t = t.clone();
                tokio::spawn(async move { t.get("https://x.test/").send().await.unwrap() })
            })
            .collect();
        for j in jobs {
            j.await.unwrap();
        }
        assert_eq!(wire.1.load(Ordering::SeqCst), 2);
    }
}
