//! Client for an external Cloudflare solver
//! (github.com/B00H0O/cloudflare-solver).
//!
//! The solver drives a real browser; interloper only talks to it over HTTP,
//! and only when `INTERLOPER_SOLVER_URL` (or `COWBIRD_SOLVER_URL`) is set. It
//! answers two questions: a Turnstile token for a sitekey, and the cookies and
//! User-Agent that get past an interstitial. Both are bound to the IP that
//! earned them, so the solver and interloper must share an egress; a
//! transport's proxy is forwarded to the solver for exactly that reason.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::error::{Error, Result, clip};
use crate::transport::{Backend, Body, HttpRequest, Method, NetConfig, WreqBackend};

pub const ENV: &[&str] = &["INTERLOPER_SOLVER_URL", "COWBIRD_SOLVER_URL"];

#[derive(Clone)]
pub struct Clearance {
    pub cookies: Vec<(String, String)>,
    pub user_agent: String,
}

impl fmt::Debug for Clearance {
    // cf_clearance is a credential for this egress.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clearance")
            .field("cookies", &"<redacted>")
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

#[derive(Clone)]
pub struct Solver {
    url: String,
    proxy: Option<String>,
    backend: Arc<dyn Backend>,
}

impl fmt::Debug for Solver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Solver").field("url", &self.url).finish()
    }
}

impl Solver {
    pub fn new(url: &str) -> Result<Self> {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(Error::unsupported(format!(
                "solver URL must be http(s)://, got {url:?}"
            )));
        }
        // Solves are slow (a real browser), so a generous timeout.
        let backend = WreqBackend::new(NetConfig {
            proxy: None,
            timeout: Duration::from_secs(90),
        })?;
        Ok(Self::with_backend(url, Arc::new(backend)))
    }

    pub fn with_backend(url: &str, backend: Arc<dyn Backend>) -> Self {
        Solver {
            url: url.trim_end_matches('/').to_string(),
            proxy: None,
            backend,
        }
    }

    pub fn from_env() -> Result<Option<Self>> {
        match ENV
            .iter()
            .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
        {
            Some(url) => Self::new(url.trim()).map(Some),
            None => Ok(None),
        }
    }

    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    async fn post(&self, path: &str, mut body: Map<String, Value>) -> Result<Value> {
        if let Some(p) = &self.proxy {
            body.insert("proxy".into(), json!(p));
        }
        let req = HttpRequest {
            method: Method::Post,
            url: format!("{}{path}", self.url),
            query: vec![],
            headers: vec![("Accept".into(), "application/json".into())],
            cookies: vec![],
            body: Body::Json(Value::Object(body)),
        };
        let resp = self
            .backend
            .send(req, false)
            .await
            .map_err(|e| Error::SolverUnavailable(format!("{path}: {e}")))?;
        if resp.status >= 300 {
            return Err(Error::SolverUnavailable(format!(
                "{path}: HTTP {}",
                resp.status
            )));
        }
        serde_json::from_str(&resp.text).map_err(|_| {
            Error::SolverUnavailable(format!("{path}: not JSON: {}", clip(&resp.text, 200)))
        })
    }

    /// A Turnstile token for `sitekey` as served on `url`.
    pub async fn turnstile(
        &self,
        url: &str,
        sitekey: &str,
        action: Option<&str>,
        cdata: Option<&str>,
    ) -> Result<String> {
        let mut body = Map::new();
        body.insert("url".into(), json!(url));
        body.insert("sitekey".into(), json!(sitekey));
        if let Some(a) = action {
            body.insert("action".into(), json!(a));
        }
        if let Some(c) = cdata {
            body.insert("cdata".into(), json!(c));
        }
        let answer = self.post("/turnstile", body).await?;
        match answer.get("token").and_then(Value::as_str) {
            Some(t) if !t.is_empty() => Ok(t.to_string()),
            _ => Err(Error::SolverUnavailable(clip(
                &format!("/turnstile gave no token: {answer}"),
                300,
            ))),
        }
    }

    /// Cookies and User-Agent that pass the interstitial on `url`'s host.
    pub async fn clearance(&self, url: &str) -> Result<Clearance> {
        let mut body = Map::new();
        body.insert("url".into(), json!(url));
        let answer = self.post("/iuam", body).await?;
        let headers = answer.get("headers").cloned().unwrap_or(Value::Null);
        let cookie_header = headers.get("Cookie").and_then(Value::as_str).unwrap_or("");
        let cookies: Vec<(String, String)> = cookie_header
            .split(';')
            .filter_map(|p| {
                let (k, v) = p.trim().split_once('=')?;
                (!k.is_empty()).then(|| (k.to_string(), v.to_string()))
            })
            .collect();
        let ua = headers
            .get("User-Agent")
            .and_then(Value::as_str)
            .unwrap_or("");
        if ua.is_empty() || !cookies.iter().any(|(k, _)| k == "cf_clearance") {
            return Err(Error::SolverUnavailable(
                "/iuam gave no cf_clearance cookie and User-Agent".into(),
            ));
        }
        Ok(Clearance {
            cookies,
            user_agent: ua.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    #[tokio::test]
    async fn turnstile_forwards_proxy_and_returns_token() {
        let wire = Fixtures::new().route("/turnstile", Reply::json(json!({"token": "tok"})));
        let s = Solver::with_backend("http://s.test/", wire.clone())
            .with_proxy(Some("socks5://p".into()));
        assert_eq!(
            s.turnstile("https://x.test", "key", None, None)
                .await
                .unwrap(),
            "tok"
        );
        let Body::Json(body) = &wire.seen()[0].body else {
            panic!()
        };
        assert_eq!(body["proxy"], "socks5://p");
        assert_eq!(wire.seen()[0].url, "http://s.test/turnstile");
    }

    #[tokio::test]
    async fn failures_are_solver_unavailable() {
        let wire = Fixtures::new()
            .route("/turnstile", Reply::json(json!({"token": ""})))
            .route("/iuam", Reply::status(500));
        let s = Solver::with_backend("http://s.test", wire);
        assert!(matches!(
            s.turnstile("u", "k", None, None).await,
            Err(Error::SolverUnavailable(_))
        ));
        assert!(matches!(
            s.clearance("u").await,
            Err(Error::SolverUnavailable(_))
        ));
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(Solver::new("localhost:407").is_err());
    }
}
