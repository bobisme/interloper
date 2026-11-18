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
            follow_redirects: true,
        };
        let resp = self
            .backend
            .send(req, false)
            .await
            .map_err(|e| Error::SolverUnavailable(format!("{path}: {e}")))?;
        if resp.status >= 300 {
            // The solver explains a refusal as {"success":false,"message":..}:
            // 400 a bad request, 429 every tab busy, 500 a solve that failed
            // or timed out (its own `timeOut`, 29s by default).
            let why = serde_json::from_str::<Value>(&resp.text)
                .ok()
                .and_then(|v| {
                    v.get("message")?
                        .as_str()
                        .map(|m| format!(": {}", clip(m, 200)))
                })
                .unwrap_or_default();
            return Err(Error::SolverUnavailable(format!(
                "{path}: HTTP {}{why}",
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

    #[tokio::test]
    async fn a_refusal_carries_the_solvers_message() {
        // The solver's real error shape (server.rs json_error).
        let wire = Fixtures::new().route(
            "/turnstile",
            Reply::json(json!({"success": false, "message": "websocket read timed out"}))
                .with_status(500),
        );
        let err = Solver::with_backend("http://s.test", wire)
            .turnstile("https://x.test", "k", None, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::SolverUnavailable(m) if m == "/turnstile: HTTP 500: websocket read timed out"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn parses_the_solvers_real_iuam_answer() {
        // Shape from a live /iuam at ce75d71 (values replaced).
        let wire = Fixtures::new().route(
            "/iuam",
            Reply::json(json!({
                "headers": {
                    "Cookie": "cf_clearance=CLR.a=b-c;",
                    "User-Agent": "Mozilla/5.0 (Linux; Android 16; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.178 Mobile Safari/537.36"
                },
                "ip": "192.0.2.1",
                "elapsed": "1.21s",
                "elapsed_ms": 1210,
                "status": "completed"
            })),
        );
        let c = Solver::with_backend("http://s.test", wire)
            .clearance("https://x.test/")
            .await
            .unwrap();
        assert_eq!(
            c.cookies,
            [("cf_clearance".to_string(), "CLR.a=b-c".to_string())]
        );
        assert!(c.user_agent.contains("Chrome/148"));
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(Solver::new("localhost:407").is_err());
    }
}
