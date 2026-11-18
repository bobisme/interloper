//! Offline doubles: a replay wire, a fake provider, and helpers to build a
//! pool of fakes. Shipped in the library (not `#[cfg(test)]`) because the CLI,
//! the server and third-party adapters test against them too.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Message, MessageRow};
use crate::provider::{GenerateOptions, Provider};
use crate::transport::{Backend, Body, HttpRequest, HttpResponse, Transport, encode_pairs};

/// One canned answer.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Fail at the wire (connection refused, timeout) instead of answering.
    pub wire_error: Option<String>,
}

impl Reply {
    pub fn json(v: Value) -> Self {
        Reply {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: v.to_string(),
            wire_error: None,
        }
    }

    pub fn text(s: impl Into<String>) -> Self {
        Reply {
            status: 200,
            headers: vec![],
            body: s.into(),
            wire_error: None,
        }
    }

    pub fn status(status: u16) -> Self {
        Reply {
            status,
            headers: vec![],
            body: String::new(),
            wire_error: None,
        }
    }

    pub fn wire_error(msg: impl Into<String>) -> Self {
        Reply {
            wire_error: Some(msg.into()),
            ..Reply::status(0)
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    pub fn set_cookie(self, name: &str, value: &str) -> Self {
        self.header("Set-Cookie", &format!("{name}={value}; Path=/"))
    }
}

struct Route {
    key: String,
    // Answers in order; the last one repeats.
    replies: Vec<Reply>,
    calls: AtomicUsize,
}

/// A replay wire. A route key matches as a substring of
/// `"METHOD url?query body cookies headers"`, longest key first, so a single
/// message URL never gets the list fixture, and a backend that multiplexes one
/// URL on a query parameter or request body can still be routed per call.
/// The same matching rule as cowbird's FakeTransport, so its fixtures port
/// directly.
#[derive(Default)]
pub struct Fixtures {
    routes: Mutex<Vec<Route>>,
    seen: Mutex<Vec<HttpRequest>>,
    fresh: Mutex<Vec<bool>>,
}

impl Fixtures {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Arc<Fixtures> {
        Arc::new(Fixtures::default())
    }

    /// Load `name` from a fixture directory as JSON.
    pub fn load(dir: &str, name: &str) -> Value {
        let path = format!("{dir}/{name}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    pub fn load_text(dir: &str, name: &str) -> String {
        let path = format!("{dir}/{name}");
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {path}: {e}"))
    }

    pub fn route(self: Arc<Self>, key: &str, reply: Reply) -> Arc<Self> {
        self.route_seq(key, [reply])
    }

    pub fn route_seq(
        self: Arc<Self>,
        key: &str,
        replies: impl IntoIterator<Item = Reply>,
    ) -> Arc<Self> {
        let replies: Vec<Reply> = replies.into_iter().collect();
        assert!(!replies.is_empty(), "a route needs at least one reply");
        {
            let mut routes = self.routes.lock().unwrap();
            routes.retain(|r| r.key != key);
            routes.push(Route {
                key: key.to_string(),
                replies,
                calls: AtomicUsize::new(0),
            });
        }
        self
    }

    /// Every request the wire received, in order.
    pub fn seen(&self) -> Vec<HttpRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// Whether each request asked for a fresh session.
    pub fn fresh_flags(&self) -> Vec<bool> {
        self.fresh.lock().unwrap().clone()
    }

    pub fn methods(&self) -> Vec<&'static str> {
        self.seen().iter().map(|r| r.method.as_str()).collect()
    }

    /// A transport over this wire, with retries off so failures are immediate.
    pub fn transport(self: &Arc<Self>, provider: &str, caps: &Capabilities) -> Transport {
        Transport::new(provider, self.clone())
            .retries(0)
            .max_concurrency(caps.max_concurrency)
            .fresh_session(caps.fresh_session)
    }

    fn target(req: &HttpRequest) -> String {
        let body = match &req.body {
            Body::Empty => String::new(),
            Body::Json(v) => v.to_string(),
            Body::Form(p) => encode_pairs(p),
            Body::Raw { data, .. } => data.clone(),
        };
        let cookies = encode_pairs(&req.cookies);
        let headers = req
            .headers
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} {}?{} {} {} {}",
            req.method.as_str(),
            req.url,
            encode_pairs(&req.query),
            body,
            cookies,
            headers
        )
    }
}

#[async_trait]
impl Backend for Fixtures {
    async fn send(
        &self,
        req: HttpRequest,
        fresh: bool,
    ) -> std::result::Result<HttpResponse, String> {
        let target = Self::target(&req);
        self.seen.lock().unwrap().push(req);
        self.fresh.lock().unwrap().push(fresh);
        let routes = self.routes.lock().unwrap();
        let mut order: Vec<&Route> = routes.iter().collect();
        order.sort_by_key(|r| std::cmp::Reverse(r.key.len()));
        let Some(route) = order.into_iter().find(|r| target.contains(&r.key)) else {
            panic!("unexpected request: {target}");
        };
        let n = route.calls.fetch_add(1, Ordering::SeqCst);
        let reply = &route.replies[n.min(route.replies.len() - 1)];
        if let Some(e) = &reply.wire_error {
            return Err(e.clone());
        }
        Ok(HttpResponse {
            status: reply.status,
            headers: reply.headers.clone(),
            text: reply.body.clone(),
        })
    }
}

pub const FAKE_CAPS: Capabilities = Capabilities {
    sites: &["fake.test"],
    domains: &["fake.test"],
    ..Capabilities::DEFAULT
};

type Override<T> = Arc<dyn Fn(usize) -> Result<T> + Send + Sync>;

/// A provider that never touches a network. `pages` is consumed one entry per
/// `list()` call; once exhausted, the inbox stays as the last page.
#[derive(Clone)]
pub struct FakeProvider {
    pub name: &'static str,
    pub caps: Capabilities,
    pages: Arc<Mutex<VecDeque<Vec<MessageRow>>>>,
    last: Arc<Mutex<Vec<MessageRow>>>,
    bodies: Arc<Mutex<Vec<Message>>>,
    generated: Arc<AtomicUsize>,
    list_calls: Arc<AtomicUsize>,
    generate_override: Option<Override<Address>>,
    list_override: Option<Override<Vec<MessageRow>>>,
    pub delay: Option<std::time::Duration>,
    pub deleted: Arc<Mutex<Vec<String>>>,
}

impl FakeProvider {
    pub fn new(name: &'static str) -> Self {
        FakeProvider {
            name,
            caps: FAKE_CAPS,
            pages: Default::default(),
            last: Default::default(),
            bodies: Default::default(),
            generated: Default::default(),
            list_calls: Default::default(),
            generate_override: None,
            list_override: None,
            delay: None,
            deleted: Default::default(),
        }
    }

    pub fn caps(mut self, caps: Capabilities) -> Self {
        self.caps = caps;
        self
    }

    pub fn pages(self, pages: impl IntoIterator<Item = Vec<MessageRow>>) -> Self {
        self.pages.lock().unwrap().extend(pages);
        self
    }

    /// Full messages served by `get()`, matched by id.
    pub fn bodies(self, bodies: impl IntoIterator<Item = Message>) -> Self {
        self.bodies.lock().unwrap().extend(bodies);
        self
    }

    pub fn generate_with(
        mut self,
        f: impl Fn(usize) -> Result<Address> + Send + Sync + 'static,
    ) -> Self {
        self.generate_override = Some(Arc::new(f));
        self
    }

    pub fn failing(self, err: Error) -> Self {
        self.generate_with(move |_| Err(err.clone()))
    }

    pub fn list_with(
        mut self,
        f: impl Fn(usize) -> Result<Vec<MessageRow>> + Send + Sync + 'static,
    ) -> Self {
        self.list_override = Some(Arc::new(f));
        self
    }

    pub fn slow(mut self, d: std::time::Duration) -> Self {
        self.delay = Some(d);
        self
    }

    pub fn generated(&self) -> usize {
        self.generated.load(Ordering::SeqCst)
    }

    /// A fake message whose text is `text`.
    pub fn message(id: &str, subject: &str, text: &str) -> Message {
        Message::from_bodies(id, "s@x.test", subject, None, "", Some(text.to_string()))
    }
}

#[async_trait]
impl Provider for FakeProvider {
    fn name(&self) -> &str {
        self.name
    }

    fn caps(&self) -> &Capabilities {
        &self.caps
    }

    async fn generate(&self, _opts: &GenerateOptions) -> Result<Address> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        let n = self.generated.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = &self.generate_override {
            return f(n);
        }
        let local = if n == 0 {
            "a".to_string()
        } else {
            format!("a{n}")
        };
        Ok(Address::new(format!("{local}@fake.test"), self.name))
    }

    async fn list(&self, _address: &Address) -> Result<Vec<MessageRow>> {
        if let Some(f) = &self.list_override {
            return f(self.list_calls.fetch_add(1, Ordering::SeqCst));
        }
        if let Some(page) = self.pages.lock().unwrap().pop_front() {
            *self.last.lock().unwrap() = page.clone();
            return Ok(page);
        }
        Ok(self.last.lock().unwrap().clone())
    }

    async fn get(&self, _address: &Address, id: &str) -> Result<Message> {
        if let Some(m) = self.bodies.lock().unwrap().iter().find(|m| m.id == id) {
            return Ok(m.clone());
        }
        Ok(Message::from_bodies(
            id,
            "s@x.test",
            "hi",
            None,
            "",
            Some(String::new()),
        ))
    }

    async fn delete(&self, _address: &Address, id: &str) -> Result<()> {
        if !self.caps.delete {
            return Err(Error::unsupported(format!("{} cannot delete", self.name)));
        }
        self.deleted.lock().unwrap().push(id.to_string());
        Ok(())
    }
}
