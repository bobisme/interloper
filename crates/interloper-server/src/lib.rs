//! HTTP API over interloper.
//!
//! | route | |
//! |---|---|
//! | `GET /health` | liveness, no auth, not rate limited |
//! | `GET /v1/providers` | measured health matrix |
//! | `DELETE /v1/providers/{name}/quarantine` | return a quarantined provider to routing |
//! | `POST /v1/inboxes` | issue an address |
//! | `GET /v1/inboxes/{addr}/messages` | list |
//! | `GET /v1/inboxes/{addr}/messages/{id}` | read one, with its OTP |
//! | `DELETE /v1/inboxes/{addr}/messages/{id}` | delete |
//! | `GET /v1/inboxes/{addr}/wait` | long-poll for the next (matching) message |
//! | `GET /v1/inboxes/{addr}/events` | Server-Sent Events: every message as it lands |
//! | `POST/GET /v1/webhooks`, `DELETE /v1/webhooks/{id}` | one-shot outbound webhooks |
//!
//! Every response is `{"success", "data", "error"}`. Auth is `X-API-Key`.

pub mod config;
pub mod error;
pub mod ratelimit;
pub mod service;
pub mod store;
pub mod webhooks;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, Query, Request as HttpRequest, State};
use axum::http::{HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use futures::StreamExt;
use interloper::health::Status;
use interloper::regex::Regex;
use interloper::{Interloper, Kind, MailFilter, Message, Request};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::config::Config;
use crate::error::ApiError;
use crate::ratelimit::Limiter;
use crate::service::Service;
use crate::store::Store;
use crate::webhooks::Webhooks;

/// The one response shape. `success` is derived from `error`, so a body can
/// never claim success while carrying one.
pub fn envelope(data: Value) -> Value {
    json!({"success": true, "data": data, "error": null})
}

pub fn envelope_err(msg: &str) -> Value {
    json!({"success": false, "data": null, "error": msg})
}

/// The one shape a message takes on the wire: `.../messages/{id}`, `wait`,
/// SSE and webhook payloads alike.
pub fn message_json(m: &Message, otp: Option<&str>) -> Value {
    json!({
        "id": m.id,
        "sender": m.sender,
        "subject": m.subject,
        "received_at": m.received_at.map(|t| t.to_string()),
        "html": m.html,
        "text": m.text,
        "links": m.links,
        "otp": otp,
    })
}

pub struct AppState {
    pub config: Config,
    pub service: Arc<Service>,
    pub webhooks: Arc<Webhooks>,
    limiter: Limiter,
}

type St = State<Arc<AppState>>;

impl AppState {
    pub fn new(config: Config, il: Interloper, store: Store) -> Arc<Self> {
        let service = Service::new(il, store);
        let webhooks = Webhooks::new(
            service.clone(),
            config.webhook_allow_private,
            config.webhook_secret.clone(),
        );
        let limiter = Limiter::new(config.rate_limit.0, config.rate_limit.1);
        Arc::new(AppState {
            config,
            service,
            webhooks,
            limiter,
        })
    }

    fn key_valid(&self, candidate: &str) -> bool {
        // Constant-time against every configured key, so timing cannot
        // recover a key byte by byte.
        let mut ok = 0u8;
        for k in &self.config.api_keys {
            ok |= u8::from(bool::from(candidate.as_bytes().ct_eq(k.as_bytes())));
        }
        ok == 1
    }
}

async fn auth(State(s): St, req: HttpRequest, next: Next) -> Result<Response, ApiError> {
    let key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key.is_empty() || !s.key_valid(key) {
        return Err(ApiError::Unauthorized);
    }
    Ok(next.run(req).await)
}

async fn rate_limit(State(s): St, req: HttpRequest, next: Next) -> Result<Response, ApiError> {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| "unknown".to_string(), |c| c.0.ip().to_string());
    let key = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let bucket = if !key.is_empty() && s.key_valid(key) {
        format!("{ip}|{key}")
    } else {
        ip
    };
    if !s.limiter.allow(&bucket) {
        return Err(ApiError::RateLimited);
    }
    Ok(next.run(req).await)
}

async fn health() -> Json<Value> {
    Json(envelope(json!({"status": "ok"})))
}

async fn providers(State(s): St) -> Json<Value> {
    let il = &s.service.il;
    let rows: Vec<Value> = il
        .registry()
        .specs()
        .map(|spec| {
            let h = il.health();
            let mut status = h.status(spec.name).to_string();
            if h.status(spec.name) == Status::Down && h.tier(spec.name).is_some() {
                status = "probation".into();
            }
            json!({
                "provider": spec.name,
                "status": status,
                "p50": h.p50(spec.name),
                "kind": spec.caps.kind.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
                "sites": spec.caps.sites,
                "needs_solver": spec.caps.needs_solver,
            })
        })
        .collect();
    Json(envelope(Value::Array(rows)))
}

async fn clear_quarantine(State(s): St, Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    if !s.service.il.registry().contains(&name) {
        return Err(ApiError::NotFound);
    }
    let was = s.service.il.health().unquarantine(&name);
    Ok(Json(envelope(json!({"cleared": was}))))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CreateInbox {
    provider: Option<String>,
    kind: Option<Kind>,
    local: Option<String>,
    domain: Option<String>,
    #[serde(default)]
    domain_not_in: Vec<String>,
    address_ttl_seconds: Option<u64>,
    message_ttl_seconds: Option<u64>,
}

async fn create_inbox(
    State(s): St,
    body: Option<Json<CreateInbox>>,
) -> Result<Json<Value>, ApiError> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    let req = Request {
        provider: b.provider,
        kind: b.kind,
        local: b.local,
        domain: b.domain,
        domain_not_in: b.domain_not_in,
        address_ttl: b.address_ttl_seconds.map(Duration::from_secs),
        message_ttl: b.message_ttl_seconds.map(Duration::from_secs),
        ..Default::default()
    };
    let a = s.service.create(&req).await?;
    // `state` is deliberately absent: a provider credential the server holds
    // so the client never has to.
    Ok(Json(envelope(json!({
        "address": a.value,
        "provider": a.provider,
        "expires_at": a.expires_at.map(|t| t.to_string()),
    }))))
}

async fn list_messages(State(s): St, Path(addr): Path<String>) -> Result<Json<Value>, ApiError> {
    let rows = s.service.inbox(&addr)?.messages().await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"id": r.id, "sender": r.sender, "subject": r.subject,
                   "received_at": r.received_at.map(|t| t.to_string()), "locked": r.locked})
        })
        .collect();
    Ok(Json(envelope(Value::Array(data))))
}

async fn get_message(
    State(s): St,
    Path((addr, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (m, code) = s.service.get_message(&addr, &id).await?;
    Ok(Json(envelope(message_json(&m, code.as_deref()))))
}

async fn delete_message(
    State(s): St,
    Path((addr, id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    s.service.inbox(&addr)?.delete(&id).await?;
    Ok(Json(envelope(json!({"deleted": id}))))
}

#[derive(Deserialize)]
struct WaitQuery {
    timeout: Option<u64>,
    #[serde(default)]
    otp: bool,
    pattern: Option<String>,
    from: Option<String>,
    subject: Option<String>,
}

fn compile(pattern: Option<&str>) -> Result<Option<Regex>, ApiError> {
    pattern
        .map(|p| {
            // Bounded: a caller-supplied regex must not be able to build an
            // enormous automaton on the server.
            interloper::regex::RegexBuilder::new(p)
                .size_limit(1 << 20)
                .build()
                .map_err(|_| ApiError::BadRequest("invalid pattern".into()))
        })
        .transpose()
}

async fn wait(
    State(s): St,
    Path(addr): Path<String>,
    Query(q): Query<WaitQuery>,
) -> Result<Json<Value>, ApiError> {
    if q.timeout == Some(0) {
        return Err(ApiError::BadRequest("timeout must be at least 1".into()));
    }
    let held = s.config.clamp_wait(q.timeout);
    let pattern = compile(q.pattern.as_deref())?;
    let filter = MailFilter {
        from: q.from,
        subject: q.subject,
    };
    let found = s
        .service
        .wait(&addr, held, pattern.as_ref(), q.otp, &filter)
        .await?;
    Ok(Json(envelope(match found {
        Some((m, code)) => message_json(&m, code.as_deref()),
        None => Value::Null,
    })))
}

/// Every message as it lands, as Server-Sent Events. Long-poll `wait`
/// answers one message per request; this holds one connection for a stream.
async fn events(State(s): St, Path(addr): Path<String>) -> Result<impl IntoResponse, ApiError> {
    let inbox = s.service.inbox(&addr)?;
    let stream = async_stream::stream! {
        let mut mail = inbox.watch(None);
        while let Some(m) = mail.next().await {
            match m {
                Ok(m) => {
                    let code = interloper::parse::extract_otp(&m.subject, &m.text, None);
                    yield Ok::<_, Infallible>(Event::default().event("message").json_data(message_json(&m, code.as_deref())).expect("json"));
                }
                Err(e) => {
                    let (_, msg) = error::status_for(&e);
                    yield Ok(Event::default().event("error").data(msg));
                    break;
                }
            }
        }
    };
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWebhook {
    address: String,
    url: String,
    timeout: Option<u64>,
}

async fn create_webhook(
    State(s): St,
    Json(b): Json<CreateWebhook>,
) -> Result<Json<Value>, ApiError> {
    // Resolve first, so an address this server never issued fails now with a
    // 404 rather than later as a silent timeout.
    s.service.inbox(&b.address)?;
    if b.timeout == Some(0) {
        return Err(ApiError::BadRequest("timeout must be at least 1".into()));
    }
    let timeout = s.config.clamp_webhook(b.timeout);
    // The one place a raw error reaches a client: it is about the caller's
    // own URL, which they already have.
    let id = s
        .webhooks
        .create(b.address.to_lowercase(), &b.url, timeout)
        .await
        .map_err(ApiError::BadRequest)?;
    Ok(Json(envelope(json!({"id": id}))))
}

async fn list_webhooks(State(s): St) -> Json<Value> {
    Json(envelope(serde_json::to_value(s.webhooks.list()).unwrap()))
}

async fn delete_webhook(State(s): St, Path(id): Path<String>) -> Json<Value> {
    Json(envelope(json!({"cancelled": s.webhooks.cancel(&id)})))
}

async fn fallback() -> ApiError {
    ApiError::NotFound
}

pub fn router(state: Arc<AppState>) -> Router {
    let v1 = Router::new()
        .route("/providers", get(providers))
        .route("/providers/{name}/quarantine", delete(clear_quarantine))
        .route("/inboxes", post(create_inbox))
        .route("/inboxes/{addr}/messages", get(list_messages))
        .route(
            "/inboxes/{addr}/messages/{id}",
            get(get_message).delete(delete_message),
        )
        .route("/inboxes/{addr}/wait", get(wait))
        .route("/inboxes/{addr}/events", get(events))
        .route("/webhooks", post(create_webhook).get(list_webhooks))
        .route("/webhooks/{id}", delete(delete_webhook))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit));
    let mut app = Router::new()
        .route("/health", get(health))
        .nest("/v1", v1)
        .fallback(fallback)
        .with_state(state.clone());
    if !state.config.allowed_origins.is_empty() {
        let origins: Vec<HeaderValue> = state
            .config
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        app = app.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    "x-api-key".parse().unwrap(),
                ]),
        );
    }
    app
}

/// Run the server until Ctrl-C/SIGTERM. Refuses to start without API keys.
pub async fn serve(config: Config, il: Interloper) -> Result<(), String> {
    if config.api_keys.is_empty() {
        return Err("INTERLOPER_API_KEYS is empty; refusing to start an open server".into());
    }
    let store = match &config.database {
        // A silent fall back to memory while an operator believes state is
        // durable would be invisible until reads start missing.
        Some(p) => Store::sqlite(p).map_err(|e| format!("database {}: {e}", p.display()))?,
        None => Store::memory(),
    };
    let bind = config.bind;
    let every = config.maintenance_every;
    let state = AppState::new(config, il, store);
    let maint = state.clone();
    let maintenance = tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let _ = maint.service.il.save_health();
            if let Ok(n) = maint.service.store.sweep()
                && n > 0
            {
                tracing::info!(reaped = n, "expired addresses swept");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    tracing::info!(%bind, "interloper server listening");
    let app = router(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    maintenance.abort();
    state.webhooks.shutdown();
    // Measurements taken while serving are worth keeping; a read-only disk
    // must not fail shutdown.
    let _ = state.service.il.save_health();
    result.map_err(|e| e.to_string())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

#[cfg(test)]
mod tests;
