use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request as Req, StatusCode};
use http_body_util::BodyExt;
use interloper::model::Capabilities;
use interloper::testing::{FAKE_CAPS, FakeProvider};
use interloper::{Error, HealthStore, Interloper, MessageRow, Registry};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;

const FAST: Capabilities = Capabilities {
    poll_interval: Duration::from_millis(5),
    delete: true,
    ..FAKE_CAPS
};

fn app_with(
    providers: Vec<FakeProvider>,
    tweak: impl FnOnce(&mut Config),
) -> (Router, Arc<AppState>) {
    let mut reg = Registry::new([], Arc::new(HealthStore::new()));
    for p in providers {
        reg.insert(Arc::new(p));
    }
    let mut config = Config {
        api_keys: vec!["k1".into(), "k2".into()],
        wait_max: Duration::from_secs(2),
        wait_default: Duration::from_secs(1),
        ..Config::default()
    };
    tweak(&mut config);
    let state = AppState::new(
        config,
        Interloper::with_registry(reg).with_hedge(None),
        Store::memory(),
    );
    (router(state.clone()), state)
}

fn app(providers: Vec<FakeProvider>) -> Router {
    app_with(providers, |_| {}).0
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    key: Option<&str>,
) -> (StatusCode, Value) {
    let mut b = Req::builder().method(method).uri(uri);
    if let Some(k) = key {
        b = b.header("x-api-key", k);
    }
    let req = match body {
        Some(v) => b
            .header("content-type", "application/json")
            .body(Body::from(v.to_string())),
        None => b.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

fn mailbox() -> FakeProvider {
    FakeProvider::new("fake")
        .caps(FAST)
        .pages([vec![
            MessageRow::new("m1", "s", "Welcome"),
            MessageRow::new("m2", "s", "Code"),
        ]])
        .bodies([
            FakeProvider::message("m1", "Welcome", "Hello there"),
            FakeProvider::message("m2", "Your code", "Your verification code is 771204"),
        ])
}

#[tokio::test]
async fn health_needs_no_key() {
    let (s, v) = call(&app(vec![]), "GET", "/health", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!({"success": true, "data": {"status": "ok"}, "error": null})
    );
}

#[tokio::test]
async fn v1_requires_a_valid_key() {
    let a = app(vec![]);
    assert_eq!(
        call(&a, "GET", "/v1/providers", None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = call(&a, "GET", "/v1/providers", None, Some("nope")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["success"], false);
    assert_eq!(
        call(&a, "GET", "/v1/providers", None, Some("k2")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn issue_then_read_then_wait_for_otp() {
    let a = app(vec![mailbox()]);
    let (s, v) = call(&a, "POST", "/v1/inboxes", Some(json!({})), Some("k1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let addr = v["data"]["address"].as_str().unwrap().to_string();
    assert!(
        v["data"].get("state").is_none(),
        "state must never leave the server"
    );

    let (s, v) = call(
        &a,
        "GET",
        &format!("/v1/inboxes/{addr}/messages"),
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"].as_array().unwrap().len(), 2);

    let (_, v) = call(
        &a,
        "GET",
        &format!("/v1/inboxes/{addr}/messages/m2"),
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(v["data"]["otp"], "771204");

    let (_, v) = call(
        &a,
        "GET",
        &format!("/v1/inboxes/{addr}/wait?otp=true"),
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(v["data"]["id"], "m2", "wait?otp skips mail without a code");
    assert_eq!(v["data"]["otp"], "771204");
}

#[tokio::test]
async fn wait_filters_by_subject_and_times_out_to_null() {
    let a = app(vec![mailbox()]);
    let (_, v) = call(&a, "POST", "/v1/inboxes", None, Some("k1")).await;
    let addr = v["data"]["address"].as_str().unwrap().to_string();
    let (_, v) = call(
        &a,
        "GET",
        &format!("/v1/inboxes/{addr}/wait?subject=welcome"),
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(v["data"]["id"], "m1");
    let (s, v) = call(
        &a,
        "GET",
        &format!("/v1/inboxes/{addr}/wait?subject=invoice&timeout=1"),
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"], Value::Null);
}

#[tokio::test]
async fn unknown_address_is_404() {
    let (s, v) = call(
        &app(vec![]),
        "GET",
        "/v1/inboxes/who@x.test/messages",
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "unknown address");
}

#[tokio::test]
async fn provider_errors_never_leak_upstream_detail() {
    let p = FakeProvider::new("fake").failing(Error::drift("fake", "x", "SECRET-UPSTREAM-PAYLOAD"));
    let (s, v) = call(&app(vec![p]), "POST", "/v1/inboxes", None, Some("k1")).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!v.to_string().contains("SECRET"), "{v}");
}

#[tokio::test]
async fn bad_options_are_422() {
    let (s, _) = call(
        &app(vec![mailbox()]),
        "POST",
        "/v1/inboxes",
        Some(json!({"local": "a/b"})),
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = call(
        &app(vec![mailbox()]),
        "POST",
        "/v1/inboxes",
        Some(json!({"bogus": 1})),
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn quarantine_can_be_cleared() {
    let (a, state) = app_with(vec![mailbox()], |_| {});
    state.service.il.health().quarantine("fake", "drift");
    let (_, v) = call(
        &a,
        "DELETE",
        "/v1/providers/fake/quarantine",
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(v["data"]["cleared"], true);
    let (s, _) = call(
        &a,
        "DELETE",
        "/v1/providers/nope/quarantine",
        None,
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rate_limit_buckets_by_valid_key() {
    let (a, _) = app_with(vec![], |c| c.rate_limit = (2, Duration::from_secs(60)));
    for _ in 0..2 {
        assert_eq!(
            call(&a, "GET", "/v1/providers", None, Some("k1")).await.0,
            StatusCode::OK
        );
    }
    let (s, v) = call(&a, "GET", "/v1/providers", None, Some("k1")).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v["error"], "rate limit exceeded");
    // Another valid key has its own budget.
    assert_eq!(
        call(&a, "GET", "/v1/providers", None, Some("k2")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn webhook_to_private_host_is_refused_with_reason() {
    let a = app(vec![mailbox()]);
    let (_, v) = call(&a, "POST", "/v1/inboxes", None, Some("k1")).await;
    let addr = v["data"]["address"].as_str().unwrap().to_string();
    let (s, v) = call(
        &a,
        "POST",
        "/v1/webhooks",
        Some(json!({"address": addr, "url": "http://127.0.0.1/x"})),
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(v["error"].as_str().unwrap().contains("private"));
    let (s, _) = call(
        &a,
        "POST",
        "/v1/webhooks",
        Some(json!({"address": "nobody@x.test", "url": "https://example.com"})),
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webhook_delivers_signed_payload() {
    use axum::extract::State as AxState;
    use axum::http::HeaderMap;
    // A receiver on loopback; private targets allowed for this test only.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(HeaderMap, Value)>(1);
    let receiver = Router::new()
        .route(
            "/hook",
            post(
                |AxState(tx): AxState<tokio::sync::mpsc::Sender<(HeaderMap, Value)>>,
                 h: HeaderMap,
                 Json(v): Json<Value>| async move {
                    tx.send((h, v)).await.unwrap();
                    "ok"
                },
            ),
        )
        .with_state(tx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, receiver).await.unwrap() });

    let (a, _) = app_with(vec![mailbox()], |c| {
        c.webhook_allow_private = true;
        c.webhook_secret = Some("shh".into());
    });
    let (_, v) = call(&a, "POST", "/v1/inboxes", None, Some("k1")).await;
    let addr = v["data"]["address"].as_str().unwrap().to_string();
    let (s, v) = call(
        &a,
        "POST",
        "/v1/webhooks",
        Some(
            json!({"address": addr, "url": format!("http://127.0.0.1:{port}/hook"), "timeout": 5}),
        ),
        Some("k1"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (headers, payload) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payload["event"], "message");
    assert_eq!(payload["id"], "m1");
    let sig = headers
        .get(webhooks::SIGNATURE_HEADER)
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(
        sig,
        webhooks::sign("shh", serde_json::to_vec(&payload).unwrap().as_slice())
    );
}

#[tokio::test]
async fn sse_streams_messages() {
    let a = app(vec![mailbox()]);
    let (_, v) = call(&a, "POST", "/v1/inboxes", None, Some("k1")).await;
    let addr = v["data"]["address"].as_str().unwrap().to_string();
    let req = Req::get(format!("/v1/inboxes/{addr}/events"))
        .header("x-api-key", "k1")
        .body(Body::empty())
        .unwrap();
    let resp = a.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body().into_data_stream();
    let mut seen = String::new();
    while !seen.contains("771204") {
        let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        seen.push_str(&String::from_utf8_lossy(&chunk));
    }
    assert!(seen.contains("event: message"));
}

#[tokio::test]
async fn unknown_route_is_enveloped_404() {
    let (s, v) = call(&app(vec![]), "GET", "/nope", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["success"], false);
}

#[tokio::test]
async fn serve_refuses_without_keys() {
    let il = Interloper::with_registry(Registry::new([], Arc::new(HealthStore::new())));
    assert!(
        serve(Config::default(), il)
            .await
            .unwrap_err()
            .contains("refusing")
    );
}
