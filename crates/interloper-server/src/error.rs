//! HTTP errors. Clients get a fixed message per kind; detail goes to the log.
//!
//! Library errors carry diagnostics meant for a maintainer: schema drift
//! renders the payload it got back from a third party. Putting that in a
//! response body would hand callers a slice of someone else's response.

use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use interloper::Error;

use crate::envelope_err;
use crate::store::StoreUnavailable;

#[derive(Debug)]
pub enum ApiError {
    Core(Error),
    UnknownAddress,
    Store(StoreUnavailable),
    BadRequest(String),
    Unauthorized,
    RateLimited,
    NotFound,
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError::Core(e)
    }
}

impl From<StoreUnavailable> for ApiError {
    fn from(e: StoreUnavailable) -> Self {
        ApiError::Store(e)
    }
}

pub fn status_for(e: &Error) -> (StatusCode, &'static str) {
    match e {
        Error::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "upstream rate limited"),
        Error::MessageLocked { .. } => (
            StatusCode::LOCKED,
            "the message is behind the provider's paywall",
        ),
        Error::MessageGone { .. } => (StatusCode::GONE, "that message is no longer available"),
        Error::NoProviderAvailable { .. } => (
            StatusCode::SERVICE_UNAVAILABLE,
            "no provider available for that request",
        ),
        Error::NotSupported(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "no provider supports that combination of options",
        ),
        Error::AddressExpired(_) => (StatusCode::GONE, "that address has expired"),
        Error::SolverUnavailable(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "cloudflare solver unavailable",
        ),
        Error::InvalidToken(_) => (StatusCode::UNPROCESSABLE_ENTITY, "invalid inbox token"),
        Error::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "timed out"),
        Error::ProviderDown { .. } | Error::Challenge { .. } | Error::SchemaDrift { .. } => {
            (StatusCode::BAD_GATEWAY, "upstream provider error")
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg, retry_after): (StatusCode, String, Option<&str>) = match &self {
            ApiError::Core(e) => {
                let (s, m) = status_for(e);
                tracing::warn!(status = s.as_u16(), error = %e, "request failed");
                (
                    s,
                    m.into(),
                    (s == StatusCode::TOO_MANY_REQUESTS).then_some("30"),
                )
            }
            ApiError::UnknownAddress => (StatusCode::NOT_FOUND, "unknown address".into(), None),
            ApiError::Store(e) => {
                tracing::warn!(error = %e.0, "store unavailable");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "address store unavailable".into(),
                    Some("5"),
                )
            }
            ApiError::BadRequest(m) => (StatusCode::UNPROCESSABLE_ENTITY, m.clone(), None),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "invalid or missing API key".into(),
                None,
            ),
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit exceeded".into(),
                Some("60"),
            ),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found".into(), None),
        };
        let mut resp = (status, Json(envelope_err(&msg))).into_response();
        if let Some(ra) = retry_after {
            resp.headers_mut()
                .insert("retry-after", HeaderValue::from_static(ra));
        }
        resp
    }
}
