//! Every failure interloper can report, and what each one means for routing.
//!
//! cowbird decided reroutability with a class attribute that defaulted to
//! `False`, so a new error type silently opted out of rerouting. Here the
//! decision is a `match` with no wildcard: adding a variant does not compile
//! until someone says what it means for routing and for health.

use std::time::Duration;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Network failure, 5xx, timeout, or a status the adapter did not expect.
    #[error("{provider}: down: {detail}")]
    ProviderDown { provider: String, detail: String },

    /// An anti-bot interstitial was served instead of a response. Usually the
    /// egress IP is wrong rather than the provider being broken, so health
    /// records it as a hint that a residential IP is needed.
    #[error("{provider}: anti-bot challenge (HTTP {status})")]
    Challenge { provider: String, status: u16 },

    /// The Cloudflare solver failed. Not the provider's fault: reroutes, but
    /// never counts against the provider's health.
    #[error("solver: {0}")]
    SolverUnavailable(String),

    #[error("{provider}: rate limited")]
    RateLimited {
        provider: String,
        retry_after: Option<Duration>,
    },

    /// The response parsed, but its shape is not what this adapter knows. This
    /// is how these services break in practice, so it is loud, carries both
    /// halves of the mismatch, and quarantines the provider.
    #[error("{provider}: schema drift: expected {expected}, got {got}")]
    SchemaDrift {
        provider: String,
        expected: String,
        got: String,
    },

    /// The message exists but is behind the provider's paywall.
    #[error("{provider}: message {id} is locked")]
    MessageLocked { provider: String, id: String },

    /// The message existed and the backend no longer has it. An answer about
    /// one message, not about the provider.
    #[error("{provider}: message {id} is gone")]
    MessageGone { provider: String, id: String },

    /// The provider does not have the requested capability, or the request
    /// itself is unusable (a bad local part, an unserved domain).
    #[error("not supported: {0}")]
    NotSupported(String),

    #[error("address expired: {0}")]
    AddressExpired(String),

    #[error("no provider available (tried: {}){}", fmt_tried(.tried), fmt_last(.last))]
    NoProviderAvailable {
        tried: Vec<String>,
        last: Option<Box<Error>>,
    },

    #[error("timeout: {0}")]
    Timeout(String),

    /// A token handed to `resume` could not be decoded.
    #[error("invalid inbox token: {0}")]
    InvalidToken(String),
}

fn fmt_tried(tried: &[String]) -> String {
    if tried.is_empty() {
        "none".into()
    } else {
        tried.join(", ")
    }
}

fn fmt_last(last: &Option<Box<Error>>) -> String {
    match last {
        Some(e) => format!("; last error: {e}"),
        None => String::new(),
    }
}

/// What an error teaches the health store about the provider that raised it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthEffect {
    /// The provider is at fault; count it as a failure.
    Failure,
    /// The adapter no longer matches the backend; quarantine.
    Drift,
    /// Nothing is learned about the provider either way.
    Neutral,
}

impl Error {
    /// Whether the pool should try another provider after this error.
    pub fn reroutable(&self) -> bool {
        match self {
            Error::ProviderDown { .. }
            | Error::Challenge { .. }
            | Error::SolverUnavailable(_)
            | Error::RateLimited { .. }
            | Error::SchemaDrift { .. } => true,
            Error::MessageLocked { .. }
            | Error::MessageGone { .. }
            | Error::NotSupported(_)
            | Error::AddressExpired(_)
            | Error::NoProviderAvailable { .. }
            | Error::Timeout(_)
            | Error::InvalidToken(_) => false,
        }
    }

    pub fn health_effect(&self) -> HealthEffect {
        match self {
            Error::SchemaDrift { .. } => HealthEffect::Drift,
            Error::ProviderDown { .. } | Error::Challenge { .. } | Error::RateLimited { .. } => {
                HealthEffect::Failure
            }
            // A solver failure reroutes but is not the provider's fault. The
            // rest are correct answers to the caller's specific request.
            Error::SolverUnavailable(_)
            | Error::MessageLocked { .. }
            | Error::MessageGone { .. }
            | Error::NotSupported(_)
            | Error::AddressExpired(_)
            | Error::NoProviderAvailable { .. }
            | Error::Timeout(_)
            | Error::InvalidToken(_) => HealthEffect::Neutral,
        }
    }

    /// A stable snake_case name for this kind of failure, for scripts and
    /// agents. These strings are an interface: never rename one.
    pub fn code(&self) -> &'static str {
        match self {
            Error::ProviderDown { .. } => "provider_down",
            Error::Challenge { .. } => "challenge",
            Error::SolverUnavailable(_) => "solver_unavailable",
            Error::RateLimited { .. } => "rate_limited",
            Error::SchemaDrift { .. } => "schema_drift",
            Error::MessageLocked { .. } => "message_locked",
            Error::MessageGone { .. } => "message_gone",
            Error::NotSupported(_) => "not_supported",
            Error::AddressExpired(_) => "address_expired",
            Error::NoProviderAvailable { .. } => "no_provider",
            Error::Timeout(_) => "timeout",
            Error::InvalidToken(_) => "invalid_token",
        }
    }

    /// Whether running the same operation again later can succeed without the
    /// caller changing anything. Distinct from [`Error::reroutable`], which is
    /// about trying a *different* provider right now.
    pub fn retryable(&self) -> bool {
        match self {
            Error::ProviderDown { .. }
            | Error::Challenge { .. }
            | Error::SolverUnavailable(_)
            | Error::RateLimited { .. }
            | Error::Timeout(_) => true,
            // Nothing was eligible, or every candidate failed. Retryable unless
            // the last failure was itself a final answer.
            Error::NoProviderAvailable { last, .. } => last.as_ref().is_none_or(|e| e.retryable()),
            Error::SchemaDrift { .. }
            | Error::MessageLocked { .. }
            | Error::MessageGone { .. }
            | Error::NotSupported(_)
            | Error::AddressExpired(_)
            | Error::InvalidToken(_) => false,
        }
    }

    /// How long the provider asked the caller to wait, when it said.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Error::RateLimited { retry_after, .. } => *retry_after,
            Error::NoProviderAvailable { last: Some(e), .. } => e.retry_after(),
            _ => None,
        }
    }

    pub fn down(provider: impl Into<String>, detail: impl std::fmt::Display) -> Self {
        Error::ProviderDown {
            provider: provider.into(),
            detail: detail.to_string(),
        }
    }

    /// Schema drift. `got` is rendered with `Debug` and clipped so a whole HTML
    /// page never ends up in a quarantine reason.
    pub fn drift(
        provider: impl Into<String>,
        expected: impl Into<String>,
        got: impl std::fmt::Debug,
    ) -> Self {
        Error::SchemaDrift {
            provider: provider.into(),
            expected: expected.into(),
            got: clip(&format!("{got:?}"), 240),
        }
    }

    pub fn gone(provider: impl Into<String>, id: impl Into<String>) -> Self {
        Error::MessageGone {
            provider: provider.into(),
            id: id.into(),
        }
    }

    pub fn unsupported(detail: impl Into<String>) -> Self {
        Error::NotSupported(detail.into())
    }
}

pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_about_one_message_do_not_reroute_or_hurt_health() {
        for e in [
            Error::gone("p", "1"),
            Error::MessageLocked {
                provider: "p".into(),
                id: "1".into(),
            },
            Error::unsupported("x"),
        ] {
            assert!(!e.reroutable(), "{e}");
            assert_eq!(e.health_effect(), HealthEffect::Neutral, "{e}");
        }
    }

    #[test]
    fn solver_failure_reroutes_without_blaming_the_provider() {
        let e = Error::SolverUnavailable("refused".into());
        assert!(e.reroutable());
        assert_eq!(e.health_effect(), HealthEffect::Neutral);
    }

    #[test]
    fn drift_quarantines_and_clips() {
        let e = Error::drift("p", "a list", "x".repeat(10_000));
        assert_eq!(e.health_effect(), HealthEffect::Drift);
        assert!(e.to_string().len() < 400);
    }

    #[test]
    fn codes_and_retryability() {
        let limited = Error::RateLimited {
            provider: "p".into(),
            retry_after: Some(Duration::from_secs(7)),
        };
        assert_eq!(limited.code(), "rate_limited");
        assert!(limited.retryable());
        let none = Error::NoProviderAvailable {
            tried: vec!["p".into()],
            last: Some(Box::new(limited)),
        };
        assert_eq!(none.code(), "no_provider");
        assert!(none.retryable());
        assert_eq!(none.retry_after(), Some(Duration::from_secs(7)));
        let unknown = Error::NoProviderAvailable {
            tried: vec!["nope".into()],
            last: Some(Box::new(Error::unsupported("unknown provider"))),
        };
        assert!(!unknown.retryable());
        assert!(!Error::InvalidToken("x".into()).retryable());
    }

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("ééé", 3), "é…");
    }
}
