//! How the CLI reports failure: one stable error code, an exit code derived
//! from it, a retry verdict, and a hint that says what to do next.
//!
//! [`ERROR_CODES`] and [`EXIT_CODES`] are the single source of truth: the exit
//! status is looked up from the table, and `--help`, `guide` and the tests all
//! read the same tables, so the documentation cannot drift from behavior.

use std::time::Duration;

use interloper::Error;
use serde_json::{Value, json};

use crate::suggest;

pub struct ExitInfo {
    pub code: u8,
    pub name: &'static str,
    pub meaning: &'static str,
}

pub const EXIT_OK: u8 = 0;
pub const EXIT_ERROR: u8 = 1;
pub const EXIT_TIMEOUT: u8 = 2;
pub const EXIT_USAGE: u8 = 3;
pub const EXIT_UNAVAILABLE: u8 = 4;
pub const EXIT_INBOX: u8 = 5;
pub const EXIT_MESSAGE: u8 = 6;

pub const EXIT_CODES: &[ExitInfo] = &[
    ExitInfo {
        code: EXIT_OK,
        name: "ok",
        meaning: "Success; stdout holds the result.",
    },
    ExitInfo {
        code: EXIT_ERROR,
        name: "error",
        meaning: "Anything else: schema drift (an adapter no longer matches its backend), an internal or I/O failure, or a canary run that found drift.",
    },
    ExitInfo {
        code: EXIT_TIMEOUT,
        name: "timeout",
        meaning: "Nothing matching arrived before --timeout. Retry the same command, ideally with a longer --timeout.",
    },
    ExitInfo {
        code: EXIT_USAGE,
        name: "usage",
        meaning: "The command cannot work as written: bad flag value, unknown provider or kind, bad --pattern, or an option combination no provider supports. Fix the command; never retry it unchanged.",
    },
    ExitInfo {
        code: EXIT_UNAVAILABLE,
        name: "unavailable",
        meaning: "Upstream could not serve the request right now (provider down, rate limited, challenged, solver failed, no provider available). Usually retryable; the JSON `retryable` field is authoritative.",
    },
    ExitInfo {
        code: EXIT_INBOX,
        name: "inbox",
        meaning: "The address expired or the token is invalid. Run `interloper new` for a fresh address.",
    },
    ExitInfo {
        code: EXIT_MESSAGE,
        name: "message",
        meaning: "That message is gone or locked. List the inbox again and pick another id.",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    Yes,
    No,
    /// Decided per occurrence; read the JSON `retryable` field.
    Depends,
}

impl Retry {
    pub fn as_str(self) -> &'static str {
        match self {
            Retry::Yes => "yes",
            Retry::No => "no",
            Retry::Depends => "depends",
        }
    }
}

pub struct CodeInfo {
    pub code: &'static str,
    pub exit: u8,
    pub retry: Retry,
    pub meaning: &'static str,
}

/// Every error code the CLI can emit. The core library's codes come first
/// (see `interloper::Error::code`), then the CLI's own.
pub const ERROR_CODES: &[CodeInfo] = &[
    CodeInfo {
        code: "provider_down",
        exit: EXIT_UNAVAILABLE,
        retry: Retry::Yes,
        meaning: "Network failure, 5xx or unexpected status from the provider.",
    },
    CodeInfo {
        code: "challenge",
        exit: EXIT_UNAVAILABLE,
        retry: Retry::Yes,
        meaning: "Anti-bot interstitial; the egress IP is likely flagged. Try another provider or INTERLOPER_PROXY.",
    },
    CodeInfo {
        code: "solver_unavailable",
        exit: EXIT_UNAVAILABLE,
        retry: Retry::Yes,
        meaning: "The Cloudflare solver (INTERLOPER_SOLVER_URL) failed or is not configured.",
    },
    CodeInfo {
        code: "rate_limited",
        exit: EXIT_UNAVAILABLE,
        retry: Retry::Yes,
        meaning: "The provider throttled us. Wait retry_after_seconds when present.",
    },
    CodeInfo {
        code: "schema_drift",
        exit: EXIT_ERROR,
        retry: Retry::No,
        meaning: "The provider changed its API; the adapter is quarantined. Use another provider.",
    },
    CodeInfo {
        code: "message_locked",
        exit: EXIT_MESSAGE,
        retry: Retry::No,
        meaning: "The message is behind the provider's paywall.",
    },
    CodeInfo {
        code: "message_gone",
        exit: EXIT_MESSAGE,
        retry: Retry::No,
        meaning: "The message existed and the provider no longer has it.",
    },
    CodeInfo {
        code: "not_supported",
        exit: EXIT_USAGE,
        retry: Retry::No,
        meaning: "The provider cannot do what was asked (custom local part, domain, kind, TTL, bare address).",
    },
    CodeInfo {
        code: "address_expired",
        exit: EXIT_INBOX,
        retry: Retry::No,
        meaning: "The address has expired. Run `interloper new`.",
    },
    CodeInfo {
        code: "no_provider",
        exit: EXIT_UNAVAILABLE,
        retry: Retry::Depends,
        meaning: "Every eligible provider failed or is cooling down. Retryable unless the last failure was final.",
    },
    CodeInfo {
        code: "timeout",
        exit: EXIT_TIMEOUT,
        retry: Retry::Yes,
        meaning: "Nothing matching arrived in time.",
    },
    CodeInfo {
        code: "invalid_token",
        exit: EXIT_INBOX,
        retry: Retry::No,
        meaning: "TARGET is not a decodable ilp1.… token.",
    },
    CodeInfo {
        code: "usage",
        exit: EXIT_USAGE,
        retry: Retry::No,
        meaning: "Bad command line: unknown flag, bad value, bad --pattern, missing argument.",
    },
    CodeInfo {
        code: "unknown_provider",
        exit: EXIT_USAGE,
        retry: Retry::No,
        meaning: "No provider by that name; see `did_you_mean` and `interloper providers`.",
    },
    CodeInfo {
        code: "config",
        exit: EXIT_USAGE,
        retry: Retry::No,
        meaning: "An INTERLOPER_* environment variable is invalid.",
    },
    CodeInfo {
        code: "internal",
        exit: EXIT_ERROR,
        retry: Retry::No,
        meaning: "An unexpected failure (I/O, server startup).",
    },
];

pub fn code_info(code: &str) -> Option<&'static CodeInfo> {
    ERROR_CODES.iter().find(|c| c.code == code)
}

/// One failure, ready to print.
#[derive(Debug, Clone)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub hint: String,
    pub retryable: bool,
    pub retry_after: Option<Duration>,
    /// Providers attempted, for `no_provider`.
    pub tried: Box<[String]>,
    /// The likely intended value, for misspellings.
    pub did_you_mean: Option<Box<str>>,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>, hint: impl Into<String>) -> Self {
        let retryable = code_info(code).is_some_and(|c| c.retry == Retry::Yes);
        Failure {
            code,
            message: message.into(),
            hint: hint.into(),
            retryable,
            retry_after: None,
            tried: Box::default(),
            did_you_mean: None,
        }
    }

    pub fn usage(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Failure::new("usage", message, hint)
    }

    pub fn not_supported(message: impl Into<String>, hint: impl Into<String>) -> Self {
        Failure::new("not_supported", message, hint)
    }

    pub fn config(message: impl Into<String>) -> Self {
        Failure::new(
            "config",
            message,
            "fix the INTERLOPER_* variable named in the message; `interloper guide` lists them",
        )
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Failure::new(
            "internal",
            message,
            "rerun with -v for details; report it if it persists",
        )
    }

    /// `name` is not a provider. Suggests the closest known one.
    pub fn unknown_provider<'a>(name: &str, known: impl IntoIterator<Item = &'a str>) -> Self {
        let guess = suggest::closest(name, known).map(str::to_string);
        let hint = match &guess {
            Some(g) => format!(
                "did you mean {g:?}? `interloper providers` lists every provider and its health"
            ),
            None => "`interloper providers` lists every provider and its health".into(),
        };
        let mut f = Failure::new(
            "unknown_provider",
            format!("unknown provider {name:?}"),
            hint,
        );
        f.did_you_mean = guess.map(Into::into);
        f
    }

    /// A clap parse error, as a `usage` failure.
    pub fn from_clap(e: &clap::Error) -> Self {
        use clap::error::{ContextKind, ContextValue};
        let rendered = e.render().to_string();
        let message = rendered
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("bad command line")
            .trim()
            .trim_start_matches("error: ")
            .to_string();
        let mut guess = None;
        let mut hint = String::new();
        for kind in [
            ContextKind::SuggestedValue,
            ContextKind::SuggestedArg,
            ContextKind::SuggestedSubcommand,
        ] {
            match e.get(kind) {
                Some(ContextValue::String(s)) => guess = Some(s.clone()),
                // clap orders suggestions by ascending confidence.
                Some(ContextValue::Strings(v)) if !v.is_empty() => guess = v.last().cloned(),
                _ => {}
            }
        }
        if let Some(g) = &guess {
            hint.push_str(&format!("did you mean {g:?}? "));
        }
        if let Some(ContextValue::Strings(valid)) = e.get(ContextKind::ValidValue) {
            hint.push_str(&format!("valid values: {}. ", valid.join(", ")));
        }
        hint.push_str("Run `interloper --help` or `interloper guide`.");
        let mut f = Failure::usage(message, hint);
        f.did_you_mean = guess.map(Into::into);
        f
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = hint.into();
        self
    }

    pub fn exit_code(&self) -> u8 {
        code_info(self.code).map_or(EXIT_ERROR, |c| c.exit)
    }

    pub fn to_json(&self) -> Value {
        let mut e = json!({
            "code": self.code,
            "retryable": self.retryable,
            "message": self.message,
            "hint": self.hint,
        });
        let obj = e.as_object_mut().expect("object");
        if let Some(d) = self.retry_after {
            obj.insert("retry_after_seconds".into(), json!(d.as_secs_f64().ceil()));
        }
        if !self.tried.is_empty() {
            obj.insert("tried".into(), json!(self.tried));
        }
        if let Some(g) = &self.did_you_mean {
            obj.insert("did_you_mean".into(), json!(g));
        }
        json!({ "error": e })
    }

    pub fn render_plain(&self) -> String {
        let mut s = format!("error[{}]: {}", self.code, self.message);
        if let Some(d) = self.retry_after {
            s.push_str(&format!(" (retry after {}s)", d.as_secs_f64().ceil()));
        }
        if !self.hint.is_empty() {
            s.push_str(&format!("\n  hint: {}", self.hint));
        }
        s
    }
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        let hint = default_hint(&e);
        let mut f = Failure::new(e.code(), e.to_string(), hint);
        f.retryable = e.retryable();
        f.retry_after = e.retry_after();
        if let Error::NoProviderAvailable { tried, .. } = &e {
            f.tried = tried.clone().into();
        }
        f
    }
}

fn default_hint(e: &Error) -> String {
    match e {
        Error::ProviderDown { .. } => {
            "the provider failed or did not answer; retry, or omit --provider so the pool can pick another".into()
        }
        Error::Challenge { .. } => {
            "the provider served an anti-bot page, usually because the egress IP is flagged; use another provider or set INTERLOPER_PROXY to a residential proxy".into()
        }
        Error::SolverUnavailable(_) => {
            "check that the cloudflare-solver at INTERLOPER_SOLVER_URL is running and reachable".into()
        }
        Error::RateLimited { .. } => {
            "wait retry_after_seconds when given (else ~30s) and retry, or omit --provider".into()
        }
        Error::SchemaDrift { provider, .. } => format!(
            "{provider} changed its API and is quarantined; use another provider. After an adapter fix: `interloper health clear {provider}`"
        ),
        Error::MessageLocked { .. } => {
            "the provider keeps this message behind a paywall; it cannot be read here".into()
        }
        Error::MessageGone { .. } => {
            "list the inbox again with `interloper read TARGET` and pick a current id".into()
        }
        Error::NotSupported(_) => {
            "`interloper providers --json` shows what each provider supports (kind, custom_local, address_ttl)".into()
        }
        Error::AddressExpired(_) => "run `interloper new` for a fresh address".into(),
        Error::NoProviderAvailable { tried, .. } => no_provider_hint(tried),
        Error::Timeout(_) => {
            "nothing matched in time; retry with a longer --timeout, loosen --from/--subject, or check the address was submitted".into()
        }
        Error::InvalidToken(_) => {
            "pass the whole ilp1.… token printed by `interloper new` (quote it in the shell), or `-` to read it from stdin".into()
        }
    }
}

pub fn no_provider_hint(tried: &[String]) -> String {
    if tried.is_empty() {
        "no provider was eligible: every one matching these constraints is cooling down after recent failures. Retry in a minute, relax the constraints, or check `interloper providers`".into()
    } else {
        format!(
            "tried {} and all failed; retry later, or check `interloper providers` for health",
            tried.join(", ")
        )
    }
}

/// Print a failure to stderr in the mode in effect.
pub fn report(f: &Failure, json: bool) {
    if json {
        eprintln!("{}", f.to_json());
    } else {
        eprintln!("{}", f.render_plain());
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One of every core variant. `variant_index` has no wildcard, so a new
    /// variant breaks this build until it is added here and to ERROR_CODES.
    pub fn core_samples() -> Vec<Error> {
        let samples = vec![
            Error::down("p", "502"),
            Error::Challenge {
                provider: "p".into(),
                status: 403,
            },
            Error::SolverUnavailable("refused".into()),
            Error::RateLimited {
                provider: "p".into(),
                retry_after: Some(Duration::from_millis(2500)),
            },
            Error::drift("p", "a list", "{}"),
            Error::MessageLocked {
                provider: "p".into(),
                id: "1".into(),
            },
            Error::gone("p", "1"),
            Error::unsupported("x"),
            Error::AddressExpired("a@b".into()),
            Error::NoProviderAvailable {
                tried: vec!["a".into(), "b".into()],
                last: Some(Box::new(Error::down("b", "502"))),
            },
            Error::Timeout("nothing".into()),
            Error::InvalidToken("bad".into()),
        ];
        let mut seen: Vec<usize> = samples.iter().map(variant_index).collect();
        seen.sort();
        assert_eq!(seen, (0..12).collect::<Vec<_>>(), "one sample per variant");
        samples
    }

    fn variant_index(e: &Error) -> usize {
        match e {
            Error::ProviderDown { .. } => 0,
            Error::Challenge { .. } => 1,
            Error::SolverUnavailable(_) => 2,
            Error::RateLimited { .. } => 3,
            Error::SchemaDrift { .. } => 4,
            Error::MessageLocked { .. } => 5,
            Error::MessageGone { .. } => 6,
            Error::NotSupported(_) => 7,
            Error::AddressExpired(_) => 8,
            Error::NoProviderAvailable { .. } => 9,
            Error::Timeout(_) => 10,
            Error::InvalidToken(_) => 11,
        }
    }

    #[test]
    fn every_core_code_is_tabled_and_its_retry_verdict_matches() {
        for e in core_samples() {
            let info = code_info(e.code()).unwrap_or_else(|| panic!("{} not tabled", e.code()));
            match info.retry {
                Retry::Yes => assert!(e.retryable(), "{}", e.code()),
                Retry::No => assert!(!e.retryable(), "{}", e.code()),
                Retry::Depends => {}
            }
            let f = Failure::from(e);
            assert_eq!(f.exit_code(), info.exit);
            assert!(!f.hint.is_empty(), "{} has no hint", f.code);
        }
    }

    #[test]
    fn codes_are_unique_snake_case_and_exits_documented() {
        let mut codes: Vec<_> = ERROR_CODES.iter().map(|c| c.code).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), ERROR_CODES.len());
        for c in ERROR_CODES {
            assert!(
                c.code
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "{}",
                c.code
            );
            assert!(EXIT_CODES.iter().any(|x| x.code == c.exit), "{}", c.code);
        }
    }

    #[test]
    fn exit_code_mapping() {
        let exit = |e: Error| Failure::from(e).exit_code();
        assert_eq!(exit(Error::Timeout("t".into())), 2);
        assert_eq!(exit(Error::unsupported("x")), 3);
        assert_eq!(exit(Error::down("p", "x")), 4);
        assert_eq!(
            exit(Error::NoProviderAvailable {
                tried: vec![],
                last: None
            }),
            4
        );
        assert_eq!(exit(Error::AddressExpired("a".into())), 5);
        assert_eq!(exit(Error::InvalidToken("a".into())), 5);
        assert_eq!(exit(Error::gone("p", "1")), 6);
        assert_eq!(exit(Error::drift("p", "x", "y")), 1);
        assert_eq!(Failure::usage("x", "y").exit_code(), 3);
        assert_eq!(Failure::unknown_provider("x", ["y"]).exit_code(), 3);
        assert_eq!(Failure::internal("x").exit_code(), 1);
    }

    #[test]
    fn json_shape() {
        let e = Error::NoProviderAvailable {
            tried: vec!["a".into()],
            last: Some(Box::new(Error::RateLimited {
                provider: "a".into(),
                retry_after: Some(Duration::from_millis(2500)),
            })),
        };
        let v = Failure::from(e).to_json();
        let err = v["error"].as_object().unwrap();
        assert_eq!(v.as_object().unwrap().len(), 1, "only the error key");
        assert_eq!(err["code"], "no_provider");
        assert_eq!(err["retryable"], true);
        assert!(err["message"].as_str().unwrap().contains("tried: a"));
        assert!(
            err["hint"]
                .as_str()
                .unwrap()
                .contains("interloper providers")
        );
        assert_eq!(err["retry_after_seconds"], 3.0);
        assert_eq!(err["tried"], json!(["a"]));

        let v = Failure::from(Error::InvalidToken("x".into())).to_json();
        let keys: Vec<_> = v["error"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["code", "hint", "message", "retryable"]);
        assert_eq!(v["error"]["retryable"], false);
    }

    #[test]
    fn unknown_provider_suggests() {
        let f = Failure::unknown_provider("mailtn", ["mailtm", "duckmail"]);
        assert_eq!(f.code, "unknown_provider");
        assert_eq!(f.did_you_mean.as_deref(), Some("mailtm"));
        assert!(f.hint.contains("\"mailtm\""));
        assert_eq!(f.to_json()["error"]["did_you_mean"], "mailtm");
        assert!(!f.retryable);
    }

    #[test]
    fn plain_rendering_names_the_code() {
        let s = Failure::from(Error::Timeout("no mail".into())).render_plain();
        assert!(s.starts_with("error[timeout]: timeout: no mail"), "{s}");
        assert!(s.contains("hint:"));
    }
}
