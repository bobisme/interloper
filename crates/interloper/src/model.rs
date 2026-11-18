//! The nouns: what a provider can do, the address it issues, and the mail
//! that arrives there.

use std::fmt;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    GmailAlias,
    OutlookAlias,
    OwnDomain,
    Edu,
}

impl Kind {
    pub const ALL: [Kind; 4] = [
        Kind::GmailAlias,
        Kind::OutlookAlias,
        Kind::OwnDomain,
        Kind::Edu,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::GmailAlias => "gmail-alias",
            Kind::OutlookAlias => "outlook-alias",
            Kind::OwnDomain => "own-domain",
            Kind::Edu => "edu",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Kind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Kind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| Error::unsupported(format!("unknown kind {s:?}")))
    }
}

/// What a backend can do. Declared once per provider as a `const`.
///
/// Start from [`Capabilities::DEFAULT`] and override what differs, so a new
/// field never forces an edit to every adapter.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub kind: &'static [Kind],
    /// Front doors: the sites a human would recognise. Never called.
    pub sites: &'static [&'static str],
    /// Domains known up front. Empty means discovered at generate time.
    pub domains: &'static [&'static str],
    pub domain_count: usize,
    /// How long an address lives. `None` is forever.
    pub address_ttl: Option<Duration>,
    /// How long a received message is retained. `None` is forever/unknown.
    pub message_ttl: Option<Duration>,
    pub push: bool,
    pub delete: bool,
    pub custom_local: bool,
    pub self_hosted: bool,
    pub needs_residential_ip: bool,
    /// `generate()` issues credentials or a session that later calls need. A
    /// caller resuming the address elsewhere must carry `Address::state`.
    pub needs_state: bool,
    /// The backend's tolerance. Held across every request to it, so no amount
    /// of caller concurrency can exceed it.
    pub max_concurrency: usize,
    /// Polling cadence for `watch()`.
    pub poll_interval: Duration,
    /// The backend keys inboxes on a session cookie: run each request on a
    /// throwaway session and replay identity from `Address::state`.
    pub fresh_session: bool,
    /// Unusable without a Cloudflare solver; skipped when none is configured.
    pub needs_solver: bool,
}

pub const fn hours(h: u64) -> Duration {
    Duration::from_secs(h * 3600)
}

pub const fn days(d: u64) -> Duration {
    Duration::from_secs(d * 86_400)
}

pub const fn minutes(m: u64) -> Duration {
    Duration::from_secs(m * 60)
}

impl Capabilities {
    pub const DEFAULT: Capabilities = Capabilities {
        kind: &[Kind::OwnDomain],
        sites: &[],
        domains: &[],
        domain_count: 1,
        address_ttl: None,
        message_ttl: None,
        push: false,
        delete: false,
        custom_local: false,
        self_hosted: false,
        needs_residential_ip: false,
        needs_state: false,
        max_concurrency: 4,
        poll_interval: Duration::from_secs(5),
        fresh_session: false,
        needs_solver: false,
    };

    pub fn serves(&self, kind: Kind) -> bool {
        self.kind.contains(&kind)
    }
}

/// One issued address, bound to the provider that issued it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub value: String,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Opaque per-provider state. Core never inspects or logs it; only the
    /// issuing provider reads it back. Treat it as a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

const TOKEN_PREFIX: &str = "ilp1.";

impl Address {
    pub fn new(value: impl Into<String>, provider: impl Into<String>) -> Self {
        Address {
            value: value.into(),
            provider: provider.into(),
            expires_at: None,
            state: None,
        }
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn expiring(mut self, ttl: Option<Duration>) -> Self {
        self.expires_at = ttl.and_then(|d| {
            Timestamp::now()
                .checked_add(jiff::SignedDuration::try_from(d).ok()?)
                .ok()
        });
        self
    }

    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }

    pub fn local(&self) -> &str {
        self.value.rsplit_once('@').map_or(&self.value, |(l, _)| l)
    }

    pub fn domain(&self) -> &str {
        self.value.rsplit_once('@').map_or("", |(_, d)| d)
    }

    /// One self-contained, copy-pasteable handle for this inbox: address,
    /// provider, expiry and provider state together. cowbird made a second
    /// process carry three values (`ADDRESS --provider P --state S`); this is
    /// one. It contains the state, so it is a credential.
    pub fn to_token(&self) -> String {
        let json = serde_json::to_vec(self).expect("Address always serializes");
        format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json))
    }

    pub fn from_token(token: &str) -> Result<Self> {
        let body = token
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| Error::InvalidToken(format!("missing {TOKEN_PREFIX} prefix")))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|e| Error::InvalidToken(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| Error::InvalidToken(e.to_string()))
    }

    pub fn looks_like_token(s: &str) -> bool {
        s.trim().starts_with(TOKEN_PREFIX)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address")
            .field("value", &self.value)
            .field("provider", &self.provider)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// A row in an inbox listing: headers only, no body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageRow {
    pub id: String,
    pub sender: String,
    pub subject: String,
    pub received_at: Option<Timestamp>,
    #[serde(default)]
    pub locked: bool,
}

impl MessageRow {
    pub fn new(
        id: impl Into<String>,
        sender: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        MessageRow {
            id: id.into(),
            sender: sender.into(),
            subject: subject.into(),
            received_at: None,
            locked: false,
        }
    }

    pub fn at(mut self, at: Option<Timestamp>) -> Self {
        self.received_at = at;
        self
    }
}

/// A full message. `text` is always populated: adapters that only get HTML
/// derive it, so extraction never has to care which one a backend served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub sender: String,
    pub subject: String,
    pub received_at: Option<Timestamp>,
    pub html: String,
    pub text: String,
    pub links: Vec<String>,
}

impl Message {
    /// Build a message from whichever bodies the backend served, deriving the
    /// text and links from the HTML. A blank `text` falls back to the HTML.
    pub fn from_bodies(
        id: impl Into<String>,
        sender: impl Into<String>,
        subject: impl Into<String>,
        received_at: Option<Timestamp>,
        html: impl Into<String>,
        text: Option<String>,
    ) -> Self {
        let html = html.into();
        let text = match text {
            Some(t) if !t.trim().is_empty() => t,
            _ => crate::parse::html_to_text(&html),
        };
        let mut links = crate::parse::extract_links(&html);
        if links.is_empty() {
            links = crate::parse::extract_text_links(&text);
        }
        Message {
            id: id.into(),
            sender: sender.into(),
            subject: subject.into(),
            received_at,
            html,
            text,
            links,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips_and_carries_state() {
        let a = Address::new("x@y.test", "mailtm").with_state(r#"{"token":"t"}"#);
        let token = a.to_token();
        assert!(token.starts_with("ilp1."));
        assert_eq!(Address::from_token(&token).unwrap(), a);
    }

    #[test]
    fn token_rejects_garbage() {
        assert!(Address::from_token("nope").is_err());
        assert!(Address::from_token("ilp1.!!!").is_err());
        assert!(Address::from_token("ilp1.e30").is_err()); // "{}" lacks fields
    }

    #[test]
    fn debug_never_prints_state() {
        let a = Address::new("x@y.test", "p").with_state("secret-password");
        assert!(!format!("{a:?}").contains("secret"));
    }

    #[test]
    fn kind_round_trips_through_strings() {
        for k in Kind::ALL {
            assert_eq!(k.as_str().parse::<Kind>().unwrap(), k);
        }
    }
}
