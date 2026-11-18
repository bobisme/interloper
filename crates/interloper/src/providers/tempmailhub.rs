//! tempmailhub.org: real Gmail accounts, read server-side over IMAP.
//!
//! Each address is a whole Gmail account from a small recycled pool, and the
//! inboxes are shared: an address arrives already holding strangers' mail, and
//! generate() hands the same account back to repeat callers from one IP.
//! Callers must match on sender or subject, never take "the newest message".
//!
//! The web client lists by `email_id`; the same endpoint takes `{"email"}` too
//! and answers the same rows, so no state is carried. The rows hold the whole
//! body, so get() is a lookup in list(). There is no delete and no domain
//! choice.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://api.tempmailhub.org";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::GmailAlias],
    sites: &["tempmailhub.org"],
    domains: &["gmail.com"],
    domain_count: 1,
    // The site's terms say 15 minutes; not measured.
    address_ttl: Some(minutes(15)),
    // x-ratelimit-limit is 100 per window, and a listing is an IMAP fetch
    // that takes 5-10s (a stuck account hits nginx's 60s 504).
    max_concurrency: 1,
    poll_interval: Duration::from_secs(10),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "tempmailhub",
    caps: CAPS,
    build: |t| Arc::new(TempMailHub { http: t }),
};

pub struct TempMailHub {
    http: Transport,
}

fn sender(r: &J<'_>) -> String {
    let (address, name) = (r.s("senderEmail"), r.s("senderName"));
    match (name.is_empty(), address.is_empty()) {
        (false, false) => format!("{name} <{address}>"),
        (_, false) => address,
        _ => name,
    }
}

fn row(r: &J<'_>) -> Result<MessageRow> {
    Ok(MessageRow::new(id(r)?, sender(r), r.s("subject")).at(r.time("date")))
}

/// A row without a usable id is drift: get() could never find it again.
fn id(r: &J<'_>) -> Result<String> {
    let id = r.req_id("id")?;
    if id.is_empty() {
        return Err(r.drift("a non-empty 'id'"));
    }
    Ok(id)
}

impl TempMailHub {
    async fn rows(&self, a: &Address) -> Result<Value> {
        self.http
            .post(format!("{API}/emails/messages"))
            .json_body(&json!({"email": a.value}))
            .json()
            .await
    }
}

#[async_trait]
impl Provider for TempMailHub {
    fn name(&self) -> &str {
        "tempmailhub"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "tempmailhub picks both the local part and the domain",
            ));
        }
        let v = self.http.post(format!("{API}/emails")).json().await?;
        let j = J::new("tempmailhub", &v, "POST /emails");
        let email = j.at("email")?.str()?;
        if !email.contains('@') {
            return Err(j.at("email")?.drift("an email address"));
        }
        Ok(Address::new(email, "tempmailhub"))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.rows(a).await?;
        let j = J::new("tempmailhub", &v, "emails/messages");
        j.at("emails")?.items()?.iter().map(row).collect()
    }

    async fn get(&self, a: &Address, want: &str) -> Result<Message> {
        let v = self.rows(a).await?;
        let j = J::new("tempmailhub", &v, "emails/messages");
        for r in j.at("emails")?.items()? {
            if id(&r)? == want {
                return Ok(Message::from_bodies(
                    want,
                    sender(&r),
                    r.s("subject"),
                    r.time("date"),
                    r.s("body"),
                    None,
                ));
            }
        }
        Err(Error::gone("tempmailhub", want))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tempmailhub");
    const GENERATE: &str = "POST https://api.tempmailhub.org/emails?";
    const MESSAGES: &str = "POST https://api.tempmailhub.org/emails/messages";

    // messages.json keeps the recorded row shape, but its content is
    // synthetic: every inbox in the pool holds other people's mail.

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route_seq(GENERATE, [f("generate_1.json"), f("generate_2.json")])
            .route(MESSAGES, f("messages.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TempMailHub {
            http: w.transport("tempmailhub", &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("pool.account.two@gmail.com", "tempmailhub")
    }

    fn ts(s: &str) -> Option<jiff::Timestamp> {
        Some(s.parse().unwrap())
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_hands_out_a_gmail_address() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, "pool.account.one@gmail.com");
        assert!(a.state.is_none());
    }

    #[tokio::test]
    async fn the_inbox_is_read_by_address() {
        let w = wire();
        let rows = build(&w).list(&address()).await.unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["imap-61417", "imap-61416"]);
        let req = w.seen().pop().unwrap();
        assert_eq!(req.method.as_str(), "POST");
        assert_eq!(req.url, format!("{API}/emails/messages"));
        assert!(
            matches!(&req.body, crate::transport::Body::Json(v) if *v == json!({"email": address().value}))
        );
    }

    #[tokio::test]
    async fn list_rows_carry_sender_subject_and_utc_date() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows[0].sender, "Example <noreply@example.com>");
        assert_eq!(rows[0].subject, "Your verification code");
        assert_eq!(rows[0].received_at, ts("2026-09-24T12:31:42Z"));
    }

    #[tokio::test]
    async fn get_reads_the_row_body() {
        let m = build(&wire()).get(&address(), "imap-61417").await.unwrap();
        assert_eq!(m.id, "imap-61417");
        assert_eq!(m.sender, "Example <noreply@example.com>");
        assert_eq!(m.subject, "Your verification code");
        assert_eq!(m.received_at, ts("2026-09-24T12:31:42Z"));
        assert!(
            m.text.contains("Your verification code is 482913"),
            "{}",
            m.text
        );
        assert!(m.html.contains("<p"));
    }

    #[tokio::test]
    async fn get_extracts_links_from_the_body() {
        let m = build(&wire()).get(&address(), "imap-61416").await.unwrap();
        assert!(m.links.iter().any(|l| l.contains("example.com/confirm")));
    }

    #[tokio::test]
    async fn a_message_no_longer_listed_is_gone() {
        assert!(matches!(
            build(&wire()).get(&address(), "imap-1").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(MESSAGES, Reply::json(json!({"emails": []})));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_list_without_an_emails_array_is_drift() {
        for payload in [
            json!({"emails": {}}),
            json!({"error": "x"}),
            json!([]),
            json!({"emails": [{"x": 1}]}),
        ] {
            let w = wire().route(MESSAGES, Reply::json(payload.clone()));
            assert!(
                matches!(
                    build(&w).list(&address()).await,
                    Err(Error::SchemaDrift { .. })
                ),
                "{payload}"
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_generate_is_drift() {
        for payload in [
            json!({"email_id": 10}),
            json!({"email": "no-at-sign"}),
            json!([]),
        ] {
            let w = wire().route(GENERATE, Reply::json(payload.clone()));
            assert!(
                matches!(
                    build(&w).generate(&GenerateOptions::default()).await,
                    Err(Error::SchemaDrift { .. })
                ),
                "{payload}"
            );
        }
    }

    #[tokio::test]
    async fn a_429_surfaces_as_rate_limited() {
        let w = wire().route(MESSAGES, Reply::json(json!({})).with_status(429));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::RateLimited { .. })
        ));
    }

    #[tokio::test]
    async fn a_chosen_local_or_domain_is_refused() {
        let opts = GenerateOptions {
            local: Some("me".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }
}
