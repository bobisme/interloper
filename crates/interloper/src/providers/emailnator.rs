//! emailnator.com: Gmail-alias disposable addresses.
//!
//! Contract verified live 2026-09-04 (in cowbird). Its first body read takes
//! about 39 seconds, so poll_interval is 10s rather than the 5s default.
//!
//! It sits behind Cloudflare, but needs_residential_ip is false: the same
//! upstream has been served continuously from a Render dyno (a datacenter IP)
//! without drawing a challenge. The declared flag is only a hint for humans;
//! what drives behavior is the observed one on the health entry, set the
//! moment a challenge is seen and cleared on the next success. Declaring true
//! here would be a guess overriding a measurement.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;

use super::util::no_custom_local;
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://www.emailnator.com";

// Upstream option ids: domain 1, plusGmail 2, dotGmail 3, googleMail 8.
// dotGmail is the default: it yields the widest pool of distinct-looking
// addresses at gmail.com.
const DOT_GMAIL: u32 = 3;

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::GmailAlias],
    sites: &["emailnator.com"],
    domain_count: 6,
    message_ttl: Some(days(1)),
    delete: true,
    poll_interval: Duration::from_secs(10),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "emailnator",
    caps: CAPS,
    build: |t| Arc::new(Emailnator { http: t }),
};

pub struct Emailnator {
    http: Transport,
}

/// Rows carry a Unix epoch under `timestamp` (and `date` on a full document).
/// Recorded responses show plain integer seconds, not ISO strings. A bad or
/// missing value yields None: a timestamp we cannot read is not a reason to
/// fail a message the caller can otherwise use.
fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.time("timestamp").or_else(|| j.time("date"))
}

#[async_trait]
impl Provider for Emailnator {
    fn name(&self) -> &str {
        "emailnator"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        no_custom_local("emailnator", opts)?;
        if let Some(d) = &opts.domain {
            return Err(Error::unsupported(format!(
                "emailnator picks its own domain, not {d}"
            )));
        }
        let v = self
            .http
            .post(format!("{API}/api/generate-email"))
            .json_body(&json!({"ids": [DOT_GMAIL]}))
            .json()
            .await?;
        let email = J::new("emailnator", &v, "generate-email")
            .at("email")?
            .str()?
            .to_string();
        Ok(Address::new(email, "emailnator"))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let resp = self
            .http
            .post(format!("{API}/api/message-list"))
            .json_body(&json!({"email": a.value, "limit": 20}))
            .send_json()
            .await?;
        // An address upstream has never seen answers 404. That is an empty
        // inbox, not a fault: every freshly generated address starts here.
        if resp.status == 404 {
            return Ok(vec![]);
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "emailnator",
                format!("message-list answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json("emailnator")?;
        J::new("emailnator", &v, "message-list")
            .at("messages")?
            .items()?
            .iter()
            .map(|r| {
                let mut row =
                    MessageRow::new(r.req_id("id")?, r.s("from"), r.s("subject")).at(at(r));
                row.locked = r.opt("locked").and_then(|l| l.bool().ok()) == Some(true);
                Ok(row)
            })
            .collect()
    }

    async fn get(&self, _a: &Address, id: &str) -> Result<Message> {
        let v = self
            .http
            .get(format!("{API}/api/message/{}", urlencoding::encode(id)))
            .json()
            .await?;
        let j = J::new("emailnator", &v, "message");
        let content = j.at("content")?.value().as_str().unwrap_or_default();
        let locked = j.opt("locked").and_then(|l| l.bool().ok()) == Some(true);
        // A paywalled message answers 200 with an empty body rather than an
        // error status, so emptiness is the only signal there is.
        if locked || content.is_empty() {
            return Err(Error::MessageLocked {
                provider: "emailnator".into(),
                id: id.into(),
            });
        }
        // The document repeats the row's envelope fields; carrying them through
        // means a caller who only ever calls get() still gets a usable Message.
        Ok(Message::from_bodies(
            id,
            j.s("from"),
            j.s("subject"),
            at(&j),
            content,
            None,
        ))
    }

    async fn delete(&self, _a: &Address, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!(
                "{API}/api/delete-message/{}",
                urlencoding::encode(id)
            ))
            .send()
            .await?;
        // Already gone is the outcome the caller wanted.
        match resp.status {
            200 | 204 | 404 => Ok(()),
            s => Err(Error::down(
                "emailnator",
                format!("delete failed, HTTP {s}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/emailnator");

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route("/api/generate-email", f("generate.json"))
            .route("/api/message-list", f("message_list_full.json"))
            .route("/api/message/", f("message_raw.json"))
            .route("/api/delete-message/", Reply::text(""))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Emailnator {
            http: w.transport("emailnator", &CAPS),
        })
    }

    crate::contract_tests!(
        SPEC,
        build(&wire().route_seq(
            "/api/generate-email",
            [f("generate.json"), f("generate_second.json")]
        ))
    );

    fn address() -> Address {
        Address::new("cb.fixture.first@gmail.com", "emailnator")
    }

    /// Every route answers `status` with an empty body.
    fn all_status(status: u16) -> Arc<Fixtures> {
        Fixtures::new()
            .route("/api/message-list", Reply::status(status))
            .route("/api/delete-message/", Reply::status(status))
    }

    #[tokio::test]
    async fn generate_requests_the_dot_gmail_option() {
        // The option id is the whole request. Sending the wrong one silently
        // yields a different class of address than the capabilities promise.
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let req = &w.seen()[0];
        assert_eq!(req.method.as_str(), "POST");
        assert_eq!(req.body, crate::transport::Body::Json(json!({"ids": [3]})));
        assert!(req.url.ends_with("/api/generate-email"));
        assert_eq!(a.value, "cb.fixture.first@gmail.com");
        assert_eq!(a.provider, "emailnator");
    }

    #[tokio::test]
    async fn generate_without_an_email_string_is_drift() {
        let w = wire().route(
            "/api/generate-email",
            Reply::json(json!({"status": "success"})),
        );
        let err = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }), "{err}");
        assert!(err.to_string().contains("email"), "{err}");
    }

    #[tokio::test]
    async fn an_address_upstream_has_never_seen_is_an_empty_inbox_not_an_error() {
        // emailnator answers 404 for an unknown address, which is where every
        // freshly generated address starts. Treating that as a fault would
        // mark the provider down on its own happy path.
        assert!(
            build(&all_status(404))
                .list(&address())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn message_row_missing_id_is_drift_naming_id() {
        let broken =
            json!({"status": "success", "messages": [{"from": "a@b.test", "subject": "hi"}]});
        let w = wire().route("/api/message-list", Reply::json(broken));
        let err = build(&w).list(&address()).await.unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }), "{err}");
        assert!(err.to_string().contains("\"id\""), "{err}");
    }

    #[tokio::test]
    async fn message_list_in_an_unexpected_shape_is_drift() {
        let w = wire().route(
            "/api/message-list",
            Reply::json(json!({"status": "success"})),
        );
        let err = build(&w).list(&address()).await.unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }), "{err}");
        assert!(err.to_string().contains("messages"), "{err}");
    }

    #[tokio::test]
    async fn row_timestamps_are_unix_epochs_not_iso_strings() {
        // Recorded rows carry integer epoch seconds. An ISO-only parse would
        // silently yield None for every message, losing ordering.
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(
            rows[0].received_at,
            Some(jiff::Timestamp::from_second(1788705267).unwrap())
        );
    }

    #[tokio::test]
    async fn get_carries_the_envelope_through_from_the_document() {
        let m = build(&wire()).get(&address(), "gp1.Ty1XDO").await.unwrap();
        assert_eq!(m.sender, "Digen AI <welcome@digen.ai>");
        assert_eq!(m.subject, "Verify your DIGEN email address");
        assert!(m.text.contains("270442"), "{}", m.text);
    }

    #[tokio::test]
    async fn a_paywalled_message_is_locked_and_never_reroutes() {
        // MessageLocked is an answer to the caller, not a provider fault:
        // rerouting would try every backend for a message only this one holds.
        let locked = json!({"id": "x", "content": "", "locked": true});
        let w = wire().route("/api/message/", Reply::json(locked));
        let err = build(&w).get(&address(), "x").await.unwrap_err();
        assert!(matches!(err, Error::MessageLocked { .. }), "{err}");
        assert!(!err.reroutable());
    }

    #[tokio::test]
    async fn get_without_content_is_drift() {
        let w = wire().route("/api/message/", Reply::json(json!({"id": "x"})));
        let err = build(&w).get(&address(), "x").await.unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }), "{err}");
        assert!(err.to_string().contains("content"), "{err}");
    }

    #[tokio::test]
    async fn deleting_an_already_deleted_message_is_success() {
        build(&all_status(404))
            .delete(&address(), "gone")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_reports_an_unexpected_status_as_provider_down() {
        let err = build(&all_status(403))
            .delete(&address(), "x")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ProviderDown { .. }), "{err}");
        assert!(err.to_string().contains("403"), "{err}");
    }

    #[tokio::test]
    async fn a_chosen_local_part_is_refused() {
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
