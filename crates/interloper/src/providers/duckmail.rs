//! DuckMail (api.duckmail.sbs), the backend behind freetempmail.com.
//!
//! A mail.tm clone: same Hydra API, same account/token/messages flow. The one
//! protocol difference is that its list endpoints keep the `hydra:member`
//! envelope even under `Accept: application/json`, where mail.tm returns a
//! bare array.
//!
//! All 19 domains it lists (checked 2026-09-24) carry only `isVerified: true`,
//! with no isPrivate/owner flag, and accounts were created anonymously on both
//! the first and the last of them, so no domain filtering is needed.

use std::sync::Arc;

use super::mailtm::{self, MailTm};
use crate::model::{Capabilities, days};
use crate::registry::ProviderSpec;
use crate::transport::Transport;

const API: &str = "https://api.duckmail.sbs";

pub const CAPS: Capabilities = Capabilities {
    sites: &["duckmail.sbs", "freetempmail.com"],
    domain_count: 19,
    // POST /accounts answers with expiresAt one day out.
    address_ttl: Some(days(1)),
    // Not measured: no mail was sent. Nothing outlives its account.
    message_ttl: Some(days(1)),
    ..mailtm::CAPS
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "duckmail",
    caps: CAPS,
    build: |t| Arc::new(build(t)),
};

fn build(t: Transport) -> MailTm {
    MailTm::new("duckmail", API, CAPS, t).with_envelope()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::model::Address;
    use crate::provider::{GenerateOptions, Provider};
    use crate::testing::{Fixtures, Reply};
    use serde_json::{Value, json};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/duckmail");

    // domains/account/token/messages_empty were recorded live through a real
    // transport. messages_full and message_one are hand-built in mail.tm's row
    // shape: recording them needs a message delivered to the inbox, and
    // nothing here sends mail.
    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/domains", f("domains.json"))
            .route("/accounts", f("account.json").with_status(201))
            .route("/token", f("token.json"))
            .route(
                "GET https://api.duckmail.sbs/messages?",
                f("messages_full.json"),
            )
            .route("/messages/6a1f2c9e4b7d", f("message_one.json"))
            .route("DELETE", Reply::status(204))
    }

    fn over(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(build(w.transport("duckmail", &CAPS)))
    }

    crate::contract_tests!(SPEC, over(&wire()));

    fn address() -> Address {
        let state = json!({"address": "a@niceground.shop", "password": "x", "token": "t"});
        Address::new("a@niceground.shop", "duckmail").with_state(state.to_string())
    }

    fn served() -> Vec<String> {
        Fixtures::load(DIR, "domains.json")["hydra:member"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["domain"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn declares_its_own_name_and_front_doors() {
        assert_eq!(SPEC.name, "duckmail");
        assert_eq!(CAPS.sites, ["duckmail.sbs", "freetempmail.com"]);
        assert_eq!(CAPS.domain_count, served().len());
    }

    #[tokio::test]
    async fn every_request_goes_to_duckmail_and_none_to_mail_tm() {
        let w = wire();
        let p = over(&w);
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        let rows = p.list(&a).await.unwrap();
        p.get(&a, &rows[0].id).await.unwrap();
        p.delete(&a, &rows[0].id).await.unwrap();
        let urls: Vec<String> = w.seen().iter().map(|r| r.full_url()).collect();
        assert_eq!(urls.len(), 6);
        assert!(
            urls.iter()
                .all(|u| u.starts_with("https://api.duckmail.sbs/")),
            "{urls:?}"
        );
    }

    #[tokio::test]
    async fn generate_uses_a_domain_duckmail_serves() {
        let a = over(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert!(served().iter().any(|d| d == a.domain()), "{}", a.value);
        assert_eq!(a.provider, "duckmail");
    }

    #[tokio::test]
    async fn empty_inbox_envelope_lists_as_empty() {
        let w = wire().route(
            "GET https://api.duckmail.sbs/messages?",
            Reply::json(Fixtures::load(DIR, "messages_empty.json")),
        );
        assert!(over(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_bare_array_where_the_envelope_belongs_is_schema_drift() {
        // DuckMail wraps list endpoints in hydra:member even under
        // Accept: application/json. A bare array means the shape moved.
        let w = wire().route("/domains", Reply::json(Value::Array(vec![])));
        let err = over(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }), "{err}");
        assert!(err.to_string().contains("hydra:member"), "{err}");
    }
}
