//! mail.cx — the site's own origin, not the keyed api.mail.cx host.
//!
//! The inbox endpoint is a long-poll: an empty inbox holds about 25 seconds
//! and answers 204, and it returns the moment mail lands. list() is that
//! long-poll, so the default watch loop over it already sees mail as soon as
//! it arrives. The transport's 60 s timeout comfortably covers the hold.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::Rng;

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://mail.cx/v1";
const NAME: &str = "mailcx";
const LOCAL_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mail.cx"],
    domains: &[], // discovered from /v1/config
    domain_count: 3,
    // The config's ttl_seconds, read as message retention.
    message_ttl: Some(hours(1)),
    custom_local: true,
    // One request at a time. Concurrent long-polls draw 429, so a second
    // address waits behind the first one's 25 s hold.
    max_concurrency: 1,
    poll_interval: std::time::Duration::from_secs(1),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(MailCx::new(t)),
};

/// The served domains and the one the site defaults to.
#[derive(Clone)]
struct Domains {
    all: Vec<String>,
    default: String,
}

pub struct MailCx {
    http: Transport,
    // Read from /v1/config once per process.
    domains: Mutex<Option<Domains>>,
}

impl MailCx {
    pub fn new(http: Transport) -> Self {
        MailCx {
            http,
            domains: Mutex::new(None),
        }
    }

    async fn domains(&self) -> Result<Domains> {
        if let Some(d) = self.domains.lock().unwrap().clone() {
            return Ok(d);
        }
        let config = self.http.get(format!("{API}/config")).json().await?;
        let entries = J::new(NAME, &config, "config").at("system_domains")?;
        let entries = entries.items()?;
        if entries.is_empty() {
            return Err(entries_drift(&config));
        }
        let objects: Vec<_> = entries.iter().filter(|e| e.value().is_object()).collect();
        let all: Vec<String> = objects
            .iter()
            .filter_map(|e| e.value().get("domain")?.as_str().map(String::from))
            .collect();
        let Some(first) = all.first().cloned() else {
            return Err(Error::drift(
                NAME,
                "'domain' in a system_domains entry",
                &config["system_domains"],
            ));
        };
        let default = objects
            .iter()
            .find(|e| e.value().get("default").and_then(|d| d.as_bool()) == Some(true))
            .and_then(|e| e.value().get("domain")?.as_str().map(String::from))
            .unwrap_or(first);
        let d = Domains { all, default };
        *self.domains.lock().unwrap() = Some(d.clone());
        Ok(d)
    }
}

fn entries_drift(config: &serde_json::Value) -> Error {
    Error::drift(NAME, "system_domains in /v1/config", config)
}

fn random_local() -> String {
    let mut rng = rand::rng();
    (0..6)
        .map(|_| LOCAL_ALPHABET[rng.random_range(0..LOCAL_ALPHABET.len())] as char)
        .collect()
}

#[async_trait]
impl Provider for MailCx {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let d = self.domains().await?;
        let domain = match &opts.domain {
            Some(want) => d
                .all
                .iter()
                .find(|x| x.eq_ignore_ascii_case(want))
                .cloned()
                .ok_or_else(|| {
                    Error::unsupported(format!("mailcx does not serve {want}; has {:?}", d.all))
                })?,
            None => d.default,
        };
        let local = opts.local.clone().unwrap_or_else(random_local);
        Ok(Address::new(format!("{local}@{domain}"), NAME))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        // A quick peek at an empty inbox costs the full 25 s hold. No
        // parameter makes this endpoint non-blocking (measured 2026-09-11).
        let resp = self
            .http
            .get(format!("{API}/inbox/{}", a.value))
            .send_json()
            .await?;
        if resp.status == 204 {
            return Ok(vec![]);
        }
        if resp.status >= 400 {
            return Err(Error::down(
                NAME,
                format!("inbox answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json(NAME)?;
        J::new(NAME, &v, "inbox")
            .at("emails")?
            .items()?
            .iter()
            .map(|r| {
                Ok(
                    MessageRow::new(r.req_id("id")?, r.s("from_email"), r.s("subject"))
                        .at(r.time("created_at")),
                )
            })
            .collect()
    }

    async fn get(&self, _a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .http
            .get(format!("{API}/email/{}", urlencoding::encode(id)))
            .send_json()
            .await?;
        if resp.status == 404 {
            return Err(Error::gone(NAME, id));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                NAME,
                format!("email answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json(NAME)?;
        let j = J::new(NAME, &v, "email");
        if !v.is_object() {
            return Err(j.drift("an object"));
        }
        let text = v
            .get("text_body")
            .and_then(|t| t.as_str())
            .map(String::from);
        let id = j.opt("id").and_then(|i| i.id().ok()).unwrap_or(id.into());
        Ok(Message::from_bodies(
            id,
            j.s("from_email"),
            j.s("subject"),
            j.time("created_at"),
            j.s("html_body"),
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mailcx");
    const MESSAGE_ID: &str = "16ce0b8348a324de8720ac3c92ae8e6d";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/v1/config", f("config.json"))
            .route("/v1/inbox/", f("inbox.json"))
            .route("/v1/email/", f("email.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(MailCx::new(w.transport(NAME, &CAPS)))
    }

    fn address() -> Address {
        Address::new("cbfixt@uqu.me", NAME)
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_uses_the_default_domain_and_reads_config_once() {
        let w = wire();
        let p = build(&w);
        let first = p.generate(&GenerateOptions::default()).await.unwrap();
        p.generate(&GenerateOptions::default()).await.unwrap();
        assert!(first.value.ends_with("@uqu.me"), "{}", first.value);
        assert_eq!(
            w.seen()
                .iter()
                .filter(|r| r.url.contains("/v1/config"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_domain_it_does_not_serve_is_refused() {
        let opts = GenerateOptions {
            domain: Some("elsewhere.test".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_204_from_the_long_poll_is_an_empty_inbox() {
        let w = wire().route("/v1/inbox/", Reply::status(204));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_404_on_read_is_gone() {
        let w = wire().route(
            "/v1/email/",
            Reply::json(json!({"error": "not_found"})).with_status(404),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn the_text_body_is_used_as_sent() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.text, "Your verification code is 482913.");
    }

    #[tokio::test]
    async fn a_non_object_inbox_row_is_drift() {
        let w = wire().route(
            "/v1/inbox/",
            Reply::json(json!({"emails": ["not-a-dict"], "next_since": null})),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_non_object_message_body_is_drift() {
        let w = wire().route("/v1/email/", Reply::json(json!(["not-a-dict"])));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn non_object_system_domains_entries_are_drift() {
        let w = wire().route(
            "/v1/config",
            Reply::json(json!({"system_domains": ["ddker.com", "uqu.me"], "ttl_seconds": 3600})),
        );
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn no_domain_field_anywhere_is_drift() {
        let w = wire().route(
            "/v1/config",
            Reply::json(
                json!({"system_domains": [{"not_domain": "ddker.com"}], "ttl_seconds": 3600}),
            ),
        );
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
