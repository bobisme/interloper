//! inboxes.com: a catch-all across 18 domains.
//!
//! Any local part on any of its domains receives mail with no registration,
//! so generate() makes no request at all. The declared domain list is the only
//! thing between a typo and an address that silently never receives, so it is
//! refreshed from `GET /api/v2/domain`, not from memory.
//!
//! Do not reach for the v3 API: it is the paid RapidAPI surface behind an
//! `apikey` header; the free site uses v2, unauthenticated in practice.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::util::{local_or_random, pick_domain};
use crate::error::Result;
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::Transport;

const API: &str = "https://inboxes.com/api/v2";

// Recorded live from GET /api/v2/domain on 2026-09-07.
const DOMAINS: &[&str] = &[
    "blondmail.com",
    "chapsmail.com",
    "clowmail.com",
    "dropjar.com",
    "fivermail.com",
    "getairmail.com",
    "getmule.com",
    "getnada.com",
    "gimpmail.com",
    "givmail.com",
    "guysmail.com",
    "inboxbear.com",
    "replyloop.com",
    "robot-mail.com",
    "tafmail.com",
    "temptami.com",
    "tupmail.com",
    "vomoto.com",
];

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["inboxes.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    message_ttl: Some(days(7)),
    delete: true,
    custom_local: true,
    poll_interval: std::time::Duration::from_secs(3),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "inboxes",
    caps: CAPS,
    build: |t| Arc::new(Inboxes { http: t }),
};

pub struct Inboxes {
    http: Transport,
}

/// Epoch seconds under `r`, else an ISO string under `cr`. An unreadable
/// timestamp is not a reason to fail a usable message.
fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.value()
        .get("r")
        .and_then(parse_value_time)
        .or_else(|| j.time("cr"))
}

#[async_trait]
impl Provider for Inboxes {
    fn name(&self) -> &str {
        "inboxes"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("inboxes", opts, DOMAINS)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            "inboxes",
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .http
            .get(format!("{API}/inbox/{}", a.value))
            .json()
            .await?;
        let j = J::new("inboxes", &v, "inbox");
        // Terse, undocumented field names: uid/f/s/r.
        j.at("msgs")?
            .items()?
            .iter()
            .map(|r| Ok(MessageRow::new(r.req_id("uid")?, r.s("f"), r.s("s")).at(at(r))))
            .collect()
    }

    async fn get(&self, _a: &Address, id: &str) -> Result<Message> {
        let v = self
            .http
            .get(format!("{API}/message/{}", urlencoding::encode(id)))
            .json()
            .await?;
        let j = J::new("inboxes", &v, "message");
        // `text` is frequently an explicit null on HTML-only mail.
        let text = v.get("text").and_then(Value::as_str).map(String::from);
        Ok(Message::from_bodies(
            j.req_id("uid")?,
            j.s("f"),
            j.s("s"),
            at(&j),
            j.s("html"),
            text,
        ))
    }

    async fn delete(&self, _a: &Address, id: &str) -> Result<()> {
        // Bulk endpoint, ids in the body. Answers 200 {"changed": true}
        // whether or not the uid existed: deleting a gone message succeeds.
        self.http
            .delete(format!("{API}/message/"))
            .json_body(&json!({"ids": [id]}))
            .send_json()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/inboxes");

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/inbox/", f("inbox_full.json"))
            .route("/message/", f("message_one.json"))
            .route("DELETE", Reply::json(json!({"changed": true})))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Inboxes {
            http: w.transport("inboxes", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_makes_no_request_and_honours_options() {
        let w = wire();
        let opts = GenerateOptions {
            local: Some("me".into()),
            domain: Some("GETNADA.com".into()),
            ..Default::default()
        };
        let a = build(&w).generate(&opts).await.unwrap();
        assert_eq!(a.value, "me@getnada.com");
        assert!(w.seen().is_empty());
    }

    #[test]
    fn declared_domains_match_the_recorded_listing() {
        let v = Fixtures::load(DIR, "domains.json");
        let live: Vec<&str> = v["domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["qdn"].as_str().unwrap())
            .collect();
        assert_eq!(live, DOMAINS);
    }

    #[tokio::test]
    async fn null_text_falls_back_to_html() {
        let mut doc = Fixtures::load(DIR, "message_one.json");
        doc["text"] = Value::Null;
        let w = wire().route("/message/", Reply::json(doc));
        let m = build(&w)
            .get(&Address::new("a@getnada.com", "inboxes"), "x")
            .await
            .unwrap();
        assert!(!m.text.is_empty());
    }

    #[tokio::test]
    async fn missing_msgs_is_drift() {
        let w = wire().route("/inbox/", Reply::json(json!({"messages": []})));
        let err = build(&w)
            .list(&Address::new("a@getnada.com", "inboxes"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }));
    }
}
