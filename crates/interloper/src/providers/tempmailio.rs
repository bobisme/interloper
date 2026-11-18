//! temp-mail.io — the web client's own JSON API at api.internal.temp-mail.io.
//!
//! List rows carry the whole message, text and HTML both, so get() is a lookup
//! in list() and there is no second endpoint. The token generate() returns is
//! only needed to delete; reading is keyed on the address alone.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://api.internal.temp-mail.io/api/v3";
const NAME: &str = "tempmailio";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["temp-mail.io"],
    domains: &[],
    domain_count: 7,
    address_ttl: Some(days(1)),
    message_ttl: Some(days(1)),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(TempMailIo { http: t }),
};

pub struct TempMailIo {
    http: Transport,
}

fn sender(j: &J<'_>) -> String {
    j.s("from")
}

impl TempMailIo {
    async fn rows(&self, a: &Address) -> Result<Value> {
        self.http
            .get(format!("{API}/email/{}/messages", a.value))
            .json()
            .await
    }
}

/// Every row must be an object with an `id`; anything else is drift.
fn checked<'a>(v: &'a Value) -> Result<Vec<(String, J<'a>)>> {
    J::new(NAME, v, "messages")
        .items()?
        .into_iter()
        .map(|r| Ok((r.req_id("id")?, r)))
        .collect()
}

#[async_trait]
impl Provider for TempMailIo {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "tempmailio picks both the local part and the domain",
            ));
        }
        let v = self
            .http
            .post(format!("{API}/email/new"))
            .json_body(&json!({"min_name_length": 10, "max_name_length": 10}))
            .json()
            .await?;
        let value = J::new(NAME, &v, "/email/new")
            .at("email")?
            .str()?
            .to_string();
        Ok(Address::new(value, NAME).expiring(CAPS.address_ttl))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.rows(a).await?;
        Ok(checked(&v)?
            .into_iter()
            .map(|(id, r)| MessageRow::new(id, sender(&r), r.s("subject")).at(r.time("created_at")))
            .collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let v = self.rows(a).await?;
        let Some((_, r)) = checked(&v)?.into_iter().find(|(rid, _)| rid == id) else {
            return Err(Error::gone(NAME, id));
        };
        let text = r
            .value()
            .get("body_text")
            .and_then(Value::as_str)
            .map(String::from);
        Ok(Message::from_bodies(
            id,
            sender(&r),
            r.s("subject"),
            r.time("created_at"),
            r.s("body_html"),
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tempmailio");
    const MESSAGE_ID: &str = "df254d10-f1fd-490d-849f-72da92e86038";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route_seq(
                "POST https://api.internal.temp-mail.io/api/v3/email/new",
                [f("new_1.json"), f("new_2.json")],
            )
            .route("/messages", f("messages.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TempMailIo {
            http: w.transport(NAME, &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("8xsmyjdem5@ruutukf.com", NAME)
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn the_body_comes_inline_from_the_list() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.text.contains("everything is working as expected"));
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
        assert_eq!(
            m.sender,
            "\"JoltMx Delivery Test\" <test@sendtest.joltmx.com>"
        );
    }

    #[tokio::test]
    async fn a_message_no_longer_listed_is_gone() {
        let w = wire().route(
            "/messages",
            Reply::json(Fixtures::load(DIR, "messages_empty.json")),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_list_that_is_not_an_array_is_drift() {
        let w = wire().route("/messages", Reply::json(json!({"error": "changed"})));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
