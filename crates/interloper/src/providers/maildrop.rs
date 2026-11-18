//! maildrop.cc: a GraphQL API with introspection left on. Any local part at
//! the domain receives, so generate() makes no request.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://api.maildrop.cc/graphql";
const DOMAINS: &[&str] = &["maildrop.cc"];
const INBOX: &str =
    "query ($mailbox: String!) { inbox(mailbox: $mailbox) { id headerfrom subject date } }";
const MESSAGE: &str = "query ($mailbox: String!, $id: String!) { message(mailbox: $mailbox, id: $id) { id headerfrom subject date html } }";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["maildrop.cc"],
    domains: DOMAINS,
    domain_count: 1,
    message_ttl: Some(days(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "maildrop",
    caps: CAPS,
    build: |t| Arc::new(Maildrop { http: t }),
};

pub struct Maildrop {
    http: Transport,
}

impl Maildrop {
    async fn query(&self, query: &str, field: &str, vars: Value) -> Result<Value> {
        let v = self
            .http
            .post(API)
            .json_body(&json!({"query": query, "variables": vars}))
            .json()
            .await?;
        // A GraphQL `errors` array is the backend answering, not a shape change.
        if let Some(errors) = v.get("errors").filter(|e| !e.is_null()) {
            let msg = errors
                .get(0)
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(Error::down("maildrop", msg));
        }
        let j = J::new("maildrop", &v, "graphql");
        let data = j.at("data")?;
        Ok(data.at(field)?.value().clone())
    }
}

fn mailbox(a: &Address) -> Value {
    Value::String(a.local().to_string())
}

#[async_trait]
impl Provider for Maildrop {
    fn name(&self) -> &str {
        "maildrop"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("maildrop", opts, DOMAINS)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            "maildrop",
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let rows = self
            .query(INBOX, "inbox", json!({"mailbox": mailbox(a)}))
            .await?;
        if rows.is_null() {
            return Ok(vec![]);
        }
        J::new("maildrop", &rows, "data.inbox")
            .items()?
            .iter()
            .map(|r| {
                Ok(
                    MessageRow::new(r.req_id("id")?, r.s("headerfrom"), r.s("subject"))
                        .at(r.time("date")),
                )
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let row = self
            .query(MESSAGE, "message", json!({"mailbox": mailbox(a), "id": id}))
            .await?;
        if row.is_null() {
            return Err(Error::gone("maildrop", id));
        }
        let j = J::new("maildrop", &row, "data.message");
        if !row.is_object() {
            return Err(j.drift("a message object"));
        }
        let mid = j
            .opt("id")
            .map(|i| i.id())
            .transpose()?
            .unwrap_or_else(|| id.to_string());
        Ok(Message::from_bodies(
            mid,
            j.s("headerfrom"),
            j.s("subject"),
            j.time("date"),
            j.s("html"),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/maildrop");

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("inbox(mailbox", f("inbox.json"))
            .route("message(mailbox", f("message.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Maildrop {
            http: w.transport("maildrop", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn graphql_errors_are_an_outage_not_drift() {
        let w = wire().route(
            "inbox(mailbox",
            Reply::json(Fixtures::load(DIR, "errors.json")),
        );
        let err = build(&w)
            .list(&Address::new("x@maildrop.cc", "maildrop"))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ProviderDown { .. }), "{err}");
    }

    #[tokio::test]
    async fn null_message_is_gone() {
        let w = wire().route(
            "message(mailbox",
            Reply::json(Fixtures::load(DIR, "message_null.json")),
        );
        let err = build(&w)
            .get(&Address::new("x@maildrop.cc", "maildrop"), "id")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::MessageGone { .. }));
    }

    #[tokio::test]
    async fn mailbox_is_the_local_part() {
        let w = wire();
        build(&w)
            .list(&Address::new("someone@maildrop.cc", "maildrop"))
            .await
            .unwrap();
        let crate::transport::Body::Json(body) = &w.seen()[0].body else {
            panic!()
        };
        assert_eq!(body["variables"]["mailbox"], "someone");
    }

    #[tokio::test]
    async fn message_has_code_and_link() {
        let m = build(&wire())
            .get(&Address::new("x@maildrop.cc", "maildrop"), "gYz1WaK7aq")
            .await
            .unwrap();
        assert!(m.text.contains("482913"));
        assert_eq!(m.links, ["https://example.test/verify?token=abc"]);
    }
}
