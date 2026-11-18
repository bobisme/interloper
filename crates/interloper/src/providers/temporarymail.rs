//! temporarymail.com — the web client's `/api/?action=` endpoints.
//!
//! generate() hands back a secretKey, and the inbox is read with that key
//! rather than the address, so it travels in Address::state. A message is read
//! by its id alone: getEmail for the headers, /view/?i=<id> for the HTML body.
//!
//! The inbox listing reports "[No Subject]" for a message nobody has opened
//! yet; getEmail has the real one.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::{Captures, Regex};
use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::Transport;

// The apex. www.temporarymail.com now answers every path, the API included,
// with a 301 to it (found live 2026-11-18; cowbird still called www).
const SITE: &str = "https://temporarymail.com";
const NAME: &str = "temporarymail";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["temporarymail.com"],
    domains: &[],
    domain_count: 9,
    // The site keeps an address alive as long as it is used once every
    // 14 days, so 14 days is the floor, not the ceiling.
    address_ttl: Some(days(14)),
    // Not measured.
    message_ttl: Some(days(1)),
    needs_state: true,
    // A burst of calls drew a 429 during recon.
    max_concurrency: 1,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(TemporaryMail { http: t }),
};

// The view page rewrites every link to its own redirector. Unwrapped, so a
// caller's link() gets the real target.
static REDIRECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"href="/redirect/\?d=([^"]+)""#).unwrap());

fn unwrap_links(html: &str) -> String {
    REDIRECT
        .replace_all(html, |c: &Captures| {
            let target = urlencoding::decode(&c[1])
                .map(|s| s.into_owned())
                .unwrap_or_else(|_| c[1].to_string());
            format!("href=\"{target}\"")
        })
        .into_owned()
}

fn sender(j: &J<'_>) -> String {
    let (address, name) = (j.s("from"), j.s("name"));
    if !name.is_empty() && !address.is_empty() {
        format!("{name} <{address}>")
    } else {
        address
    }
}

fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.value().get("date").and_then(parse_value_time)
}

pub struct TemporaryMail {
    http: Transport,
}

impl TemporaryMail {
    async fn messages(&self, action: &str, value: &str) -> Result<Map<String, Value>> {
        let v = self
            .http
            .get(format!("{SITE}/api/"))
            .query("action", action)
            .query("value", value)
            .json()
            .await?;
        // An empty result is a JSON array, a non-empty one an object keyed by
        // id.
        match v {
            Value::Array(a) if a.is_empty() => Ok(Map::new()),
            Value::Object(m) if m.values().all(Value::is_object) => Ok(m),
            other => Err(Error::drift(
                NAME,
                format!("an object of rows from {action}"),
                other,
            )),
        }
    }
}

#[async_trait]
impl Provider for TemporaryMail {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "temporarymail picks both the local part and the domain",
            ));
        }
        let v = self
            .http
            .get(format!("{SITE}/api/"))
            .query("action", "requestEmailAccess")
            .query("key", "")
            .query("value", "random")
            .json()
            .await?;
        let j = J::new(NAME, &v, "requestEmailAccess");
        let value = j.at("address")?.str()?.to_string();
        let key = j.at("secretKey")?.str()?.to_string();
        Ok(Address::new(value, NAME)
            .with_state(key)
            .expiring(CAPS.address_ttl))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let key = a.state.as_deref().ok_or_else(|| {
            Error::unsupported("temporarymail needs the secretKey issued by generate()")
        })?;
        let rows = self.messages("checkInbox", key).await?;
        Ok(rows
            .iter()
            .map(|(id, row)| {
                let j = J::new(NAME, row, "checkInbox");
                MessageRow::new(id.clone(), sender(&j), j.s("subject")).at(at(&j))
            })
            .collect())
    }

    async fn get(&self, _a: &Address, id: &str) -> Result<Message> {
        let rows = self.messages("getEmail", id).await?;
        let Some(row) = rows.get(id) else {
            return Err(Error::gone(NAME, id));
        };
        let j = J::new(NAME, row, "getEmail");
        let html = self
            .http
            .get(format!("{SITE}/view/"))
            .query("i", id)
            .text()
            .await?;
        Ok(Message::from_bodies(
            id,
            sender(&j),
            j.s("subject"),
            at(&j),
            unwrap_links(&html),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/temporarymail");
    const MESSAGE_ID: &str = "3XnhI0W1FLu9lX4qWlGCkrkAoIJwx23q";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route_seq(
                "action=requestEmailAccess",
                [f("access_1.json"), f("access_2.json")],
            )
            .route("action=checkInbox", f("inbox.json"))
            .route("action=getEmail", f("email.json"))
            .route("/view/", Reply::text(Fixtures::load_text(DIR, "view.html")))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TemporaryMail {
            http: w.transport(NAME, &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("Polo.Pascal@HorizonsPost.com", NAME)
            .with_state("5zvhLspSb3KmQjY0BddngDj8oEHyP87e")
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn the_inbox_is_read_with_the_secret_key_from_generate() {
        let w = wire();
        let p = build(&w);
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        p.list(&a).await.unwrap();
        let key = a.state.clone().unwrap();
        assert!(
            w.seen()
                .iter()
                .any(|r| r.query.iter().any(|(k, v)| k == "value" && *v == key))
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_answers_an_empty_array() {
        let w = wire().route("action=checkInbox", Reply::json(json!([])));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_takes_the_subject_from_get_email_and_the_body_from_view() {
        // The inbox listing says "[No Subject]" until a message has been
        // opened.
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.subject.starts_with("JoltMx test email"), "{}", m.subject);
        assert!(m.text.contains("everything is working as expected"));
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/")),
            "{:?}",
            m.links
        );
        assert!(m.links.iter().all(|l| !l.contains("/redirect/")));
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
    }

    #[tokio::test]
    async fn a_message_get_email_does_not_know_is_gone() {
        let w = wire().route("action=getEmail", Reply::json(json!([])));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn list_without_the_secret_key_is_refused() {
        assert!(matches!(
            build(&wire())
                .list(&Address::new("x@HorizonsPost.com", NAME))
                .await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn an_inbox_that_is_neither_object_nor_array_is_drift() {
        let w = wire().route("action=checkInbox", Reply::json(json!("changed")));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
