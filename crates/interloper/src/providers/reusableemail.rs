//! reusable.email: the web client's `/v1/inbox` API.
//!
//! Inboxes are public: anyone can mint a read token for any name, so a caller
//! wanting privacy must use an unguessable local part (the default random one
//! is). An inbox is created by `POST /v1/inbox/ensure`; reads carry
//! `Authorization: Inbox <token>` from `POST /v1/inbox/<address>/token`, which
//! lasts 24 hours.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://api.reusable.email/v1/inbox";
const DOMAIN: &str = "reusable.email";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["reusable.email"],
    domains: &[DOMAIN],
    domain_count: 1,
    // The name is reusable: an inbox is not retired.
    address_ttl: None,
    // Not measured; the site's agent API documents 90 days of retention.
    message_ttl: Some(days(90)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "reusableemail",
    caps: CAPS,
    build: |t| {
        Arc::new(ReusableEmail {
            http: t,
            tokens: Mutex::default(),
        })
    },
};

pub struct ReusableEmail {
    http: Transport,
    // Any process can mint a token from the address alone, so it is cached
    // here rather than carried in Address::state.
    tokens: Mutex<HashMap<String, String>>,
}

fn inbox_url(a: &Address) -> String {
    format!("{API}/{}", urlencoding::encode(&a.value))
}

/// The HTTP status an error body reports: `{"error": {"status": 404, ...}}`.
fn error_status(v: &Value) -> Option<i64> {
    v.get("error")?.get("status")?.as_i64()
}

fn sender(j: &J<'_>) -> String {
    let Some(from) = j.opt("from") else {
        return String::new();
    };
    let (address, name) = (from.s("address"), from.s("name"));
    if !name.is_empty() && !address.is_empty() {
        format!("{name} <{address}>")
    } else {
        address
    }
}

impl ReusableEmail {
    async fn ensure(&self, value: &str) -> Result<()> {
        let v = self
            .http
            .post(format!("{API}/ensure"))
            .json_body(&json!({"address": value}))
            .json()
            .await?;
        match v.get("status").and_then(Value::as_str) {
            Some("created" | "exists") => Ok(()),
            _ => Err(Error::drift(
                "reusableemail",
                "'created' or 'exists' from ensure",
                v,
            )),
        }
    }

    async fn mint(&self, a: &Address) -> Result<String> {
        let url = format!("{}/token", inbox_url(a));
        let mut v = self.http.post(&url).json_body(&json!({})).json().await?;
        if error_status(&v) == Some(404) {
            // Never ensured, e.g. a hand-made Address; the web client does
            // the same.
            self.ensure(&a.value).await?;
            v = self.http.post(&url).json_body(&json!({})).json().await?;
        }
        let token = J::new("reusableemail", &v, "token")
            .at("token")?
            .str()?
            .to_string();
        self.tokens
            .lock()
            .unwrap()
            .insert(a.value.clone(), token.clone());
        Ok(token)
    }

    async fn read(&self, a: &Address, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        // A 401 means the cached token expired: drop it and mint once more.
        for _ in 0..2 {
            let cached = self.tokens.lock().unwrap().get(&a.value).cloned();
            let token = match cached {
                Some(t) => t,
                None => self.mint(a).await?,
            };
            let mut req = self
                .http
                .get(format!("{}{path}", inbox_url(a)))
                .header("Authorization", format!("Inbox {token}"));
            for (k, v) in query {
                req = req.query(*k, *v);
            }
            let v = req.json().await?;
            if error_status(&v) != Some(401) {
                return Ok(v);
            }
            self.tokens.lock().unwrap().remove(&a.value);
        }
        Err(Error::down(
            "reusableemail",
            "a freshly minted inbox token was rejected",
        ))
    }
}

#[async_trait]
impl Provider for ReusableEmail {
    fn name(&self) -> &str {
        "reusableemail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("reusableemail", opts, &[DOMAIN])?;
        let value = format!("{}@{domain}", local_or_random(opts));
        self.ensure(&value).await?;
        Ok(Address::new(value, "reusableemail"))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.read(a, "", &[("limit", "20")]).await?;
        let j = J::new("reusableemail", &v, "inbox");
        j.at("emails")?
            .items()?
            .iter()
            .map(|r| {
                Ok(MessageRow::new(r.req_id("id")?, sender(r), r.s("subject")).at(r.time("date")))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let path = format!("/emails/{}", urlencoding::encode(id));
        let v = self.read(a, &path, &[]).await?;
        // 404 for an unknown id, 400 for one that could never exist.
        if matches!(error_status(&v), Some(400 | 404)) {
            return Err(Error::gone("reusableemail", id));
        }
        let j = J::new("reusableemail", &v, "email");
        j.req_id("id")?;
        let text = Some(j.s("text")).filter(|t| !t.is_empty());
        Ok(Message::from_bodies(
            id,
            sender(&j),
            j.s("subject"),
            j.time("date"),
            j.s("html"),
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/reusableemail");
    const ENSURE: &str = "POST https://api.reusable.email/v1/inbox/ensure?";
    const TOKEN: &str = "/token?";
    const LIST: &str = "?limit=20";
    const EMAIL: &str = "/emails/1?";

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(ENSURE, f("ensure.json").with_status(201))
            .route(TOKEN, f("token.json"))
            .route(LIST, f("inbox.json"))
            .route(EMAIL, f("email.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        (SPEC.build)(w.transport("reusableemail", &CAPS))
    }

    fn address() -> Address {
        Address::new("cb4e5581de14@reusable.email", "reusableemail")
    }

    fn calls(w: &Fixtures, needle: &str) -> usize {
        w.seen()
            .iter()
            .filter(|r| format!("{} {}", r.method.as_str(), r.url).contains(needle))
            .count()
    }

    fn ts(s: &str) -> Option<jiff::Timestamp> {
        Some(s.parse().unwrap())
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_ensures_the_inbox() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let seen = w.seen();
        assert_eq!(seen.len(), 1);
        assert!(
            matches!(&seen[0].body, crate::transport::Body::Json(v) if *v == json!({"address": a.value}))
        );
        assert!(a.value.ends_with("@reusable.email"));
    }

    #[tokio::test]
    async fn generate_honours_a_chosen_local() {
        let opts = GenerateOptions {
            local: Some("hello".into()),
            domain: Some("reusable.email".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "hello@reusable.email");
    }

    #[tokio::test]
    async fn a_domain_it_does_not_serve_is_refused() {
        let opts = GenerateOptions {
            domain: Some("gmail.com".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn list_sends_the_inbox_token() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        let get = w
            .seen()
            .into_iter()
            .find(|r| r.method.as_str() == "GET")
            .unwrap();
        assert_eq!(
            get.url,
            "https://api.reusable.email/v1/inbox/cb4e5581de14%40reusable.email"
        );
        assert_eq!(
            get.header("Authorization"),
            Some("Inbox fixture-token-not-real")
        );
    }

    #[tokio::test]
    async fn list_parses_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "1");
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d377706d)");
        assert_eq!(rows[0].received_at, ts("2026-09-24T12:50:15Z"));
    }

    #[tokio::test]
    async fn the_token_is_minted_once_per_address() {
        let w = wire();
        let p = build(&w);
        p.list(&address()).await.unwrap();
        p.get(&address(), "1").await.unwrap();
        assert_eq!(calls(&w, "/token"), 1);
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(LIST, f("inbox_empty.json"));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_parses_sender_subject_utc_date_and_body() {
        let m = build(&wire()).get(&address(), "1").await.unwrap();
        assert_eq!(m.id, "1");
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert_eq!(m.subject, "JoltMx test email (ref 01a0d377706d)");
        assert_eq!(m.received_at, ts("2026-09-24T12:50:15Z"));
        assert!(m.text.contains("everything is working as expected"));
        assert!(!m.html.is_empty());
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
    }

    #[tokio::test]
    async fn an_unknown_id_is_gone() {
        let w = wire().route(EMAIL, f("email_missing.json").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), "1").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_list_without_emails_is_drift() {
        let w = wire().route(LIST, Reply::json(json!({"inbox": {}, "rows": []})));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_rejected_token_is_reminted_once() {
        let w = wire().route_seq(
            LIST,
            [f("unauthorized.json").with_status(401), f("inbox.json")],
        );
        let rows = build(&w).list(&address()).await.unwrap();
        assert_eq!(rows[0].id, "1");
        assert_eq!(calls(&w, "/token"), 2);
    }

    #[tokio::test]
    async fn a_token_rejected_twice_is_not_retried_forever() {
        let w = wire().route(LIST, f("unauthorized.json").with_status(401));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
        assert_eq!(calls(&w, "/token"), 2);
    }

    #[tokio::test]
    async fn an_inbox_that_does_not_exist_yet_is_ensured_before_the_token() {
        let w = wire().route_seq(
            TOKEN,
            [f("token_missing.json").with_status(404), f("token.json")],
        );
        build(&w)
            .list(&Address::new("cbnew@reusable.email", "reusableemail"))
            .await
            .unwrap();
        assert_eq!(calls(&w, "/v1/inbox/ensure"), 1);
        assert_eq!(calls(&w, "/token"), 2);
    }
}
