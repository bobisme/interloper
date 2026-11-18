//! mail.tm, and every backend that speaks its API (DuckMail reuses this).
//!
//! mail.tm content-negotiates: a browser Accept gets XML, curl's `*/*` gets a
//! JSON-LD envelope with `hydra:member`, and `Accept: application/json` (what
//! the transport pins) gets a plain JSON array from list endpoints. Fixtures
//! were recorded through the real transport for exactly that reason.
//!
//! An inbox is an account. Its JWT expires; the state carries the password so
//! a 401 re-mints the token and retries once. (cowbird packed the password
//! for that purpose but never re-minted.)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::util::{local_or_random, pick_domain, random_local};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mail.tm"],
    domains: &[], // discovered per call; mail.tm rotates them
    domain_count: 1,
    message_ttl: Some(days(7)),
    delete: true,
    custom_local: true,
    needs_state: true,
    // mail.tm publishes 8 QPS per IP.
    max_concurrency: 4,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "mailtm",
    caps: CAPS,
    build: |t| Arc::new(MailTm::new("mailtm", "https://api.mail.tm", CAPS, t)),
};

#[derive(Serialize, Deserialize)]
struct State {
    address: String,
    password: String,
    token: String,
}

pub struct MailTm {
    name: &'static str,
    api: &'static str,
    caps: Capabilities,
    http: Transport,
    // Re-minted tokens, by address. Address::state is immutable, so a fresh
    // token lives here for the rest of the process.
    tokens: Mutex<HashMap<String, String>>,
}

impl MailTm {
    pub fn new(name: &'static str, api: &'static str, caps: Capabilities, http: Transport) -> Self {
        MailTm {
            name,
            api,
            caps,
            http,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    fn state(&self, a: &Address) -> Result<State> {
        let raw = a.state.as_deref().ok_or_else(|| {
            Error::unsupported(format!(
                "{} needs the state issued by generate()",
                self.name
            ))
        })?;
        serde_json::from_str(raw)
            .map_err(|_| Error::unsupported(format!("{}: unreadable state", self.name)))
    }

    fn token(&self, a: &Address) -> Result<String> {
        if let Some(t) = self.tokens.lock().unwrap().get(&a.value) {
            return Ok(t.clone());
        }
        Ok(self.state(a)?.token)
    }

    async fn mint(&self, address: &str, password: &str) -> Result<String> {
        let auth = self
            .http
            .post(format!("{}/token", self.api))
            .json_body(&json!({"address": address, "password": password}))
            .json()
            .await?;
        Ok(J::new(self.name, &auth, "/token")
            .at("token")?
            .str()?
            .to_string())
    }

    /// GET with the inbox's bearer token, re-minting once on 401.
    async fn authed_get(&self, a: &Address, path: &str) -> Result<crate::transport::HttpResponse> {
        let url = format!("{}{path}", self.api);
        let resp = self
            .http
            .get(&url)
            .bearer(&self.token(a)?)
            .send_json()
            .await?;
        if resp.status != 401 {
            return Ok(resp);
        }
        let st = self.state(a)?;
        let fresh = self.mint(&st.address, &st.password).await?;
        self.tokens
            .lock()
            .unwrap()
            .insert(a.value.clone(), fresh.clone());
        self.http.get(&url).bearer(&fresh).send_json().await
    }

    /// The rows of a list endpoint: a plain array under the pinned Accept.
    fn rows<'a>(&self, v: &'a Value, where_: &'a str) -> Result<Vec<J<'a>>> {
        J::new(self.name, v, where_).items()
    }
}

fn sender(j: &J<'_>) -> String {
    j.opt("from").map(|f| f.s("address")).unwrap_or_default()
}

#[async_trait]
impl Provider for MailTm {
    fn name(&self) -> &str {
        self.name
    }

    fn caps(&self) -> &Capabilities {
        &self.caps
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let payload = self
            .http
            .get(format!("{}/domains", self.api))
            .json()
            .await?;
        let domains: Vec<String> = self
            .rows(&payload, "/domains")?
            .iter()
            .map(|d| d.at("domain").and_then(|d| d.str().map(String::from)))
            .collect::<Result<_>>()?;
        let domain = match &opts.domain {
            Some(_) => pick_domain(self.name, opts, &domains)?,
            None => domains
                .first()
                .cloned()
                .ok_or_else(|| Error::drift(self.name, "a domain", "[]"))?,
        };
        let value = format!("{}@{domain}", local_or_random(opts));
        let password = random_local() + &random_local();
        let created = self
            .http
            .post(format!("{}/accounts", self.api))
            .json_body(&json!({"address": value, "password": password}))
            .send_json()
            .await?;
        if created.status == 422 && opts.local.is_some() {
            return Err(Error::unsupported(format!(
                "{}: {value} is taken",
                self.name
            )));
        }
        if !created.is_success() {
            return Err(Error::down(
                self.name,
                format!("account creation answered HTTP {}", created.status),
            ));
        }
        let token = self.mint(&value, &password).await?;
        let state = serde_json::to_string(&State {
            address: value.clone(),
            password,
            token,
        })
        .expect("serializes");
        Ok(Address::new(value, self.name).with_state(state))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let resp = self.authed_get(a, "/messages").await?;
        if resp.status >= 400 {
            return Err(Error::down(
                self.name,
                format!("list answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json(self.name)?;
        self.rows(&v, "/messages")?
            .iter()
            .map(|r| {
                Ok(MessageRow::new(r.req_id("id")?, sender(r), r.s("subject"))
                    .at(r.time("createdAt")))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .authed_get(a, &format!("/messages/{}", urlencoding::encode(id)))
            .await?;
        // An expired or deleted message is a 404 with a JSON error body.
        if resp.status == 404 {
            return Err(Error::gone(self.name, id));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                self.name,
                format!("get answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json(self.name)?;
        let m = J::new(self.name, &v, "/messages/{id}");
        // `html` is an array of parts.
        let html = match v.get("html") {
            Some(Value::Array(parts)) => parts.iter().filter_map(Value::as_str).collect::<String>(),
            Some(Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        let text = v.get("text").and_then(Value::as_str).map(String::from);
        Ok(Message::from_bodies(
            m.req_id("id")?,
            sender(&m),
            m.s("subject"),
            m.time("createdAt"),
            html,
            text,
        ))
    }

    async fn delete(&self, a: &Address, id: &str) -> Result<()> {
        let url = format!("{}/messages/{}", self.api, urlencoding::encode(id));
        let resp = self
            .http
            .delete(url)
            .bearer(&self.token(a)?)
            .send_json()
            .await?;
        // 204 on success. 404 means already gone, which is what the caller
        // wanted: deleting twice must not raise.
        match resp.status {
            s if s < 300 || s == 404 => Ok(()),
            s => Err(Error::down(self.name, format!("delete answered HTTP {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mailtm");

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/domains", f("domains.json"))
            .route("/accounts", f("account.json").with_status(201))
            .route("/token", f("token.json"))
            .route("GET https://api.mail.tm/messages?", f("messages_full.json"))
            .route("/messages/6a1f2c9e4b7d", f("message_one.json"))
            .route("DELETE", Reply::status(204))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(MailTm::new(
            "mailtm",
            "https://api.mail.tm",
            CAPS,
            w.transport("mailtm", &CAPS),
        ))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn with_token(token: &str) -> Address {
        let st = State {
            address: "a@uberip.com".into(),
            password: "pw".into(),
            token: token.into(),
        };
        Address::new("a@uberip.com", "mailtm").with_state(serde_json::to_string(&st).unwrap())
    }

    #[tokio::test]
    async fn generate_creates_an_account_then_exchanges_it_for_a_token() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(w.methods(), ["GET", "POST", "POST"]);
        let st: State = serde_json::from_str(a.state.as_deref().unwrap()).unwrap();
        assert_eq!(st.address, a.value);
        assert_eq!(st.token, "fixture.jwt.token");
        assert!(a.value.ends_with("@uberip.com"));
    }

    #[tokio::test]
    async fn envelope_instead_of_array_is_drift() {
        let w = wire().route("/domains", Reply::json(json!({"hydra:member": []})));
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn row_without_id_is_drift_naming_the_field() {
        let w = wire().route(
            "GET https://api.mail.tm/messages?",
            Reply::json(json!([{"subject": "x"}])),
        );
        let err = build(&w)
            .list(&with_token("t"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("\"id\""), "{err}");
    }

    #[tokio::test]
    async fn unserved_domain_is_refused_not_drift() {
        let opts = GenerateOptions {
            domain: Some("nope.test".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn expired_token_is_reminted_once() {
        let w = wire().route_seq(
            "GET https://api.mail.tm/messages?",
            [
                Reply::status(401),
                Reply::json(Fixtures::load(DIR, "messages_full.json")),
            ],
        );
        let p = build(&w);
        let rows = p.list(&with_token("stale")).await.unwrap();
        assert_eq!(rows.len(), 1);
        let last = w.seen().last().unwrap().clone();
        assert_eq!(
            last.header("authorization"),
            Some("Bearer fixture.jwt.token")
        );
    }

    #[tokio::test]
    async fn missing_message_is_gone() {
        let w = wire().route(
            "/messages/zzz",
            Reply::json(json!({"detail": "Not Found"})).with_status(404),
        );
        assert!(matches!(
            build(&w).get(&with_token("t"), "zzz").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn get_reads_html_parts_text_and_links() {
        let m = build(&wire())
            .get(&with_token("t"), "6a1f2c9e4b7d")
            .await
            .unwrap();
        assert_eq!(m.text, "Your code is 448213");
        assert_eq!(m.links, ["https://verify.example.test/go"]);
        assert_eq!(m.sender, "noreply@example.test");
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let w = wire().route("DELETE", Reply::status(404));
        build(&w).delete(&with_token("t"), "x").await.unwrap();
    }
}
