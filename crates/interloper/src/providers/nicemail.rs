//! nicemail.cc, now MailPorary. The API is Inbucket's REST shape.
//!
//! The page embeds an anonymous JWT in its Nuxt payload; every API call
//! carries it. It is not tied to an address, so it is cached on the provider
//! and re-scraped when the API answers 401.

use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use serde_json::Value;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::{HttpResponse, Transport};

const SITE: &str = "https://nicemail.cc/";
const API: &str = "https://web.mailporary.com/api/v1";

// Recorded from the page's Nuxt payload on 2026-09-11. Refresh from the page,
// not from memory.
const DOMAINS: &[&str] = &[
    "suarj.com",
    "mfxis.com",
    "anogz.com",
    "jgkcr.com",
    "vbgvd.com",
    "wzjpj.com",
];

static JWT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(eyJ[\w-]+\.[\w-]+\.[\w-]+)""#).unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["nicemail.cc"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    message_ttl: Some(days(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "nicemail",
    caps: CAPS,
    build: |t| Arc::new(NiceMail::new(t)),
};

pub struct NiceMail {
    http: Transport,
    token: Mutex<Option<String>>,
}

/// A 404 on the listing is the whole mailbox; on a read, that one message.
enum On404 {
    Mailbox,
    Message(String),
}

fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.time("posix-millis")
}

impl NiceMail {
    fn new(http: Transport) -> Self {
        NiceMail {
            http,
            token: Mutex::new(None),
        }
    }

    async fn refresh_token(&self) -> Result<String> {
        let resp = self.http.get(SITE).send().await?;
        // A WAF or maintenance page has no JWT in it; that must not read as
        // "they removed the Nuxt payload".
        if resp.status >= 400 {
            return Err(Error::down(
                "nicemail",
                format!("{SITE} answered HTTP {}", resp.status),
            ));
        }
        let Some(token) = JWT.captures(&resp.text).map(|c| c[1].to_string()) else {
            return Err(Error::drift(
                "nicemail",
                "a JWT in the page's Nuxt payload",
                crate::error::clip(&resp.text, 200),
            ));
        };
        *self.token.lock().unwrap() = Some(token.clone());
        Ok(token)
    }

    async fn api_get(&self, path: &str, on404: On404) -> Result<Value> {
        let mut resp: Option<HttpResponse> = None;
        for attempt in 0..2 {
            let cached = self.token.lock().unwrap().clone();
            let token = match cached {
                Some(t) if attempt == 0 => t,
                _ => self.refresh_token().await?,
            };
            let r = self
                .http
                .get(format!("{API}{path}"))
                .bearer(&token)
                .header(
                    "X-Request-ID",
                    format!("{:032x}", rand::rng().random::<u128>()),
                )
                .header(
                    "X-Timestamp",
                    jiff::Timestamp::now().as_second().to_string(),
                )
                .send_json()
                .await?;
            let unauthorized = r.status == 401;
            resp = Some(r);
            if !unauthorized {
                break;
            }
            *self.token.lock().unwrap() = None;
        }
        let resp = resp.expect("at least one attempt");
        if resp.status == 404 {
            return Err(match on404 {
                On404::Mailbox => Error::AddressExpired("nicemail: the mailbox is gone".into()),
                On404::Message(id) => Error::gone("nicemail", id),
            });
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "nicemail",
                format!("{path} answered HTTP {}", resp.status),
            ));
        }
        resp.json("nicemail")
    }
}

#[async_trait]
impl Provider for NiceMail {
    fn name(&self) -> &str {
        "nicemail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    /// A catch-all: any local part on a served domain receives, so no request.
    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("nicemail", opts, DOMAINS)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            "nicemail",
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .api_get(&format!("/mailbox/{}", a.value), On404::Mailbox)
            .await?;
        J::new("nicemail", &v, "/mailbox")
            .items()?
            .iter()
            .map(|r| Ok(MessageRow::new(r.req_id("id")?, r.s("from"), r.s("subject")).at(at(r))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let path = format!("/mailbox/{}/{}", a.value, urlencoding::encode(id));
        let v = self.api_get(&path, On404::Message(id.into())).await?;
        let j = J::new("nicemail", &v, "/mailbox/{addr}/{id}");
        if !v.is_object() {
            return Err(j.drift("an object"));
        }
        let (html, text) = match j.opt("body") {
            None => (String::new(), None),
            Some(b) if b.value().is_object() => {
                (b.s("html"), Some(b.s("text")).filter(|t| !t.is_empty()))
            }
            Some(b) => return Err(b.drift("an object")),
        };
        let id = match j.s("id") {
            s if s.is_empty() => id.to_string(),
            s => s,
        };
        Ok(Message::from_bodies(
            id,
            j.s("from"),
            j.s("subject"),
            at(&j),
            html,
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/nicemail");
    const MESSAGE_ID: &str = "20260911T092413-3854";
    const TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3ODkyMDAwMDB9.Zml4dHVyZXNpZ25hdHVyZQ";

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn msg_key() -> String {
        format!("/{MESSAGE_ID}")
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(
                "https://nicemail.cc/",
                Reply::text(Fixtures::load_text(DIR, "home.html")),
            )
            .route("/api/v1/mailbox/", f("mailbox.json"))
            .route(&msg_key(), f("message.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(NiceMail::new(w.transport("nicemail", &CAPS)))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbfixture@suarj.com", "nicemail")
    }

    fn scrapes(w: &Fixtures) -> usize {
        w.seen()
            .iter()
            .filter(|r| r.url.contains("nicemail.cc"))
            .count()
    }

    #[tokio::test]
    async fn the_page_token_is_scraped_once_and_reused() {
        let w = wire();
        let p = build(&w);
        p.list(&address()).await.unwrap();
        p.list(&address()).await.unwrap();
        assert_eq!(scrapes(&w), 1);
        let last = w.seen().last().unwrap().clone();
        assert_eq!(
            last.header("Authorization"),
            Some(format!("Bearer {TOKEN}").as_str())
        );
        assert!(last.header("X-Request-ID").is_some());
        assert!(last.header("X-Timestamp").is_some());
    }

    #[tokio::test]
    async fn a_401_rescrapes_the_token_and_retries_once() {
        let w = wire().route_seq(
            "/api/v1/mailbox/",
            [
                Reply::text("Unauthorized").with_status(401),
                f("mailbox.json"),
            ],
        );
        let rows = build(&w).list(&address()).await.unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, [MESSAGE_ID]);
        assert_eq!(scrapes(&w), 2);
    }

    #[tokio::test]
    async fn a_404_on_read_is_gone() {
        let w = wire().route(&msg_key(), Reply::text("not found").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn the_body_text_is_used_as_sent() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.text, "Your verification code is 482913.");
        assert_eq!(m.links, ["https://example.test/verify?token=abc"]);
    }

    #[tokio::test]
    async fn a_404_on_the_mailbox_expires_the_address_not_the_message() {
        let w = wire().route(
            "/api/v1/mailbox/",
            Reply::text("not found").with_status(404),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_non_object_row_in_the_mailbox_list_is_drift() {
        let w = wire().route("/api/v1/mailbox/", Reply::json(json!(["not-a-row"])));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_403_on_the_token_page_does_not_quarantine() {
        // A WAF or maintenance page on nicemail.cc has no JWT in it; that must
        // not be indistinguishable from "they removed the Nuxt payload".
        let w = wire().route(
            "https://nicemail.cc/",
            Reply::text("<html>blocked</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_truthy_non_object_body_is_drift() {
        let mut message = Fixtures::load(DIR, "message.json");
        message["body"] = json!("not-an-object");
        let w = wire().route(&msg_key(), Reply::json(message));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
