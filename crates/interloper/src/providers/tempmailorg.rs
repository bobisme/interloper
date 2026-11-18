//! temp-mail.org.
//!
//! 10minemail.com is the same backend: its bundle decodes to
//! web2.10minemail.com, which serves the same routes and accepts the same
//! tokens. The per-IP creation limit (10 mailboxes, window unknown) is shared
//! between the two.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::util::no_custom_local;
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://web2.temp-mail.org";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["temp-mail.org", "10minemail.com"],
    domain_count: 1,
    message_ttl: Some(hours(2)),
    needs_state: true,
    max_concurrency: 2,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "tempmailorg",
    caps: CAPS,
    build: |t| Arc::new(TempMailOrg { http: t }),
};

pub struct TempMailOrg {
    http: Transport,
}

/// What a 410 means depends on what was asked for: on the listing it is the
/// whole mailbox, on a single read it is that one message.
enum On410 {
    Mailbox,
    Message(String),
}

impl TempMailOrg {
    fn token<'a>(&self, a: &'a Address) -> Result<&'a str> {
        a.state
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::unsupported("tempmailorg needs the token issued by generate()"))
    }

    async fn authed_get(&self, path: &str, a: &Address, on410: On410) -> Result<Value> {
        let resp = self
            .http
            .get(format!("{API}{path}"))
            .bearer(self.token(a)?)
            .send_json()
            .await?;
        // The site's own client treats 401 as "make a new mailbox".
        if resp.status == 401 {
            return Err(Error::AddressExpired(format!(
                "tempmailorg: {} is no longer valid",
                a.value
            )));
        }
        if resp.status == 410 {
            return Err(match on410 {
                On410::Mailbox => Error::AddressExpired("tempmailorg: the mailbox is gone".into()),
                On410::Message(id) => Error::gone("tempmailorg", id),
            });
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "tempmailorg",
                format!("{path} answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json("tempmailorg")?;
        if !v.is_object() {
            return Err(Error::drift(
                "tempmailorg",
                format!("an object from {path}"),
                v,
            ));
        }
        Ok(v)
    }
}

fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.time("receivedAt")
}

#[async_trait]
impl Provider for TempMailOrg {
    fn name(&self) -> &str {
        "tempmailorg"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        no_custom_local("tempmailorg", opts)?;
        if let Some(d) = &opts.domain {
            return Err(Error::unsupported(format!(
                "tempmailorg picks its own domain, not {d}"
            )));
        }
        let resp = self.http.post(format!("{API}/mailbox")).send_json().await?;
        // The per-IP mailbox limit can come back as an HTML error page; that
        // must not reach the JSON parser and quarantine a healthy provider.
        if resp.status >= 400 {
            return Err(Error::down(
                "tempmailorg",
                format!("/mailbox answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json("tempmailorg")?;
        let j = J::new("tempmailorg", &v, "/mailbox");
        let token = j.at("token")?.str()?.to_string();
        let mailbox = j.at("mailbox")?.str()?.to_string();
        Ok(Address::new(mailbox, "tempmailorg").with_state(token))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.authed_get("/messages", a, On410::Mailbox).await?;
        J::new("tempmailorg", &v, "/messages")
            .at("messages")?
            .items()?
            .iter()
            .map(|r| Ok(MessageRow::new(r.req_id("_id")?, r.s("from"), r.s("subject")).at(at(r))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let path = format!("/messages/{}", urlencoding::encode(id));
        let v = self
            .authed_get(&path, a, On410::Message(id.to_string()))
            .await?;
        let j = J::new("tempmailorg", &v, "/messages/{id}");
        let id = match j.s("_id") {
            s if s.is_empty() => id.to_string(),
            s => s,
        };
        Ok(Message::from_bodies(
            id,
            j.s("from"),
            j.s("subject"),
            at(&j),
            j.s("bodyHtml"),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tempmailorg");
    const MESSAGE_ID: &str = "6aa3cf8112e593e42adf0df7";

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route_seq("/mailbox", [f("mailbox.json"), f("mailbox_second.json")])
            .route("/messages", f("messages.json"))
            .route(&format!("/messages/{MESSAGE_ID}"), f("message.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TempMailOrg {
            http: w.transport("tempmailorg", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbfixturea@daugr.com", "tempmailorg").with_state("fixture.token.a")
    }

    #[tokio::test]
    async fn the_token_is_the_state_and_goes_out_as_a_bearer() {
        let w = wire();
        let p = build(&w);
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(a.state.as_deref(), Some("fixture.token.a"));
        p.list(&a).await.unwrap();
        assert_eq!(
            w.seen().last().unwrap().header("Authorization"),
            Some("Bearer fixture.token.a")
        );
    }

    #[tokio::test]
    async fn a_410_on_read_is_gone() {
        let w = wire().route(
            &format!("/messages/{MESSAGE_ID}"),
            Reply::json(json!({"errorName": "GoneException"})).with_status(410),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_401_means_the_mailbox_is_gone() {
        // The site's own client treats 401 as "make a new mailbox".
        let w = wire().route(
            "/messages",
            Reply::json(json!({"errorName": "UnauthorizedException"})).with_status(401),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn the_html_body_is_turned_into_text() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.text.contains("482913"), "{}", m.text);
        assert_eq!(m.links, ["https://example.test/verify?token=abc"]);
    }

    #[tokio::test]
    async fn a_410_on_list_is_address_expired() {
        // 410 from /messages means the mailbox is gone, not a single message.
        let w = wire().route(
            "/messages",
            Reply::json(json!({"errorName": "GoneException"})).with_status(410),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_403_on_generate_does_not_quarantine() {
        // The per-IP mailbox limit can come back as an HTML error page; that
        // must not reach the JSON parser and quarantine a healthy provider.
        let w = wire().route(
            "/mailbox",
            Reply::text("<html>Too many mailboxes</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_non_object_row_in_messages_is_drift() {
        let bad = json!({"mailbox": "cbfixturea@daugr.com", "messages": ["not a dict"]});
        let w = wire().route("/messages", Reply::json(bad));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
