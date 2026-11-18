//! 10minutemail.com.
//!
//! The inbox is the JSESSIONID cookie: on a shared cookie jar a second
//! generate() hands back the first address. So each request runs on a fresh
//! session and the cookie travels in Address::state. Messages come back whole
//! in the list call; there is no separate read.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const BASE: &str = "https://10minutemail.com";
const NAME: &str = "10minutemail";
const COOKIE: &str = "JSESSIONID";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["10minutemail.com"],
    domains: &[],
    domain_count: 1,
    address_ttl: Some(minutes(10)),
    message_ttl: Some(minutes(10)),
    needs_state: true,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(TenMinuteMail { http: t }),
};

pub struct TenMinuteMail {
    http: Transport,
}

impl TenMinuteMail {
    /// Every message, bodies included, as JSON.
    async fn rows(&self, a: &Address) -> Result<Value> {
        let session = a.state.as_deref().ok_or_else(|| {
            Error::unsupported("10minutemail needs the session issued by generate()")
        })?;
        let resp = self
            .http
            .get(format!("{BASE}/messages/messagesAfter/0"))
            .cookie(COOKIE, session)
            .send_json()
            .await?;
        // An error page here is a block, not a changed API.
        if resp.status >= 400 {
            return Err(Error::down(
                NAME,
                format!("/messages/messagesAfter/0 answered HTTP {}", resp.status),
            ));
        }
        resp.json(NAME)
    }
}

/// The rows, each required to be an object with an `id`.
fn checked(v: &Value) -> Result<Vec<(String, J<'_>)>> {
    J::new(NAME, v, "messagesAfter")
        .items()?
        .into_iter()
        .map(|r| Ok((r.req_id("id")?, r)))
        .collect()
}

#[async_trait]
impl Provider for TenMinuteMail {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        // cowbird ignored the options; refusing them is what the contract
        // expects of a backend that picks its own address.
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "10minutemail picks both the local part and the domain",
            ));
        }
        let resp = self
            .http
            .get(format!("{BASE}/session/address"))
            .send_json()
            .await?;
        if resp.status >= 400 {
            return Err(Error::down(
                NAME,
                format!("/session/address answered HTTP {}", resp.status),
            ));
        }
        let v = resp.json(NAME)?;
        let Some(session) = resp.cookie(COOKIE).filter(|s| !s.is_empty()) else {
            let names: Vec<String> = resp.cookies().into_iter().map(|(k, _)| k).collect();
            return Err(Error::drift(
                NAME,
                format!("a {COOKIE} cookie from /session/address"),
                names,
            ));
        };
        let value = J::new(NAME, &v, "/session/address")
            .at("address")?
            .str()?
            .to_string();
        Ok(Address::new(value, NAME)
            .with_state(session)
            .expiring(CAPS.address_ttl))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.rows(a).await?;
        Ok(checked(&v)?
            .into_iter()
            .map(|(id, r)| {
                MessageRow::new(id, r.s("sender"), r.s("subject")).at(r.time("sentDate"))
            })
            .collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let v = self.rows(a).await?;
        let Some((_, r)) = checked(&v)?.into_iter().find(|(rid, _)| rid == id) else {
            return Err(Error::gone(NAME, id));
        };
        let text = r
            .value()
            .get("bodyPlainText")
            .and_then(Value::as_str)
            .map(String::from);
        Ok(Message::from_bodies(
            id,
            r.s("sender"),
            r.s("subject"),
            r.time("sentDate"),
            r.s("bodyHtmlContent"),
            text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tenminutemail");

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route_seq(
                "/session/address",
                [
                    f("address.json").set_cookie(COOKIE, "fixture-session-a"),
                    f("address_second.json").set_cookie(COOKIE, "fixture-session-b"),
                ],
            )
            .route("/messages/messagesAfter/0", f("messages.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TenMinuteMail {
            http: w.transport(NAME, &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("cbfixtureaaaa@onldm.net", NAME).with_state("fixture-session-a")
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn it_asks_for_a_fresh_session_per_request() {
        const { assert!(CAPS.fresh_session) };
    }

    #[tokio::test]
    async fn the_session_cookie_is_the_state_and_is_replayed() {
        let w = wire();
        let p = build(&w);
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(a.state.as_deref(), Some("fixture-session-a"));
        p.list(&a).await.unwrap();
        let last = w.seen().last().unwrap().clone();
        assert_eq!(
            last.cookies,
            [(COOKIE.to_string(), "fixture-session-a".to_string())]
        );
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn an_address_without_a_session_cookie_is_drift() {
        let w = wire().route(
            "/session/address",
            Reply::json(Fixtures::load(DIR, "address.json")),
        );
        let err = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SchemaDrift { .. }));
        assert!(err.to_string().contains("JSESSIONID"), "{err}");
    }

    #[tokio::test]
    async fn the_address_expires_in_ten_minutes() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let remaining = a.expires_at.unwrap().duration_since(jiff::Timestamp::now());
        assert!(remaining > jiff::SignedDuration::from_mins(9));
        assert!(remaining <= jiff::SignedDuration::from_mins(10));
    }

    #[tokio::test]
    async fn the_body_is_read_from_the_list_row() {
        let m = build(&wire())
            .get(&address(), "-1999566867-1570421277")
            .await
            .unwrap();
        assert_eq!(m.text, "Your verification code is 482913.");
        assert_eq!(m.links, ["https://example.test/verify?token=abc"]);
    }

    #[tokio::test]
    async fn an_id_no_longer_listed_is_gone() {
        assert!(matches!(
            build(&wire()).get(&address(), "nope").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_403_error_page_on_generate_does_not_quarantine() {
        let w = wire().route(
            "/session/address",
            Reply::text("<html>blocked</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).generate(&GenerateOptions::default()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_403_error_page_on_list_does_not_quarantine() {
        let w = wire().route(
            "/messages/messagesAfter/0",
            Reply::text("<html>blocked</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }
}
