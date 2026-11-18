//! guerrillamail.com, also served unchanged through sharklasers.com, cs.email
//! and dismail.top (listed as sites, never called).
//!
//! The inbox is keyed on a session cookie: on one shared jar a second
//! generate() hands back the first address. So every request runs on a fresh
//! session and the sid_token travels in Address::state instead.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::util::no_custom_local;
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::Transport;

const API: &str = "https://api.guerrillamail.com/ajax.php";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &[
        "guerrillamail.com",
        "sharklasers.com",
        "cs.email",
        "dismail.top",
    ],
    domain_count: 11,
    address_ttl: Some(hours(1)),
    message_ttl: Some(hours(1)),
    needs_state: true,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "guerrillamail",
    caps: CAPS,
    build: |t| Arc::new(GuerrillaMail { http: t }),
};

pub struct GuerrillaMail {
    http: Transport,
}

impl GuerrillaMail {
    async fn call(
        &self,
        function: &str,
        sid: Option<&str>,
        params: &[(&str, &str)],
    ) -> Result<Value> {
        // Every call must identify a client. Neither value is checked.
        let mut req = self
            .http
            .get(API)
            .query("f", function)
            .query("agent", "interloper")
            .query("ip", "127.0.0.1");
        for (k, v) in params {
            req = req.query(*k, *v);
        }
        if let Some(s) = sid {
            req = req.query("sid_token", s);
        }
        let resp = req.send_json().await?;
        if matches!(resp.status, 401 | 403) && sid.is_some() {
            return Err(Error::AddressExpired(
                "guerrillamail: session is no longer valid".into(),
            ));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "guerrillamail",
                format!("{function} answered HTTP {}", resp.status),
            ));
        }
        resp.json("guerrillamail")
    }

    fn sid<'a>(&self, a: &'a Address) -> Result<&'a str> {
        a.state.as_deref().ok_or_else(|| {
            Error::unsupported("guerrillamail needs the sid_token issued by generate()")
        })
    }
}

/// Epoch seconds; the welcome message carries 0, which is not a time.
fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.value().get("mail_timestamp").and_then(parse_value_time)
}

#[async_trait]
impl Provider for GuerrillaMail {
    fn name(&self) -> &str {
        "guerrillamail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        no_custom_local("guerrillamail", opts)?;
        if let Some(d) = &opts.domain {
            return Err(Error::unsupported(format!(
                "guerrillamail picks its own domain, not {d}"
            )));
        }
        let v = self
            .call("get_email_address", None, &[("lang", "en")])
            .await?;
        let j = J::new("guerrillamail", &v, "get_email_address");
        let value = j.at("email_addr")?.str()?.to_string();
        let sid = j.at("sid_token")?.str()?.to_string();
        Ok(Address::new(value, "guerrillamail")
            .with_state(sid)
            .expiring(CAPS.address_ttl))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        // Not check_email: that answers only mail that is new since the last
        // check on this sid, so a second listing comes back empty. Found live;
        // cowbird used check_email and its fixtures could not show it.
        let v = self
            .call("get_email_list", Some(self.sid(a)?), &[("offset", "0")])
            .await?;
        let j = J::new("guerrillamail", &v, "get_email_list");
        j.at("list")?
            .items()?
            .iter()
            .map(|r| {
                Ok(
                    MessageRow::new(r.req_id("mail_id")?, r.s("mail_from"), r.s("mail_subject"))
                        .at(at(r)),
                )
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let v = self
            .call("fetch_email", Some(self.sid(a)?), &[("email_id", id)])
            .await?;
        // What fetch_email answers for a message it no longer has.
        if v == Value::Bool(false) {
            return Err(Error::gone("guerrillamail", id));
        }
        let j = J::new("guerrillamail", &v, "fetch_email");
        let html = j.at("mail_body")?.str().unwrap_or_default().to_string();
        Ok(Message::from_bodies(
            j.req_id("mail_id")?,
            j.s("mail_from"),
            j.s("mail_subject"),
            at(&j),
            html,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/guerrillamail");

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route_seq(
                "f=get_email_address",
                [
                    f("get_email_address.json"),
                    f("get_email_address_second.json"),
                ],
            )
            .route("f=get_email_list", f("check_email.json"))
            .route("f=fetch_email", f("fetch_email.json"))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(GuerrillaMail {
            http: w.transport("guerrillamail", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn state_is_the_sid_and_every_request_is_a_fresh_session() {
        let w = wire();
        let p = build(&w);
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(a.state.as_deref(), Some("fixturesid0000000000000001"));
        assert!(a.expires_at.is_some());
        p.list(&a).await.unwrap();
        assert!(
            w.seen()[1]
                .full_url()
                .contains("sid_token=fixturesid0000000000000001")
        );
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn false_from_fetch_is_gone() {
        let w = wire().route("f=fetch_email", Reply::json(Value::Bool(false)));
        let a = Address::new("x@guerrillamailblock.com", "guerrillamail").with_state("sid");
        assert!(matches!(
            build(&w).get(&a, "41").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn rejected_session_is_expiry_not_an_outage() {
        let w = wire().route("f=get_email_list", Reply::status(403));
        let a = Address::new("x@guerrillamailblock.com", "guerrillamail").with_state("sid");
        assert!(matches!(
            build(&w).list(&a).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn html_body_becomes_text_with_the_code() {
        let a = Address::new("x@guerrillamailblock.com", "guerrillamail").with_state("sid");
        let m = build(&wire()).get(&a, "41").await.unwrap();
        assert!(m.text.contains("482913"), "{}", m.text);
    }
}
