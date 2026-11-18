//! tempmail.plus — the web client's open `/api/mails` endpoints.
//!
//! No account and no token: any local part at a served domain receives, and
//! the inbox is read by the address alone. The optional `epin` guards a box
//! someone has locked with a PIN; a fresh address never has one.
//!
//! The domain list is only in the page markup, not an API, so it is kept here.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const API: &str = "https://tempmail.plus/api/mails";
const NAME: &str = "tempmailplus";

const DOMAINS: &[&str] = &[
    "mailto.plus",
    "fexpost.com",
    "fexbox.org",
    "mailbox.in.ua",
    "rover.info",
    "chitthi.in",
    "fextemp.com",
    "any.pink",
    "merepost.com",
];

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["tempmail.plus"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // Not measured.
    address_ttl: Some(days(1)),
    message_ttl: Some(days(1)),
    delete: true,
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(TempMailPlus { http: t }),
};

pub struct TempMailPlus {
    http: Transport,
}

/// The `Date` header, RFC 2822.
fn date(v: Option<&Value>) -> Option<jiff::Timestamp> {
    let s = v?.as_str()?;
    jiff::fmt::rfc2822::parse(s).ok().map(|z| z.timestamp())
}

#[async_trait]
impl Provider for TempMailPlus {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain(NAME, opts, DOMAINS)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            NAME,
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .http
            .get(API)
            .query("email", &a.value)
            .query("epin", "")
            .query("limit", 20)
            .json()
            .await?;
        J::new(NAME, &v, "mails")
            .at("mail_list")?
            .items()?
            .iter()
            .map(|r| {
                // The listing's "time" is the server's local clock with no
                // zone; get() has the real Date header.
                Ok(MessageRow::new(
                    r.req_id("mail_id")?,
                    r.s("from_mail"),
                    r.s("subject"),
                ))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let v = self
            .http
            .get(format!("{API}/{}", urlencoding::encode(id)))
            .query("email", &a.value)
            .query("epin", "")
            .json()
            .await?;
        let j = J::new(NAME, &v, "mails/{id}");
        if !v.is_object() {
            return Err(j.drift("a message object"));
        }
        // Unknown ids and ids from another box both answer {"result": false}.
        if v.get("result") == Some(&Value::Bool(false)) {
            return Err(Error::gone(NAME, id));
        }
        let sender = Some(j.s("from"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| j.s("from_mail"));
        let text = v.get("text").and_then(Value::as_str).map(String::from);
        Ok(Message::from_bodies(
            id,
            sender,
            j.s("subject"),
            date(v.get("date")),
            j.s("html"),
            text,
        ))
    }

    async fn delete(&self, a: &Address, id: &str) -> Result<()> {
        let v = self
            .http
            .delete(format!("{API}/{}", urlencoding::encode(id)))
            .form([("email", a.value.as_str()), ("epin", "")])
            .json()
            .await?;
        // Deleting a message that is already gone answers false too; the
        // caller wanted it gone, and it is.
        J::new(NAME, &v, "delete").at("result")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, Method};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tempmailplus");
    const MESSAGE_ID: &str = "1880235496";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("GET https://tempmail.plus/api/mails?", f("mails.json"))
            .route(
                &format!("GET https://tempmail.plus/api/mails/{MESSAGE_ID}"),
                f("mail.json"),
            )
            .route(
                "DELETE https://tempmail.plus/api/mails/",
                Reply::json(json!({"result": true})),
            )
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TempMailPlus {
            http: w.transport(NAME, &CAPS),
        })
    }

    fn address() -> Address {
        Address::new("cbdde6e6ee7d@mailto.plus", NAME)
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn the_inbox_is_read_by_address() {
        let w = wire();
        let rows = build(&w).list(&address()).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MESSAGE_ID]
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d345ccdd)");
        assert!(w.seen().iter().any(|r| {
            r.query
                .iter()
                .any(|(k, v)| k == "email" && *v == address().value)
        }));
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(
            "GET https://tempmail.plus/api/mails?",
            Reply::json(Fixtures::load(DIR, "mails_empty.json")),
        );
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_reads_the_body_and_the_utc_date() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert!(m.text.contains("everything is working as expected"));
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
        assert_eq!(m.received_at, Some("2026-09-24T11:56:02Z".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_message_the_box_does_not_hold_is_gone() {
        let w = wire().route(
            &format!("GET https://tempmail.plus/api/mails/{MESSAGE_ID}"),
            Reply::json(Fixtures::load(DIR, "mail_missing.json")),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_list_without_mail_list_is_drift() {
        let w = wire().route(
            "GET https://tempmail.plus/api/mails?",
            Reply::json(json!({"x": 1})),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn delete_sends_the_address_with_the_id() {
        let w = wire();
        build(&w).delete(&address(), MESSAGE_ID).await.unwrap();
        let last = w.seen().last().unwrap().clone();
        assert_eq!(last.method, Method::Delete);
        assert!(last.url.ends_with(&format!("/api/mails/{MESSAGE_ID}")));
        let Body::Form(pairs) = &last.body else {
            panic!("expected a form body, got {:?}", last.body);
        };
        assert!(pairs.contains(&("email".to_string(), address().value)));
    }

    #[tokio::test]
    async fn generate_honours_a_chosen_local_and_domain() {
        let opts = GenerateOptions {
            local: Some("hello".into()),
            domain: Some("fexpost.com".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "hello@fexpost.com");
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
}
