//! mail.re146.dev: an open REST API, described at /api/swagger-json.
//!
//! Any local part at a served domain receives, so generate() only fetches the
//! domain list. The inbox is keyed by md5 of the address, not the address
//! itself, and a message is served as its raw RFC 822 source.
//!
//! The domains churn (several are throwaway registrations), so they are
//! fetched, never hardcoded.

use std::sync::Arc;

use async_trait::async_trait;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::hash::md5_hex;
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const SITE: &str = "https://mail.re146.dev";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mail.re146.dev"],
    domain_count: 13,
    // From the site's own listing; not measured here.
    address_ttl: Some(days(1)),
    message_ttl: Some(hours(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "re146",
    caps: CAPS,
    build: |t| Arc::new(Re146 { http: t }),
};

pub struct Re146 {
    http: Transport,
}

fn key(a: &Address) -> String {
    md5_hex(a.value.to_lowercase().as_bytes())
}

#[async_trait]
impl Provider for Re146 {
    fn name(&self) -> &str {
        "re146"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let v = self.http.get(format!("{SITE}/api/domains")).json().await?;
        let j = J::new("re146", &v, "/api/domains");
        let domains = j
            .items()?
            .iter()
            .map(|d| d.str().map(String::from))
            .collect::<Result<Vec<_>>>()?;
        if domains.is_empty() {
            return Err(j.drift("a non-empty list of domain names"));
        }
        let domain = pick_domain("re146", opts, &domains)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            "re146",
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .http
            .get(format!("{SITE}/api/messages/{}", key(a)))
            .json()
            .await?;
        J::new("re146", &v, "/api/messages")
            .items()?
            .iter()
            .map(|r| {
                Ok(
                    MessageRow::new(r.req_id("id")?, r.s("from"), r.s("subject"))
                        .at(r.time("receivedAt")),
                )
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .http
            .get(format!(
                "{SITE}/storage/{}/{}",
                key(a),
                urlencoding::encode(id)
            ))
            .send()
            .await?;
        if resp.status == 404 {
            return Err(Error::gone("re146", id));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "re146",
                format!("storage answered HTTP {}", resp.status),
            ));
        }
        let mail = crate::mime::parse(&resp.text);
        Ok(Message::from_bodies(
            id,
            mail.sender,
            mail.subject,
            mail.date,
            mail.html.unwrap_or_default(),
            mail.text,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/re146");
    const MESSAGE_ID: &str = "6814ac84-62ad-4619-96a0-2e44d99b7438";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/api/domains", f("domains.json"))
            .route("/api/messages/", f("messages.json"))
            .route(
                "/storage/",
                Reply::text(Fixtures::load_text(DIR, "message.eml")),
            )
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Re146 {
            http: w.transport("re146", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbbe51e1e579@zenvixsmp.xyz", "re146")
    }

    #[tokio::test]
    async fn the_inbox_is_keyed_by_the_md5_of_the_address() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        let k = md5_hex(address().value.as_bytes());
        assert!(
            w.seen()
                .iter()
                .any(|r| r.url.ends_with(&format!("/api/messages/{k}")))
        );
    }

    #[tokio::test]
    async fn a_custom_local_part_and_a_served_domain_are_honoured() {
        let opts = GenerateOptions {
            local: Some("chosen".into()),
            domain: Some("re146.dev".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "chosen@re146.dev");
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
    async fn the_body_is_parsed_out_of_the_raw_source() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.subject.starts_with("JoltMx test email"), "{}", m.subject);
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert!(
            m.text.contains("everything is working as expected"),
            "{}",
            m.text
        );
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/")),
            "{:?}",
            m.links
        );
        assert_eq!(m.received_at, Some("2026-09-24T10:29:37Z".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_404_from_storage_is_gone() {
        let w = wire().route("/storage/", Reply::text("{}").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_body_in_an_unknown_charset_is_read_not_quarantined() {
        // cowbird raised drift here (Python lacked the codec). Interloper
        // decodes lossily instead: one odd message must not quarantine the
        // provider.
        let source = "From: a@b.test\nSubject: x\n\
                      Content-Type: text/html; charset=x-no-such-charset\n\n<p>hi</p>\n";
        let w = wire().route("/storage/", Reply::text(source));
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.text.trim(), "hi");
    }

    #[tokio::test]
    async fn non_utf8_charsets_decode_exactly() {
        // "Привет" as windows-1251 base64 and a KOI8-R encoded word; these
        // degraded to U+FFFD before core read mail with full charset support.
        let source = "From: =?KOI8-R?B?8NLJ18XU?= <a@b.test>\n\
                      Subject: =?ISO-2022-JP?B?GyRCRnxLXDhsGyhC?=\n\
                      Content-Type: text/plain; charset=windows-1251\n\
                      Content-Transfer-Encoding: base64\n\nz/Do4uXy\n";
        let w = wire().route("/storage/", Reply::text(source));
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.sender, "Привет <a@b.test>");
        assert_eq!(m.subject, "日本語");
        assert_eq!(m.text.trim(), "Привет");
    }

    #[tokio::test]
    async fn a_list_that_is_not_an_array_is_drift() {
        let w = wire().route("/api/messages/", Reply::json(json!({"changed": true})));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
