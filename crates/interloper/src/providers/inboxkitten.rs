//! inboxkitten.com — open source (uilicious/inboxkitten), Mailgun-backed.
//!
//! Any local part at the domain receives, so generate() makes no request. A
//! read needs both the Mailgun storage key and its region, so the message id
//! packs them as "region:key".

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::Transport;

const API: &str = "https://inboxkitten.com/api/v1/mail";
const NAME: &str = "inboxkitten";
pub const DOMAIN: &str = "inboxkitten.com";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["inboxkitten.com"],
    domains: &[DOMAIN],
    domain_count: 1,
    // Not measured. Mailgun storage expiry is what makes an old row
    // unreadable; one day is a conservative reading of it.
    message_ttl: Some(days(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(InboxKitten { http: t }),
};

pub struct InboxKitten {
    http: Transport,
}

/// What reading one message produced, before deciding whether a failure was
/// the message or the backend.
enum Read {
    Body(String, Value),
    Expired,
}

impl InboxKitten {
    async fn read(&self, region: &str, key: &str) -> Result<Read> {
        let page = self
            .http
            .get(format!("{API}/getHtml"))
            .query("key", key)
            .query("region", region)
            .send()
            .await?;
        if page.status >= 400 {
            return Ok(Read::Expired);
        }
        let info = self
            .http
            .get(format!("{API}/getInfo"))
            .query("key", key)
            .query("region", region)
            .send_json()
            .await?;
        if info.status >= 400 {
            return Ok(Read::Expired);
        }
        // A 200 with a non-JSON body is upstream drift, not a parse error.
        Ok(Read::Body(page.text, info.json(NAME)?))
    }
}

#[async_trait]
impl Provider for InboxKitten {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain(NAME, opts, &[DOMAIN])?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            NAME,
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .http
            .get(format!("{API}/list"))
            .query("recipient", a.local())
            .json()
            .await?;
        J::new(NAME, &v, "list")
            .items()?
            .iter()
            .map(|r| {
                let storage = r.at("storage")?;
                let region = storage.at("region")?.id()?;
                let key = storage.at("key")?.id()?;
                // `message` is not always an object; a row without readable
                // headers still lists.
                let headers = r
                    .opt("message")
                    .and_then(|m| m.opt("headers"))
                    .filter(|h| h.value().is_object());
                let (from, subject) = headers
                    .map(|h| (h.s("from"), h.s("subject")))
                    .unwrap_or_default();
                Ok(MessageRow::new(format!("{region}:{key}"), from, subject)
                    .at(r.value().get("timestamp").and_then(timestamp)))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let Some((region, key)) = id.split_once(':').filter(|(_, k)| !k.is_empty()) else {
            return Err(Error::unsupported(format!(
                "inboxkitten message ids are region:key, got {id:?}"
            )));
        };
        let read = match self.read(region, key).await {
            Ok(r) => r,
            // A genuine 5xx: if list also fails, propagate that failure. If
            // list answers, the backend is fine and this message is gone.
            Err(Error::ProviderDown { .. }) => Read::Expired,
            Err(e) => return Err(e),
        };
        let (html, info) = match read {
            Read::Body(html, info) => (html, info),
            Read::Expired => {
                // Mailgun storage expires under a list row that still exists,
                // and the read then 404s or 500s.
                self.list(a).await?;
                return Err(Error::gone(NAME, id));
            }
        };
        if !info.is_object() {
            return Err(Error::drift(NAME, "an object from /getInfo", info));
        }
        let j = J::new(NAME, &info, "getInfo");
        let sender = match info.get("emailAddress") {
            Some(Value::String(s)) => s.trim_matches([' ', '<', '>']).to_string(),
            _ => String::new(),
        };
        Ok(Message::from_bodies(
            id,
            sender,
            j.s("subject"),
            None,
            html,
            None,
        ))
    }
}

/// Epoch seconds, possibly fractional.
fn timestamp(v: &Value) -> Option<jiff::Timestamp> {
    match v {
        Value::Number(n) if n.as_i64().is_none() => {
            jiff::Timestamp::from_second(n.as_f64()? as i64).ok()
        }
        other => parse_value_time(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/inboxkitten");
    const MESSAGE_ID: &str = "us-west1:BAABAQfixturekey0001";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/mail/list", f("list.json"))
            .route("/mail/getInfo", f("get_info.json"))
            .route(
                "/mail/getHtml",
                Reply::text(Fixtures::load_text(DIR, "get_html.html")),
            )
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(InboxKitten {
            http: w.transport(NAME, &CAPS),
        })
    }

    fn address() -> Address {
        Address::new(format!("cbfixture@{DOMAIN}"), NAME)
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_makes_no_request_and_honours_a_custom_local_part() {
        let w = wire();
        let opts = GenerateOptions {
            local: Some("chosen".into()),
            ..Default::default()
        };
        let a = build(&w).generate(&opts).await.unwrap();
        assert_eq!(a.value, format!("chosen@{DOMAIN}"));
        assert!(w.seen().is_empty());
    }

    #[tokio::test]
    async fn a_domain_it_does_not_serve_is_refused() {
        let opts = GenerateOptions {
            domain: Some("elsewhere.test".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn the_message_id_carries_region_and_key() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MESSAGE_ID);
        assert!(rows[0].received_at.is_some());
    }

    #[tokio::test]
    async fn a_failed_read_while_the_list_still_answers_is_gone() {
        // Mailgun storage expires under a list row that still exists, and the
        // read then 500s. The backend is up; that one message is gone.
        let w = wire().route("/mail/getHtml", Reply::status(500));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_failed_read_while_the_list_is_down_too_is_the_provider() {
        let w = wire()
            .route("/mail/getHtml", Reply::status(502))
            .route("/mail/list", Reply::status(502));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn an_id_without_a_region_is_refused() {
        assert!(matches!(
            build(&wire()).get(&address(), "no-region").await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_404_from_get_html_with_list_still_answering_is_gone() {
        let w = wire().route("/mail/getHtml", Reply::text("Not Found").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_404_from_get_info_with_list_still_answering_is_gone() {
        let w = wire().route("/mail/getInfo", Reply::text("Not Found").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_404_from_read_while_list_is_down_propagates_the_list_failure() {
        let w = wire()
            .route("/mail/getHtml", Reply::text("Not Found").with_status(404))
            .route("/mail/list", Reply::status(502));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn error_page_is_not_returned_as_message_body() {
        let w = wire().route(
            "/mail/getHtml",
            Reply::text("Error occurred").with_status(500),
        );
        let err = build(&w).get(&address(), MESSAGE_ID).await.unwrap_err();
        assert!(matches!(err, Error::MessageGone { .. }));
        assert!(!err.to_string().contains("Error occurred"));
    }

    #[tokio::test]
    async fn non_json_body_from_get_info_is_drift() {
        let w = wire().route("/mail/getInfo", Reply::text("<html>Error</html>"));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_non_object_message_field_lists_with_blank_headers() {
        let mut rows = Fixtures::load(DIR, "list.json");
        rows[0]["message"] = json!(["not", "a", "dict"]);
        let w = wire().route("/mail/list", Reply::json(rows));
        let rows = build(&w).list(&address()).await.unwrap();
        assert_eq!(rows[0].sender, "");
        assert_eq!(rows[0].subject, "");
    }

    #[tokio::test]
    async fn a_non_string_email_address_is_a_blank_sender() {
        let mut info = Fixtures::load(DIR, "get_info.json");
        info["emailAddress"] = json!(12345);
        let w = wire().route("/mail/getInfo", Reply::json(info));
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.sender, "");
    }

    #[tokio::test]
    async fn row_without_storage_is_drift() {
        let w = wire().route("/mail/list", Reply::json(json!([{"message": {}}])));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
