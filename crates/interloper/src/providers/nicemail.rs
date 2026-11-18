//! nicemail.cc, now MailPorary: nicemail.cc 301s to mailporary.com, which
//! serves the same six domains. The provider keeps the name "nicemail" because
//! it keys persisted health.
//!
//! The site is a Nuxt app over a same-origin proxy (`/api/mail/*`) in front of
//! an Inbucket-shaped store. Addresses are made up in the browser: any local
//! part on a served domain receives.
//!
//! The proxy is gated on an `edge_sid` cookie, `<expiry epoch>.<nonce>.<hmac>`,
//! good for an hour. The page hands one to anything that asks for HTML (it is
//! the `Accept: text/html` that matters), and every API answer slides it
//! forward. A request without the token, or without `X-Requested-With:
//! mailporary`, is a plain-text 403.
//!
//! Despite the privacy page ("mailboxes are scoped to a short-lived signed
//! token"), the token is per visitor, not per mailbox: one token reads any
//! address, and a second visitor's token reads the first visitor's mailbox
//! (checked live 2026-11-18). So an expired token costs one page fetch, never
//! the address. generate() fetches one and puts it in `Address::state` so a
//! resumed address starts with a token; the newest token seen is also cached
//! on the provider, and either is replaced from the page on a 403.
//!
//! Every request runs on a fresh session: the shared cookie jar swallows
//! `Set-Cookie`, so the page's token would never reach the adapter.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::{HttpResponse, Req, Transport};

const SITE: &str = "https://mailporary.com/";
const API: &str = "https://mailporary.com/api/mail";
const COOKIE: &str = "edge_sid";

// The page's `emailDomains` payload, 2026-11-18. Refresh from the page, not
// from memory.
const DOMAINS: &[&str] = &[
    "suarj.com",
    "mfxis.com",
    "anogz.com",
    "jgkcr.com",
    "vbgvd.com",
    "wzjpj.com",
];

// The page refuses these local parts (its `blockedUsernames` config).
const BLOCKED: &[&str] = &[
    "admin",
    "guest",
    "info",
    "support",
    "postmaster",
    "webmaster",
    "contact",
    "sales",
    "abuse",
    "root",
    "administrator",
    "manager",
    "hostmaster",
];

/// A token this close to its expiry is replaced before use rather than after
/// a 403.
const EXPIRY_MARGIN_SECS: i64 = 60;

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mailporary.com", "nicemail.cc"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // "Messages and attachments are deleted automatically, and in any case
    // within 12 hours."
    message_ttl: Some(hours(12)),
    delete: true,
    custom_local: true,
    needs_state: true,
    fresh_session: true,
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

#[derive(Clone, Copy)]
enum Verb {
    Get,
    Delete,
}

/// The epoch-seconds expiry at the front of the token, if it has one.
fn expiry(token: &str) -> Option<i64> {
    token.split('.').next()?.parse().ok()
}

fn fresh_enough(token: &str) -> bool {
    match expiry(token) {
        Some(exp) => exp - EXPIRY_MARGIN_SECS > jiff::Timestamp::now().as_second(),
        // An unknown shape is tried; a 403 replaces it.
        None => true,
    }
}

fn at(j: &J<'_>) -> Option<jiff::Timestamp> {
    j.time("date").or_else(|| j.time("posix-millis"))
}

impl NiceMail {
    fn new(http: Transport) -> Self {
        NiceMail {
            http,
            token: Mutex::new(None),
        }
    }

    async fn refresh_token(&self) -> Result<String> {
        let resp = self
            .http
            .get(SITE)
            .header(
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            )
            .send()
            .await?;
        // A WAF or maintenance page has no cookie; that must not read as
        // "they removed the session".
        if resp.status >= 400 {
            return Err(Error::down(
                "nicemail",
                format!("{SITE} answered HTTP {}", resp.status),
            ));
        }
        let Some(token) = resp.cookie(COOKIE) else {
            return Err(Error::drift(
                "nicemail",
                format!("an {COOKIE} cookie from {SITE}"),
                resp.cookies(),
            ));
        };
        *self.token.lock().unwrap() = Some(token.clone());
        Ok(token)
    }

    /// The provider's newest token, else the address's, else a new one.
    async fn token(&self, a: Option<&Address>) -> Result<String> {
        let cached = self.token.lock().unwrap().clone();
        let carried = a.and_then(|a| a.state.clone());
        match cached.into_iter().chain(carried).find(|t| fresh_enough(t)) {
            Some(t) => Ok(t),
            None => self.refresh_token().await,
        }
    }

    fn request(&self, verb: Verb, path: &str, token: &str) -> Req<'_> {
        let url = format!("{API}{path}");
        let req = match verb {
            Verb::Get => self.http.get(url),
            Verb::Delete => self.http.delete(url),
        };
        // What the page's own $fetch sends. A navigation (the impersonated
        // browser's default Sec-Fetch-*) is refused with the same 403 as a
        // missing token.
        req.header("X-Requested-With", "mailporary")
            .header("Referer", SITE)
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Fetch-Mode", "cors")
            .header("Sec-Fetch-Dest", "empty")
            .cookie(COOKIE, token)
    }

    /// One authenticated call. A 403 is the token (expired, or rotated out
    /// by the backend): replace it from the page and retry once.
    async fn call(
        &self,
        verb: Verb,
        a: &Address,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut token = self.token(Some(a)).await?;
        for attempt in 0..2 {
            let mut req = self.request(verb, path, &token);
            for (k, v) in query {
                req = req.query(*k, *v);
            }
            let resp = req.send_json().await?;
            if resp.status != 403 {
                // Every answer slides the session forward; keep the newest.
                if let Some(next) = resp.cookie(COOKIE) {
                    *self.token.lock().unwrap() = Some(next);
                }
                return Ok(resp);
            }
            *self.token.lock().unwrap() = None;
            if attempt == 0 {
                token = self.refresh_token().await?;
            }
        }
        // A token minted a moment ago was refused. The gate may have moved,
        // but a WAF says the same thing; let health decide.
        Err(Error::down(
            "nicemail",
            format!("{path} refused a fresh {COOKIE} with HTTP 403"),
        ))
    }

    fn check(&self, resp: &HttpResponse, path: &str) -> Result<()> {
        if resp.status >= 400 {
            return Err(Error::down(
                "nicemail",
                format!("{path} answered HTTP {}", resp.status),
            ));
        }
        Ok(())
    }

    async fn rows(&self, a: &Address) -> Result<Value> {
        let resp = self
            .call(Verb::Get, a, "/messages", &[("email", &a.value)])
            .await?;
        if resp.status == 404 {
            return Err(Error::AddressExpired(
                "nicemail: the mailbox is gone".into(),
            ));
        }
        self.check(&resp, "/messages")?;
        resp.json("nicemail")
    }

    /// The proxy answers a read or delete of an unknown id with a bare 502
    /// (Cloudflare's "error code: 502"), the same as a real outage. Tell them
    /// apart by asking whether the mailbox still lists the id.
    async fn listed(&self, a: &Address, id: &str) -> Result<bool> {
        let v = self.rows(a).await?;
        let rows = J::new("nicemail", &v, "/messages").items()?;
        Ok(rows.iter().any(|r| r.s("id") == id))
    }

    /// `/message` for `id`; `None` when the message is not there.
    async fn message_call(
        &self,
        verb: Verb,
        a: &Address,
        id: &str,
    ) -> Result<Option<HttpResponse>> {
        let resp = match self
            .call(verb, a, "/message", &[("email", &a.value), ("id", id)])
            .await
        {
            Ok(r) => r,
            Err(e @ Error::ProviderDown { .. }) => {
                return match self.listed(a, id).await {
                    Ok(false) => Ok(None),
                    _ => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        if resp.status == 404 {
            return Ok(None);
        }
        self.check(&resp, "/message")?;
        Ok(Some(resp))
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

    /// A catch-all: any local part on a served domain receives. The only
    /// request is for a token to carry.
    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("nicemail", opts, DOMAINS)?;
        let local = local_or_random(opts);
        if BLOCKED.contains(&local.to_lowercase().as_str()) {
            return Err(Error::unsupported(format!(
                "nicemail refuses the local part {local:?}"
            )));
        }
        let token = self.token(None).await?;
        Ok(Address::new(format!("{local}@{domain}"), "nicemail").with_state(token))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self.rows(a).await?;
        J::new("nicemail", &v, "/messages")
            .items()?
            .iter()
            .map(|r| Ok(MessageRow::new(r.req_id("id")?, r.s("from"), r.s("subject")).at(at(r))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let Some(resp) = self.message_call(Verb::Get, a, id).await? else {
            return Err(Error::gone("nicemail", id));
        };
        let v = resp.json("nicemail")?;
        let j = J::new("nicemail", &v, "/message");
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

    /// Deleting a message that is already gone succeeds.
    async fn delete(&self, a: &Address, id: &str) -> Result<()> {
        self.message_call(Verb::Delete, a, id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/nicemail");
    const MESSAGE_ID: &str = "20260911T092413-3854";
    // Recorded shape: `<expiry>.<32 hex nonce>.<64 hex hmac>`. Far-future
    // expiries so the fixtures never age into a refresh.
    const TOKEN: &str = "4102444800.602a1d0fb1d5a471f8a060c18a0c6ea5.f100fcbc133137d11582e56d476b907e9adf0658154664245a884d4d57c0e9b6";
    const SLID: &str = "4102448400.2da97de177bf39f74f562c0adab477c4.a1c8e91e20f4bedcba321e6f2d0c230151145630b4166335c496816c3afb30cf";

    fn f(n: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, n))
    }

    fn home() -> Reply {
        Reply::text(Fixtures::load_text(DIR, "home.html")).set_cookie(COOKIE, TOKEN)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route("GET https://mailporary.com/?", home())
            .route("/api/mail/messages?", f("mailbox.json"))
            .route("/api/mail/message?", f("message.json"))
            .route(
                "DELETE https://mailporary.com/api/mail/message?",
                Reply::json(json!({})),
            )
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(NiceMail::new(w.transport("nicemail", &CAPS)))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbfixture@suarj.com", "nicemail")
    }

    fn scrapes(w: &Fixtures) -> usize {
        w.seen().iter().filter(|r| r.url == SITE).count()
    }

    fn api_calls(w: &Fixtures) -> Vec<crate::transport::HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| r.url.contains("/api/mail/"))
            .collect()
    }

    #[test]
    fn the_token_expiry_is_read_from_its_prefix() {
        assert_eq!(expiry(TOKEN), Some(4_102_444_800));
        assert!(fresh_enough(TOKEN));
        assert!(!fresh_enough("1795041001.ab.cd"));
        assert!(fresh_enough("opaque"));
    }

    #[tokio::test]
    async fn the_page_token_is_fetched_once_and_sent_as_a_cookie() {
        let w = wire();
        let p = build(&w);
        p.list(&address()).await.unwrap();
        p.list(&address()).await.unwrap();
        assert_eq!(scrapes(&w), 1);
        let page = &w.seen()[0];
        assert!(page.header("Accept").unwrap().starts_with("text/html"));
        let last = api_calls(&w).pop().unwrap();
        assert_eq!(last.header("X-Requested-With"), Some("mailporary"));
        assert_eq!(last.header("Sec-Fetch-Mode"), Some("cors"));
        assert_eq!(last.cookies, [(COOKIE.to_string(), TOKEN.to_string())]);
        assert!(last.full_url().contains("email=cbfixture%40suarj.com"));
    }

    #[tokio::test]
    async fn generate_carries_the_page_token_in_state() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.state.as_deref(), Some(TOKEN));
        assert_eq!(scrapes(&w), 1);
    }

    #[tokio::test]
    async fn a_carried_token_is_used_without_a_page_fetch() {
        let w = wire();
        build(&w).list(&address().with_state(SLID)).await.unwrap();
        assert_eq!(scrapes(&w), 0);
        assert_eq!(api_calls(&w)[0].cookies[0].1, SLID);
    }

    #[tokio::test]
    async fn an_expired_carried_token_costs_a_page_fetch_not_the_address() {
        let w = wire();
        let a = address().with_state("1795041001.ab.cd");
        assert_eq!(build(&w).list(&a).await.unwrap().len(), 1);
        assert_eq!(scrapes(&w), 1);
        assert_eq!(api_calls(&w)[0].cookies[0].1, TOKEN);
    }

    #[tokio::test]
    async fn a_slid_token_from_an_api_answer_replaces_the_cached_one() {
        let w = wire().route(
            "/api/mail/messages?",
            f("mailbox.json").set_cookie(COOKIE, SLID),
        );
        let p = build(&w);
        p.list(&address()).await.unwrap();
        p.list(&address()).await.unwrap();
        let calls = api_calls(&w);
        assert_eq!(calls[0].cookies[0].1, TOKEN);
        assert_eq!(calls[1].cookies[0].1, SLID);
        assert_eq!(scrapes(&w), 1);
    }

    #[tokio::test]
    async fn an_expired_token_is_replaced_before_use() {
        let w = wire();
        let p = NiceMail::new(w.transport("nicemail", &CAPS));
        *p.token.lock().unwrap() = Some("1795041001.ab.cd".into());
        p.list(&address()).await.unwrap();
        assert_eq!(scrapes(&w), 1);
        assert_eq!(api_calls(&w)[0].cookies[0].1, TOKEN);
    }

    #[tokio::test]
    async fn a_403_refetches_the_token_and_retries_once() {
        let w = wire().route_seq(
            "/api/mail/messages?",
            [Reply::text("Forbidden").with_status(403), f("mailbox.json")],
        );
        let rows = build(&w).list(&address()).await.unwrap();
        let ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, [MESSAGE_ID]);
        assert_eq!(scrapes(&w), 2);
    }

    #[tokio::test]
    async fn a_403_on_a_fresh_token_is_down_not_drift() {
        let w = wire().route(
            "/api/mail/messages?",
            Reply::text("Forbidden").with_status(403),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
        assert_eq!(scrapes(&w), 2);
    }

    #[tokio::test]
    async fn a_page_without_the_cookie_is_drift() {
        let w = wire().route(
            "GET https://mailporary.com/?",
            Reply::text(Fixtures::load_text(DIR, "home.html")),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_403_on_the_page_does_not_quarantine() {
        let w = wire().route(
            "GET https://mailporary.com/?",
            Reply::text("<html>blocked</html>").with_status(403),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn the_live_empty_mailbox_lists_nothing() {
        let w = wire().route("/api/mail/messages?", f("mailbox_empty.json"));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_400_json_error_is_down_not_drift() {
        let w = wire().route(
            "/api/mail/messages?",
            f("missing_email.json").with_status(400),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn the_body_text_is_used_as_sent() {
        let w = wire();
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.text, "Your verification code is 482913.");
        assert_eq!(m.links, ["https://example.test/verify?token=abc"]);
        let read = api_calls(&w).pop().unwrap();
        assert!(read.full_url().contains(&format!("id={MESSAGE_ID}")));
    }

    #[tokio::test]
    async fn a_404_on_read_is_gone() {
        let w = wire().route(
            "/api/mail/message?",
            Reply::text("not found").with_status(404),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_502_on_read_of_an_unlisted_id_is_gone() {
        let w = wire()
            .route(
                "/api/mail/message?",
                Reply::text("error code: 502").with_status(502),
            )
            .route("/api/mail/messages?", f("mailbox_empty.json"));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_502_on_read_of_a_listed_id_is_down() {
        let w = wire().route(
            "/api/mail/message?",
            Reply::text("error code: 502").with_status(502),
        );
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_404_on_the_mailbox_expires_the_address_not_the_message() {
        let w = wire().route(
            "/api/mail/messages?",
            Reply::text("not found").with_status(404),
        );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_non_object_row_in_the_mailbox_list_is_drift() {
        let w = wire().route("/api/mail/messages?", Reply::json(json!(["not-a-row"])));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_non_array_mailbox_is_drift() {
        let w = wire().route("/api/mail/messages?", Reply::json(json!({"messages": []})));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_truthy_non_object_body_is_drift() {
        let mut message = Fixtures::load(DIR, "message.json");
        message["body"] = json!("not-an-object");
        let w = wire().route("/api/mail/message?", Reply::json(message));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn delete_sends_a_delete_with_the_id() {
        let w = wire();
        build(&w).delete(&address(), MESSAGE_ID).await.unwrap();
        let del = api_calls(&w).pop().unwrap();
        assert_eq!(del.method.as_str(), "DELETE");
        assert!(del.full_url().contains(&format!("id={MESSAGE_ID}")));
        assert_eq!(del.header("X-Requested-With"), Some("mailporary"));
    }

    #[tokio::test]
    async fn deleting_an_unlisted_id_succeeds() {
        let w = wire()
            .route(
                "DELETE https://mailporary.com/api/mail/message?",
                Reply::text("error code: 502").with_status(502),
            )
            .route("/api/mail/messages?", f("mailbox_empty.json"));
        build(&w).delete(&address(), MESSAGE_ID).await.unwrap();
    }

    #[tokio::test]
    async fn blocked_local_parts_are_refused_not_drift() {
        let opts = GenerateOptions {
            local: Some("admin".into()),
            ..GenerateOptions::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }
}
