//! xeramail.com — own-domain inboxes, behind a Cloudflare Turnstile.
//!
//! Only creating an address needs a token: `turnstileToken` in the JSON body
//! of /api/emails/generate, one solve per address. The answer carries a
//! `secret`, and every later call is authorized by it alone in
//! `X-Email-Secret`, so the secret is the whole of Address::state. A secret
//! the site no longer accepts (or an address it has dropped) answers 403
//! "Invalid email address or secret".
//!
//! There is no message endpoint to GET (405): the inbox listing already
//! carries each message's `bodyHtml` and `bodyText`, so get() reads it from
//! there.
//!
//! Free tier: xeramail.com and phuturemail.com, a chosen local part is
//! allowed, and addresses live at most 1440 minutes. emailfutureme.com is
//! paid.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_time};
use crate::transport::{HttpResponse, Transport};

const NAME: &str = "xeramail";
const SITE: &str = "https://xeramail.com";
const PAGE: &str = "https://xeramail.com/";
const SITEKEY: &str = "0x4AAAAAACkhKnNaaUhg71Sk";
const DOMAINS: &[&str] = &["xeramail.com", "phuturemail.com"];
const EXPIRY_MINUTES: u64 = 1440; // the free tier's longest

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["xeramail.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    address_ttl: Some(minutes(EXPIRY_MINUTES)),
    message_ttl: Some(days(1)),
    delete: true,
    custom_local: true,
    needs_state: true,
    needs_solver: true,
    max_concurrency: 2,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: NAME,
    caps: CAPS,
    build: |t| Arc::new(Xeramail { http: t }),
};

pub struct Xeramail {
    http: Transport,
}

/// The body as JSON, or its first 200 characters as a string so a drift
/// report shows what came back.
fn body(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.text).unwrap_or_else(|_| Value::String(clip(&resp.text, 200)))
}

impl Xeramail {
    async fn check_local(&self, local: &str, domain: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{SITE}/api/emails/check-availability"))
            .json_body(&json!({"localPart": local, "domain": domain}))
            .send_json()
            .await?;
        let data = body(&resp);
        let Some(available) = data.get("available").and_then(Value::as_bool) else {
            return Err(Error::drift(
                NAME,
                "'available' from check-availability",
                data,
            ));
        };
        if !available {
            let why = data.get("error").and_then(Value::as_str).unwrap_or("");
            return Err(Error::unsupported(format!(
                "{NAME}: {local}@{domain}: {why}"
            )));
        }
        Ok(())
    }

    fn secret<'a>(&self, a: &'a Address) -> Result<&'a str> {
        a.state.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            Error::unsupported(format!("{NAME} needs the secret issued by generate()"))
        })
    }

    async fn messages(&self, a: &Address) -> Result<Value> {
        let resp = self
            .http
            .get(format!(
                "{SITE}/api/emails/{}",
                urlencoding::encode(&a.value)
            ))
            .header("X-Email-Secret", self.secret(a)?)
            .send_json()
            .await?;
        if resp.status == 403 {
            return Err(Error::AddressExpired(format!(
                "{NAME} refused the secret for {}",
                a.value
            )));
        }
        let data = body(&resp);
        let ok = resp.status == 200
            && data
                .pointer("/email/messages")
                .and_then(Value::as_array)
                .is_some_and(|rows| {
                    rows.iter()
                        .all(|r| r.get("id").is_some_and(Value::is_string))
                });
        if !ok {
            return Err(Error::drift(NAME, "'email.messages' rows with 'id'", data));
        }
        Ok(data)
    }
}

fn rows(data: &Value) -> Vec<J<'_>> {
    // Shape checked by `messages`.
    J::new(NAME, &data["email"]["messages"], "email.messages")
        .items()
        .unwrap_or_default()
}

fn row(r: &J<'_>) -> MessageRow {
    MessageRow::new(r.s("id"), r.s("fromAddress"), r.s("subject")).at(r.time("receivedAt"))
}

#[async_trait]
impl Provider for Xeramail {
    fn name(&self) -> &str {
        NAME
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.kind.is_some_and(|k| k != Kind::OwnDomain) {
            return Err(Error::unsupported(format!(
                "{NAME} does not serve {}",
                opts.kind.unwrap()
            )));
        }
        let domain = opts.domain.as_deref().unwrap_or(DOMAINS[0]);
        if !DOMAINS.contains(&domain) {
            return Err(Error::unsupported(format!(
                "{NAME} does not serve {domain} on its free tier"
            )));
        }
        let mut req = json!({"domain": domain, "expirationMinutes": EXPIRY_MINUTES});
        if let Some(local) = &opts.local {
            self.check_local(local, domain).await?;
            req["localPart"] = json!(local);
        }
        let token = self
            .http
            .turnstile_solver()?
            .turnstile(PAGE, SITEKEY, None, None)
            .await?;
        req["turnstileToken"] = json!(token);

        let resp = self
            .http
            .post(format!("{SITE}/api/emails/generate"))
            .json_body(&req)
            .send_json()
            .await?;
        let data = body(&resp);
        let error = data.get("error").map(|e| match e {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
        if resp.status == 403
            && error
                .as_deref()
                .is_some_and(|e| e.to_lowercase().contains("captcha"))
        {
            // A refused token is the solver's fault, not a change in the API.
            return Err(Error::SolverUnavailable(format!(
                "{NAME} refused the Turnstile token: {}",
                error.unwrap_or_default()
            )));
        }
        let email = data.get("email");
        let address = email
            .and_then(|e| e.get("address"))
            .and_then(Value::as_str)
            .filter(|a| a.contains('@'));
        let secret = email
            .and_then(|e| e.get("secret"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        let (Some(address), Some(secret), true) = (address, secret, resp.status < 300) else {
            return Err(Error::drift(
                NAME,
                "'email.address' and 'email.secret'",
                data,
            ));
        };
        let mut a = Address::new(address, NAME).with_state(secret);
        a.expires_at = email
            .and_then(|e| e.get("expiresAt"))
            .and_then(Value::as_str)
            .and_then(parse_time);
        Ok(a)
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let data = self.messages(a).await?;
        Ok(rows(&data).iter().map(row).collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let data = self.messages(a).await?;
        let rows = rows(&data);
        let raw = rows
            .iter()
            .find(|r| r.s("id") == id)
            .ok_or_else(|| Error::gone(NAME, id))?;
        let head = row(raw);
        let html = raw.s("bodyHtml");
        // The HTML wins when present; the text body only stands in for it.
        let text = html.is_empty().then(|| raw.s("bodyText"));
        Ok(Message::from_bodies(
            id,
            head.sender,
            head.subject,
            head.received_at,
            html,
            text,
        ))
    }

    async fn delete(&self, a: &Address, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{SITE}/api/messages/{}", urlencoding::encode(id)))
            .header("X-Email-Secret", self.secret(a)?)
            .send_json()
            .await?;
        if resp.status == 404 {
            return Err(Error::gone(NAME, id));
        }
        if resp.status >= 300 {
            return Err(Error::drift(NAME, "2xx from delete", body(&resp)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::Solver;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::Body;

    // Recorded, with secrets replaced: every fixture except
    // synthetic_inbox.json. Its envelope is the recorded inbox; the message
    // row is synthetic, shaped from the fields the site's own JS reads (id,
    // fromAddress, subject, bodyHtml, bodyText, receivedAt), because
    // xeramail's test send never arrived.
    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/xeramail");
    const VALUE: &str = "glowing.room403@xeramail.com";
    const SECRET: &str = "SECRET-PLACEHOLDER";
    const MID: &str = "7c1e0f4a-2b3d-4e5f-8a9b-0c1d2e3f4a5b";

    const GENERATE: &str = "POST https://xeramail.com/api/emails/generate";
    const AVAILABILITY: &str = "POST https://xeramail.com/api/emails/check-availability";
    const INBOX: &str = "GET https://xeramail.com/api/emails/";
    const DELETE: &str = "DELETE https://xeramail.com/api/messages/";

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn wire() -> Arc<Fixtures> {
        let first = load("generate.json");
        let mut second = first.clone();
        second["email"]["address"] = json!("other2x@xeramail.com");
        Fixtures::new()
            // Two answers so the contract's two generates get two addresses.
            .route_seq(GENERATE, [Reply::json(first), Reply::json(second)])
            .route(AVAILABILITY, Reply::json(load("local_available.json")))
            .route(INBOX, Reply::json(load("synthetic_inbox.json")))
            .route(DELETE, Reply::json(json!({"success": true})))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport(NAME, &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(Xeramail { http: t })
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new(VALUE, NAME).with_state(SECRET)
    }

    fn sent(w: &Fixtures, prefix: &str) -> Vec<crate::transport::HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url.starts_with(url))
            .collect()
    }

    fn json_of(r: &crate::transport::HttpRequest) -> Value {
        match &r.body {
            Body::Json(v) => v.clone(),
            other => panic!("not a JSON body: {other:?}"),
        }
    }

    #[tokio::test]
    async fn generate_sends_the_turnstile_token_in_the_body() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let solves = s.seen();
        assert_eq!(solves.len(), 1);
        let ask = json_of(&solves[0]);
        assert_eq!(ask["url"], PAGE);
        assert_eq!(ask["sitekey"], SITEKEY);
        assert_eq!(
            json_of(&sent(&w, GENERATE)[0]),
            json!({"domain": "xeramail.com", "expirationMinutes": 1440, "turnstileToken": "fake-token"})
        );
    }

    #[tokio::test]
    async fn generate_keeps_the_secret_as_state_and_the_expiry() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, VALUE);
        assert_eq!(a.state.as_deref(), Some(SECRET));
        assert_eq!(a.expires_at, Some("2026-09-26T02:19:36Z".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_chosen_local_part_and_domain_are_checked_then_asked_for() {
        let w = wire();
        let opts = GenerateOptions {
            local: Some("cbtzq91x7".into()),
            domain: Some("phuturemail.com".into()),
            ..Default::default()
        };
        build(&w).generate(&opts).await.unwrap();
        assert_eq!(
            json_of(&sent(&w, AVAILABILITY)[0]),
            json!({"localPart": "cbtzq91x7", "domain": "phuturemail.com"})
        );
        let body = json_of(&sent(&w, GENERATE)[0]);
        assert_eq!(body["localPart"], "cbtzq91x7");
        assert_eq!(body["domain"], "phuturemail.com");
    }

    #[tokio::test]
    async fn a_reserved_local_part_is_refused_before_a_solve() {
        let w = wire().route(
            AVAILABILITY,
            Reply::json(load("local_reserved.json")).with_status(400),
        );
        let s = solver_wire();
        let opts = GenerateOptions {
            local: Some("admin".into()),
            ..Default::default()
        };
        let err = build_with(&w, Some(&s)).generate(&opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::NotSupported(m) if m.contains("reserved")),
            "{err}"
        );
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn what_the_free_tier_cannot_do_is_refused_before_a_solve() {
        for opts in [
            GenerateOptions {
                domain: Some("emailfutureme.com".into()),
                ..Default::default()
            },
            GenerateOptions {
                kind: Some(Kind::GmailAlias),
                ..Default::default()
            },
        ] {
            let s = solver_wire();
            let r = build_with(&wire(), Some(&s)).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}");
            assert!(s.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let w = wire();
        let r = build_with(&w, None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, GENERATE).is_empty());
    }

    #[tokio::test]
    async fn a_refused_token_is_the_solvers_fault_not_drift() {
        let w = wire().route(
            GENERATE,
            Reply::json(load("captcha_failed.json")).with_status(403),
        );
        let r = build(&w).generate(&GenerateOptions::default()).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn solver_unavailable_propagates_before_any_request() {
        let w = wire();
        let s = Fixtures::new().route("/turnstile", Reply::status(500));
        let r = build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, GENERATE).is_empty());
    }

    #[tokio::test]
    async fn list_sends_the_secret_and_costs_no_solve() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s)).list(&address()).await.unwrap();
        assert!(s.seen().is_empty());
        let gets = sent(&w, "GET https://");
        assert_eq!(gets.len(), 1);
        assert_eq!(
            gets[0].url,
            "https://xeramail.com/api/emails/glowing.room403%40xeramail.com"
        );
        assert_eq!(gets[0].header("X-Email-Secret"), Some(SECRET));
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MID);
        assert_eq!(rows[0].sender, "test@xeramail.com");
        assert_eq!(rows[0].subject, "Your Email Test is Successful!");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T02:20:05Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(INBOX, Reply::json(load("inbox_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_reads_the_body_from_the_listing_without_a_solve() {
        let (w, s) = (wire(), solver_wire());
        let m = build_with(&w, Some(&s)).get(&address(), MID).await.unwrap();
        assert_eq!(m.id, MID);
        assert!(m.html.starts_with("<div>"));
        assert!(m.text.contains("working successfully"));
        assert_eq!(m.links, ["https://xeramail.com/"]);
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn get_falls_back_to_the_text_body() {
        let mut inbox = load("synthetic_inbox.json");
        inbox["email"]["messages"][0]
            .as_object_mut()
            .unwrap()
            .remove("bodyHtml");
        let w = wire().route(INBOX, Reply::json(inbox));
        let m = build(&w).get(&address(), MID).await.unwrap();
        assert_eq!(m.text, "Your email address is working successfully.");
    }

    #[tokio::test]
    async fn a_message_not_in_the_listing_is_gone() {
        let r = build(&wire())
            .get(&address(), "00000000-0000-0000-0000-000000000000")
            .await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn a_refused_secret_is_an_expired_address() {
        let w = wire().route(INBOX, Reply::json(load("bad_secret.json")).with_status(403));
        let r = build(&w).list(&address()).await;
        assert!(matches!(r, Err(Error::AddressExpired(_))), "{r:?}");
    }

    #[tokio::test]
    async fn list_without_state_is_not_supported() {
        let r = build(&wire()).list(&Address::new(VALUE, NAME)).await;
        assert!(matches!(r, Err(Error::NotSupported(_))), "{r:?}");
    }

    #[tokio::test]
    async fn delete_sends_the_secret() {
        let w = wire();
        build(&w).delete(&address(), MID).await.unwrap();
        let dels = sent(&w, DELETE);
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0].header("X-Email-Secret"), Some(SECRET));
        assert!(dels[0].url.ends_with(&format!("/api/messages/{MID}")));
    }

    #[tokio::test]
    async fn deleting_a_missing_message_is_gone() {
        let w = wire().route(
            DELETE,
            Reply::json(load("message_not_found.json")).with_status(404),
        );
        let r = build(&w).delete(&address(), MID).await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn a_malformed_answer_is_drift() {
        let cases = [
            (GENERATE, Reply::json(json!({"email": {"address": VALUE}}))),
            (
                GENERATE,
                Reply::json(json!({"error": "Captcha token required"})).with_status(400),
            ),
            (INBOX, Reply::json(json!({"x": 1}))),
            (
                INBOX,
                Reply::json(json!({"email": {"messages": [{"subject": "no id"}]}})),
            ),
            (
                INBOX,
                Reply::json(json!({"error": "Secret is required"})).with_status(401),
            ),
            (DELETE, Reply::json(json!({"error": "?"})).with_status(400)),
        ];
        for (route, answer) in cases {
            let p = build(&wire().route(route, answer));
            let r = match route {
                GENERATE => p.generate(&GenerateOptions::default()).await.map(|_| ()),
                DELETE => p.delete(&address(), MID).await,
                _ => p.list(&address()).await.map(|_| ()),
            };
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{route}: {r:?}"
            );
        }
    }
}
