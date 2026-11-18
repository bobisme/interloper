//! tempmailo.com, an ASP.NET app driven by its own page script.
//!
//! The home page carries an antiforgery token in a hidden input and sets the
//! cookie it is bound to; every API call sends the token as the
//! `RequestVerificationToken` header with that cookie, or gets a bare 400.
//!
//! GET /changemail mints an address and answers it as plain text. POST / with
//! {"mail": address} lists the inbox, and the address is the only key: any
//! antiforgery pair reads any address, and an address the site never issued
//! answers [] like an empty one. Inboxes are public to anyone who knows the
//! address, so there is no state to carry.
//!
//! Rows carry the body, text and HTML both, so get() reads the listing.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use regex::Regex;
use serde_json::{Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_time};
use crate::transport::{Req, Transport};

const BASE: &str = "https://tempmailo.com";
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"name="__RequestVerificationToken" type="hidden" value="([^"]+)""#).unwrap()
});
static ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[^@\s"]+@[^@\s"]+$"#).unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["tempmailo.com"],
    // Sampled 20 addresses: forexzig.com, denipl.com, fxzig.com, denipl.net.
    // Not declared, since the sample may be short of the pool.
    domains: &[],
    domain_count: 4,
    address_ttl: None,
    // "We keep the received emails for two days from the date of receipt."
    message_ttl: Some(days(2)),
    // About 20 new addresses per IP before "Rate limit exceeded!".
    max_concurrency: 2,
    // The site's own page polls every 16 seconds.
    poll_interval: Duration::from_secs(15),
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "tempmailo",
    caps: CAPS,
    build: |t| Arc::new(TempMailo { http: t }),
};

pub struct TempMailo {
    http: Transport,
}

impl TempMailo {
    /// One API call carrying a fresh token and the cookie it is bound to.
    async fn call<'a>(&'a self, req: impl FnOnce(&'a Transport) -> Req<'a>) -> Result<String> {
        let home = self.http.get(format!("{BASE}/")).send().await?;
        // An error page (an origin or WAF refusing this IP) is an outage,
        // not a new page shape: it must not quarantine the adapter.
        if !home.is_success() {
            return Err(Error::down(
                "tempmailo",
                format!("/ answered HTTP {}", home.status),
            ));
        }
        let token = TOKEN
            .captures(&home.text)
            .map(|c| c[1].to_string())
            .ok_or_else(|| {
                Error::drift(
                    "tempmailo",
                    "an antiforgery token from /",
                    clip(&home.text, 200),
                )
            })?;
        let mut r = req(&self.http).header("RequestVerificationToken", token);
        // The site sets its antiforgery cookie once; after that the
        // transport's cookie jar carries it and the home page sends no
        // Set-Cookie.
        for (k, v) in home.cookies() {
            r = r.cookie(k, v);
        }
        let resp = r.send_json().await?;
        if resp.status == 400 && resp.text.to_lowercase().contains("rate limit") {
            return Err(Error::RateLimited {
                provider: "tempmailo".into(),
                retry_after: None,
            });
        }
        if resp.status != 200 {
            return Err(Error::drift(
                "tempmailo",
                "HTTP 200",
                format!("HTTP {}: {}", resp.status, clip(&resp.text, 200)),
            ));
        }
        Ok(resp.text)
    }

    async fn rows(&self, a: &Address) -> Result<Vec<Value>> {
        let text = self
            .call(|h| {
                h.post(format!("{BASE}/"))
                    .json_body(&json!({"mail": a.value}))
            })
            .await?;
        let rows: Value = serde_json::from_str(&text)
            .map_err(|_| Error::drift("tempmailo", "a JSON body", clip(&text, 200)))?;
        let ok = rows
            .as_array()
            .is_some_and(|rs| rs.iter().all(|r| r.get("id").is_some_and(Value::is_string)));
        if !ok {
            return Err(Error::drift(
                "tempmailo",
                "an array of rows with 'id'",
                clip(&rows.to_string(), 200),
            ));
        }
        Ok(rows.as_array().cloned().unwrap_or_default())
    }
}

fn row(r: &J<'_>) -> Result<MessageRow> {
    let received = match r.opt("date") {
        None => None,
        Some(d) => Some(
            d.str()
                .ok()
                .and_then(parse_time)
                .ok_or_else(|| d.drift("an ISO 'date'"))?,
        ),
    };
    Ok(MessageRow::new(r.at("id")?.str()?, r.s("from"), r.s("subject")).at(received))
}

/// A body field: absent or null is "", a string is itself, anything else is
/// drift.
fn body(r: &J<'_>, key: &str) -> Result<String> {
    match r.opt(key) {
        None => Ok(String::new()),
        Some(v) => Ok(v
            .str()
            .map_err(|_| r.drift("'html' and 'text' as strings"))?
            .to_string()),
    }
}

#[async_trait]
impl Provider for TempMailo {
    fn name(&self) -> &str {
        "tempmailo"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() || opts.domain.is_some() {
            return Err(Error::unsupported(
                "tempmailo picks both the local part and the domain",
            ));
        }
        let r: f64 = rand::rng().random();
        let text = self
            .call(|h| h.get(format!("{BASE}/changemail")).query("_r", r))
            .await?;
        let mut value = text.trim().to_string();
        // Asked for JSON, the site answers the address as a JSON string.
        if value.starts_with('"') {
            value = serde_json::from_str::<String>(&value)
                .map_err(|_| Error::drift("tempmailo", "an address", clip(&value, 200)))?;
        }
        if !ADDRESS.is_match(&value) {
            return Err(Error::drift(
                "tempmailo",
                "an address from /changemail",
                clip(&value, 200),
            ));
        }
        Ok(Address::new(value, "tempmailo"))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let rows = self.rows(a).await?;
        rows.iter()
            .enumerate()
            .map(|(i, r)| row(&J::new("tempmailo", r, &format!("rows[{i}]"))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let rows = self.rows(a).await?;
        let Some(raw) = rows.iter().find(|r| r["id"].as_str() == Some(id)) else {
            return Err(Error::gone("tempmailo", id));
        };
        let j = J::new("tempmailo", raw, "row");
        let (html, text) = (body(&j, "html")?, body(&j, "text")?);
        let r = row(&j)?;
        Ok(Message::from_bodies(
            id,
            r.sender,
            r.subject,
            r.received_at,
            html,
            Some(text),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/tempmailo");
    const COOKIE: (&str, &str) = (
        ".AspNetCore.Antiforgery.dXyz_uFU2og",
        "fixture-antiforgery-cookie",
    );
    const MESSAGE_ID: &str = "6ab62f1259324493fbc1ec8e";
    const FULL: &str = "lypibabi@forexzig.com";
    const EMPTY: &str = "cukiluzu@denipl.com";
    const HOME: &str = "GET https://tempmailo.com/?";
    const CHANGEMAIL: &str = "GET https://tempmailo.com/changemail";

    /// The listing route for an address; overrides use FULL's so they outrank
    /// the shorter keys.
    fn list_key(address: &str) -> String {
        format!(r#"POST {BASE}/? {{"mail":"{address}"}}"#)
    }

    fn home() -> String {
        Fixtures::load_text(DIR, "home.html")
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(HOME, Reply::text(home()).set_cookie(COOKIE.0, COOKIE.1))
            .route_seq(CHANGEMAIL, [Reply::text(FULL), Reply::text(EMPTY)])
            .route(
                &list_key(FULL),
                Reply::json(Fixtures::load(DIR, "messages.json")),
            )
            .route(&list_key(EMPTY), Reply::json(json!([])))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(TempMailo {
            http: w.transport("tempmailo", &CAPS),
        })
    }

    fn with(key: &str, reply: Reply) -> Arc<dyn Provider> {
        build(&wire().route(key, reply))
    }

    fn full() -> Address {
        Address::new(FULL, "tempmailo")
    }

    fn calls(w: &Fixtures, method: &str, path: &str) -> Vec<HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url == format!("{BASE}{path}"))
            .collect()
    }

    fn cookie_pair() -> Vec<(String, String)> {
        vec![(COOKIE.0.to_string(), COOKIE.1.to_string())]
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn the_inbox_is_keyed_by_the_address_alone() {
        // Any antiforgery pair reads any address, so there is no state to carry.
        const { assert!(!CAPS.needs_state) };
        const { assert!(!CAPS.fresh_session) };
    }

    #[tokio::test]
    async fn generate_replays_the_page_token_and_its_cookie() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, FULL);
        let change = calls(&w, "GET", "/changemail");
        assert_eq!(change.len(), 1);
        assert_eq!(
            change[0].header("RequestVerificationToken"),
            Some("fixture-antiforgery-token")
        );
        assert_eq!(change[0].cookies, cookie_pair());
    }

    #[tokio::test]
    async fn list_replays_the_page_token_and_its_cookie() {
        let w = wire();
        build(&w).list(&full()).await.unwrap();
        let post = calls(&w, "POST", "/");
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].body, Body::Json(json!({"mail": FULL})));
        assert_eq!(
            post[0].header("RequestVerificationToken"),
            Some("fixture-antiforgery-token")
        );
        assert_eq!(post[0].cookies, cookie_pair());
    }

    #[tokio::test]
    async fn a_chosen_address_is_refused() {
        // The client's ?tmail= is ignored upstream.
        for opts in [
            GenerateOptions {
                local: Some("me".into()),
                ..Default::default()
            },
            GenerateOptions {
                domain: Some("fxzig.com".into()),
                ..Default::default()
            },
        ] {
            assert!(matches!(
                build(&wire()).generate(&opts).await,
                Err(Error::NotSupported(_))
            ));
        }
    }

    #[tokio::test]
    async fn the_rate_limit_answer_is_rate_limited() {
        // Upstream says 400 "Rate limit exceeded!" after ~20 addresses per IP.
        let p = with(
            CHANGEMAIL,
            Reply::text("Rate limit exceeded!").with_status(400),
        );
        assert!(matches!(
            p.generate(&GenerateOptions::default()).await,
            Err(Error::RateLimited { .. })
        ));
    }

    #[tokio::test]
    async fn a_generate_answer_that_is_not_an_address_is_drift() {
        for answer in ["", "<html>oops</html>", "not an address", "a@b@c"] {
            let got = with(CHANGEMAIL, Reply::text(answer))
                .generate(&GenerateOptions::default())
                .await;
            assert!(
                matches!(got, Err(Error::SchemaDrift { .. })),
                "{answer}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_page_without_a_token_is_drift() {
        let p = with(
            HOME,
            Reply::text("<html></html>").set_cookie(COOKIE.0, COOKIE.1),
        );
        assert!(matches!(
            p.generate(&GenerateOptions::default()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_page_that_sets_no_new_cookie_still_reads_the_inbox() {
        // The transport keeps one cookie jar per provider, and the site sets
        // the antiforgery cookie only once: from the second call on, the home
        // page answers without Set-Cookie and the jar supplies it.
        let rows = with(HOME, Reply::text(home())).list(&full()).await.unwrap();
        assert!(!rows.is_empty());
    }

    #[tokio::test]
    async fn a_refused_token_is_drift() {
        // A token without its cookie gets a bare 400.
        let p = with(&list_key(FULL), Reply::status(400));
        assert!(matches!(
            p.list(&full()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&full()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MESSAGE_ID);
        assert_eq!(
            rows[0].sender,
            r#""JoltMx Delivery Test" <test@sendtest.joltmx.com>"#
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d7a7d9a6)");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T08:21:36.798Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let rows = build(&wire())
            .list(&Address::new(EMPTY, "tempmailo"))
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn a_listing_it_does_not_recognise_is_drift() {
        for answer in [
            "{}",
            "<html>error</html>",
            r#"[{"subject": "no id"}]"#,
            r#"["row"]"#,
            r#"[{"id": "1", "date": "soon"}]"#,
        ] {
            let got = with(&list_key(FULL), Reply::text(answer))
                .list(&full())
                .await;
            assert!(
                matches!(got, Err(Error::SchemaDrift { .. })),
                "{answer}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn get_takes_the_body_from_the_row() {
        let m = build(&wire()).get(&full(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.id, MESSAGE_ID);
        assert!(m.text.starts_with("This is a test email from JoltMx."));
        assert!(m.html.contains("<h2"));
        assert!(m.links.iter().any(|l| l == "https://joltmx.com"));
        assert_eq!(
            m.received_at,
            Some("2026-09-25T08:21:36.798Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn get_falls_back_to_the_html_for_text() {
        let row = json!([{"id": "1", "from": "a@x.test", "subject": "s", "html": "<p>hi</p>", "text": null}]);
        let m = with(&list_key(FULL), Reply::json(row))
            .get(&full(), "1")
            .await
            .unwrap();
        assert_eq!(m.text, "hi");
    }

    #[tokio::test]
    async fn a_message_no_longer_listed_is_gone() {
        assert!(matches!(
            build(&wire())
                .get(&Address::new(EMPTY, "tempmailo"), MESSAGE_ID)
                .await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_row_with_a_body_that_is_not_text_is_drift() {
        let row = json!([{"id": "1", "html": {"x": 1}, "text": null}]);
        assert!(matches!(
            with(&list_key(FULL), Reply::json(row))
                .get(&full(), "1")
                .await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn an_address_answered_as_a_json_string_is_unquoted() {
        // The transport asks for JSON, and then /changemail answers "x@y.com"
        // with the quotes. Mail to the quoted form goes nowhere.
        let a = with(CHANGEMAIL, Reply::text(r#""kaketyfi@fxzig.com""#))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, "kaketyfi@fxzig.com");
    }
}
