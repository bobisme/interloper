//! cloudflare_temp_email (github.com/dreamhunter2333/cloudflare_temp_email,
//! MIT).
//!
//! An open-source temp-mail worker that anyone can deploy on Cloudflare. This
//! adapter defaults to the author's public instance: the web app at
//! mail.awsl.uk, the API at temp-email-api.awsl.uk. Another deployment is
//! [`CfTempMail::new`] with its own API base and page; nothing else here is
//! instance-specific, because the domains, the Turnstile sitekey and the
//! creation switches are read from `/open_api/settings` on every generate().
//!
//! Creating an address needs a Turnstile token in `cf_token` when the
//! instance sets a sitekey (the public one does). It answers with a JWT, which
//! is the only credential for the inbox: it goes in Address::state and in
//! `Authorization: Bearer` on every later call. The JWT carries no `exp`; it
//! works until the address is deleted, which the public instance does after
//! 100 days without activity. Reading needs no solve.
//!
//! Every row, in the listing and on its own, carries the raw RFC 822 source in
//! `raw`, parsed here with `mail-parser`. `x-lang: en` pins the worker's error
//! text to English, so a refused token is recognizable by its message.

use std::sync::Arc;

use async_trait::async_trait;
use mail_parser::{MessageParser, PartKind};
use rand::seq::IndexedRandom;
use serde_json::{Map, Value, json};

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::parse::html_to_text;
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::parse_value_time;
use crate::transport::{HttpResponse, Transport};

pub const API: &str = "https://temp-email-api.awsl.uk";
pub const PAGE: &str = "https://mail.awsl.uk/";
/// i18n/en.ts TurnstileCheckFailedMsg, answered with HTTP 400.
const REFUSED_TOKEN: &str = "Human verification check failed";
const PAGE_SIZE: u32 = 100; // the worker rejects a larger limit

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mail.awsl.uk"],
    domains: &[], // read from /open_api/settings on each generate()
    domain_count: 3,
    // Deleted after 100 days without activity, per the instance's notice.
    address_ttl: None,
    message_ttl: Some(days(100)),
    delete: true,
    // The worker prepends the instance's prefix ("tmp") to any chosen name.
    custom_local: false,
    self_hosted: true,
    needs_state: true,
    needs_solver: true,
    max_concurrency: 2,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "cftempmail",
    caps: CAPS,
    build: |t| Arc::new(CfTempMail::new("cftempmail", API, PAGE, CAPS, t)),
};

pub struct CfTempMail {
    name: &'static str,
    api: String,
    page: String,
    caps: Capabilities,
    http: Transport,
}

/// Python's truthiness, which is what the worker's settings flags were
/// checked with.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// One mail as the worker stores it, its RFC 822 source parsed.
struct Mail {
    id: String,
    sender: String,
    subject: String,
    received_at: Option<jiff::Timestamp>,
    html: String,
    text: String,
}

impl CfTempMail {
    /// An instance of the worker: `api` is its API base, `page` the web app
    /// whose Turnstile sitekey the settings name.
    pub fn new(
        name: &'static str,
        api: impl Into<String>,
        page: impl Into<String>,
        caps: Capabilities,
        http: Transport,
    ) -> Self {
        CfTempMail {
            name,
            api: api.into().trim_end_matches('/').to_string(),
            page: page.into(),
            caps,
            http,
        }
    }

    fn jwt<'a>(&self, a: &'a Address) -> Result<&'a str> {
        a.state.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            Error::unsupported(format!("{} needs the JWT issued by generate()", self.name))
        })
    }

    /// A JSON 200, or drift: the worker answers errors as plain text.
    fn json200(&self, resp: &HttpResponse) -> Result<Value> {
        if resp.status == 200
            && let Ok(v) = serde_json::from_str(&resp.text)
        {
            return Ok(v);
        }
        Err(Error::drift(
            self.name,
            "a JSON 200",
            format!("HTTP {}: {}", resp.status, clip(&resp.text, 200)),
        ))
    }

    fn expired(&self, a: &Address) -> Error {
        Error::AddressExpired(format!("{} no longer knows {}", self.name, a.value))
    }

    async fn settings(&self) -> Result<(Vec<String>, Value)> {
        let data = self
            .http
            .get(format!("{}/open_api/settings", self.api))
            .header("x-lang", "en")
            .json()
            .await?;
        let domains: Option<Vec<String>> = data
            .get("domains")
            .and_then(Value::as_array)
            .filter(|d| !d.is_empty())
            .and_then(|d| d.iter().map(|x| x.as_str().map(String::from)).collect());
        let Some(domains) = domains else {
            return Err(Error::drift(self.name, "'domains' from settings", data));
        };
        let enable = data
            .get("enableUserCreateEmail")
            .is_none_or(|v| truthy(Some(v)));
        if truthy(data.get("needAuth")) || !enable {
            return Err(Error::unsupported(format!(
                "{}: this instance does not let strangers create addresses",
                self.name
            )));
        }
        if truthy(data.get("disableAnonymousUserCreateEmail")) {
            return Err(Error::unsupported(format!(
                "{}: this instance only creates addresses for its users",
                self.name
            )));
        }
        Ok((domains, data))
    }

    fn mail(&self, row: &Value) -> Result<Mail> {
        let (Some(id), Some(raw)) = (
            row.get("id").and_then(Value::as_i64),
            row.get("raw").and_then(Value::as_str),
        ) else {
            return Err(Error::drift(
                self.name,
                "a mail row with int 'id' and str 'raw'",
                row.clone(),
            ));
        };
        let source = row.get("source").and_then(Value::as_str).unwrap_or("");
        let parsed = MessageParser::default().parse(raw);
        let from = parsed
            .as_ref()
            .and_then(|m| m.from())
            .and_then(|f| f.first())
            .and_then(|mb| {
                let addr = mb.address()?;
                Some(match mb.name() {
                    Some(n) if !n.is_empty() => format!("{n} <{addr}>"),
                    _ => addr.to_string(),
                })
            });
        let subject = parsed
            .as_ref()
            .and_then(|m| m.subject())
            .unwrap_or("")
            .to_string();
        // Only a part of the asked-for type counts: mail-parser would convert
        // the other one, and an empty body falls back below.
        let body = |html: bool| -> String {
            let Some(m) = parsed.as_ref() else {
                return String::new();
            };
            let first = if html {
                m.html_body().next()
            } else {
                m.text_body().next()
            };
            first
                .filter(|p| match p.kind() {
                    PartKind::Html => html,
                    PartKind::Text => !html,
                    _ => false,
                })
                .and_then(|p| p.text())
                .map(|t| t.into_owned())
                .unwrap_or_default()
        };
        let html = body(true);
        let text = body(false);
        Ok(Mail {
            id: id.to_string(),
            sender: from.unwrap_or_else(|| source.to_string()),
            subject,
            // created_at is SQLite's CURRENT_TIMESTAMP: "YYYY-MM-DD HH:MM:SS"
            // in UTC.
            received_at: row.get("created_at").and_then(parse_value_time),
            html,
            text,
        })
    }
}

#[async_trait]
impl Provider for CfTempMail {
    fn name(&self) -> &str {
        self.name
    }

    fn caps(&self) -> &Capabilities {
        &self.caps
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        if opts.local.is_some() {
            return Err(Error::unsupported(format!(
                "{} prefixes every name, so it cannot honor a local part",
                self.name
            )));
        }
        if let Some(k) = opts.kind.filter(|k| *k != Kind::OwnDomain) {
            return Err(Error::unsupported(format!(
                "{} does not serve {k}",
                self.name
            )));
        }
        let (domains, settings) = self.settings().await?;
        let domain = match &opts.domain {
            Some(d) if domains.contains(d) => d.clone(),
            Some(d) => {
                return Err(Error::unsupported(format!(
                    "{} does not serve {d}",
                    self.name
                )));
            }
            None => domains
                .choose(&mut rand::rng())
                .cloned()
                .expect("checked non-empty"),
        };
        let mut body = Map::new();
        body.insert("domain".into(), json!(domain));
        if let Some(sitekey) = settings
            .get("cfTurnstileSiteKey")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty())
        {
            let token = self
                .http
                .turnstile_solver()?
                .turnstile(&self.page, sitekey, None, None)
                .await?;
            body.insert("cf_token".into(), json!(token));
        }
        let resp = self
            .http
            .post(format!("{}/api/new_address", self.api))
            .header("x-lang", "en")
            .json_body(&body)
            .send_json()
            .await?;
        if resp.status == 400 && resp.text.contains(REFUSED_TOKEN) {
            // The solver's fault, not a change in the API: must not
            // quarantine us.
            return Err(Error::SolverUnavailable(format!(
                "{} refused the Turnstile token",
                self.name
            )));
        }
        let data = self.json200(&resp)?;
        let address = data
            .get("address")
            .and_then(Value::as_str)
            .filter(|a| a.contains('@'));
        let jwt = data
            .get("jwt")
            .and_then(Value::as_str)
            .filter(|j| !j.is_empty());
        let (Some(address), Some(jwt)) = (address, jwt) else {
            return Err(Error::drift(
                self.name,
                "'address' and 'jwt' from new_address",
                data,
            ));
        };
        Ok(Address::new(address, self.name).with_state(jwt))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let resp = self
            .http
            .get(format!("{}/api/mails", self.api))
            .query("limit", PAGE_SIZE)
            .query("offset", 0)
            .header("x-lang", "en")
            .bearer(self.jwt(a)?)
            .send_json()
            .await?;
        if resp.status == 401 {
            return Err(self.expired(a));
        }
        let data = self.json200(&resp)?;
        let Some(rows) = data.get("results").and_then(Value::as_array) else {
            return Err(Error::drift(self.name, "'results' from mails", data));
        };
        rows.iter()
            .map(|r| {
                let m = self.mail(r)?;
                Ok(MessageRow::new(m.id, m.sender, m.subject).at(m.received_at))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .http
            .get(format!("{}/api/mail/{}", self.api, urlencoding::encode(id)))
            .header("x-lang", "en")
            .bearer(self.jwt(a)?)
            .send_json()
            .await?;
        if resp.status == 401 {
            return Err(self.expired(a));
        }
        let data = self.json200(&resp)?;
        if data.is_null() {
            // The worker's answer for an id it does not have.
            return Err(Error::gone(self.name, id));
        }
        let m = self.mail(&data)?;
        let text = if m.text.is_empty() {
            html_to_text(&m.html)
        } else {
            m.text
        };
        Ok(Message::from_bodies(
            m.id,
            m.sender,
            m.subject,
            m.received_at,
            m.html,
            Some(text),
        ))
    }

    async fn delete(&self, a: &Address, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!(
                "{}/api/mails/{}",
                self.api,
                urlencoding::encode(id)
            ))
            .header("x-lang", "en")
            .bearer(self.jwt(a)?)
            .send_json()
            .await?;
        if resp.status == 403 {
            return Err(Error::unsupported(format!(
                "{}: this instance does not let users delete mail",
                self.name
            )));
        }
        let data = self.json200(&resp)?;
        if data.get("success").is_none() {
            return Err(Error::drift(self.name, "'success' from delete", data));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solver::Solver;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/cftempmail");
    const SITEKEY: &str = "0x4AAAAAAAZSO_9yWmz_-itl";
    const JWT: &str = "JWT-PLACEHOLDER";
    const VALUE: &str = "tmpwdr154ebyfg@awsl.uk";
    const MID: &str = "3395874";

    const SETTINGS: &str = "GET https://temp-email-api.awsl.uk/open_api/settings";
    const NEW: &str = "POST https://temp-email-api.awsl.uk/api/new_address";
    const MAILS: &str = "GET https://temp-email-api.awsl.uk/api/mails";
    const MAIL: &str = "GET https://temp-email-api.awsl.uk/api/mail/";
    const DELETE: &str = "DELETE https://temp-email-api.awsl.uk/api/mails/";

    fn load(n: &str) -> Value {
        Fixtures::load(DIR, n)
    }

    fn text(n: &str) -> String {
        Fixtures::load_text(DIR, n)
    }

    fn wire() -> Arc<Fixtures> {
        let first = load("new_address.json");
        let mut second = first.clone();
        second["address"] = json!("tmpother@awsl.uk");
        Fixtures::new()
            .route(SETTINGS, Reply::json(load("settings.json")))
            // Two answers so the contract's two generates get two addresses.
            .route_seq(NEW, [Reply::json(first), Reply::json(second)])
            .route(MAILS, Reply::json(load("mails.json")))
            .route(MAIL, Reply::json(load("mail.json")))
            .route(DELETE, Reply::json(load("delete.json")))
    }

    fn solver_wire() -> Arc<Fixtures> {
        Fixtures::new().route("/turnstile", Reply::json(json!({"token": "fake-token"})))
    }

    fn build_with(w: &Arc<Fixtures>, s: Option<&Arc<Fixtures>>) -> Arc<dyn Provider> {
        let t = w
            .transport("cftempmail", &CAPS)
            .solver(s.map(|s| Solver::with_backend("http://solver.test", s.clone())));
        Arc::new(CfTempMail::new("cftempmail", API, PAGE, CAPS, t))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        build_with(w, Some(&solver_wire()))
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new(VALUE, "cftempmail").with_state(JWT)
    }

    fn sent(w: &Fixtures, prefix: &str) -> Vec<HttpRequest> {
        let (method, url) = prefix.split_once(' ').unwrap();
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url.starts_with(url))
            .collect()
    }

    fn json_of(r: &HttpRequest) -> Value {
        match &r.body {
            Body::Json(v) => v.clone(),
            other => panic!("not a JSON body: {other:?}"),
        }
    }

    fn settings_with(k: &str, v: Value) -> Reply {
        let mut s = load("settings.json");
        s[k] = v;
        Reply::json(s)
    }

    #[tokio::test]
    async fn the_turnstile_token_goes_into_new_address() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let solves = s.seen();
        assert_eq!(solves.len(), 1);
        let ask = json_of(&solves[0]);
        assert_eq!(ask["url"], "https://mail.awsl.uk/");
        assert_eq!(ask["sitekey"], SITEKEY);
        let body = json_of(&sent(&w, NEW)[0]);
        assert_eq!(body["cf_token"], "fake-token");
        assert!(["awsl.uk", "kksk.uk", "misaka.boo"].contains(&body["domain"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn generate_keeps_the_jwt_as_state() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, VALUE);
        assert_eq!(a.state.as_deref(), Some(JWT));
    }

    #[tokio::test]
    async fn a_chosen_domain_is_asked_for() {
        let w = wire();
        build(&w)
            .generate(&GenerateOptions {
                domain: Some("misaka.boo".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(json_of(&sent(&w, NEW)[0])["domain"], "misaka.boo");
    }

    #[tokio::test]
    async fn without_a_solver_generate_is_solver_unavailable() {
        let w = wire();
        let r = build_with(&w, None)
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, NEW).is_empty());
    }

    #[tokio::test]
    async fn an_instance_without_a_sitekey_needs_no_solve() {
        let w = wire().route(SETTINGS, settings_with("cfTurnstileSiteKey", json!("")));
        build_with(&w, None)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert!(json_of(&sent(&w, NEW)[0]).get("cf_token").is_none());
    }

    #[tokio::test]
    async fn another_instance_is_its_own_api_and_page() {
        let w = Fixtures::new()
            .route(
                "GET https://api.mail.test/open_api/settings",
                Reply::json(load("settings.json")),
            )
            .route(
                "POST https://api.mail.test/api/new_address",
                Reply::json(load("new_address.json")),
            );
        let s = solver_wire();
        let t = w
            .transport("mymail", &CAPS)
            .solver(Some(Solver::with_backend("http://solver.test", s.clone())));
        let p = CfTempMail::new(
            "mymail",
            "https://api.mail.test/",
            "https://mail.test/",
            CAPS,
            t,
        );
        let a = p.generate(&GenerateOptions::default()).await.unwrap();
        assert_eq!(a.provider, "mymail");
        assert_eq!(json_of(&s.seen()[0])["url"], "https://mail.test/");
    }

    #[tokio::test]
    async fn a_refused_token_is_the_solvers_fault_not_drift() {
        let w = wire().route(
            NEW,
            Reply::text(text("turnstile_refused.txt")).with_status(400),
        );
        let r = build(&w).generate(&GenerateOptions::default()).await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
    }

    #[tokio::test]
    async fn solver_unavailable_propagates_unchanged() {
        let w = wire();
        let s = Fixtures::new().route("/turnstile", Reply::status(500));
        let r = build_with(&w, Some(&s))
            .generate(&GenerateOptions::default())
            .await;
        assert!(matches!(r, Err(Error::SolverUnavailable(_))), "{r:?}");
        assert!(sent(&w, NEW).is_empty());
    }

    #[tokio::test]
    async fn what_the_instance_cannot_do_is_refused_before_a_solve() {
        for opts in [
            GenerateOptions {
                domain: Some("gmail.com".into()),
                ..Default::default()
            },
            GenerateOptions {
                local: Some("me".into()),
                ..Default::default()
            },
            GenerateOptions {
                kind: Some(Kind::GmailAlias),
                ..Default::default()
            },
        ] {
            let (w, s) = (wire(), solver_wire());
            let r = build_with(&w, Some(&s)).generate(&opts).await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{opts:?}");
            assert!(s.seen().is_empty());
            assert!(sent(&w, NEW).is_empty());
        }
    }

    #[tokio::test]
    async fn an_instance_closed_to_anonymous_creation_is_not_supported() {
        for (flag, value) in [
            ("needAuth", json!(true)),
            ("enableUserCreateEmail", json!(false)),
            ("disableAnonymousUserCreateEmail", json!(true)),
        ] {
            let w = wire().route(SETTINGS, settings_with(flag, value));
            let s = solver_wire();
            let r = build_with(&w, Some(&s))
                .generate(&GenerateOptions::default())
                .await;
            assert!(matches!(r, Err(Error::NotSupported(_))), "{flag}: {r:?}");
            assert!(s.seen().is_empty());
        }
    }

    #[tokio::test]
    async fn list_sends_the_bearer_jwt_and_no_solve() {
        let (w, s) = (wire(), solver_wire());
        build_with(&w, Some(&s)).list(&address()).await.unwrap();
        assert!(s.seen().is_empty());
        let r = &sent(&w, MAILS)[0];
        assert_eq!(r.header("Authorization"), Some("Bearer JWT-PLACEHOLDER"));
        assert_eq!(
            r.query,
            [
                ("limit".into(), "100".into()),
                ("offset".into(), "0".into())
            ]
        );
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MID);
        assert_eq!(rows[0].subject, "Your Email Test is Successful!");
        assert_eq!(rows[0].sender, "Xeramail Test <test@xeramail.com>");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T02:19:59Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(MAILS, Reply::json(load("mails_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_refused_jwt_is_an_expired_address() {
        let w = wire().route(
            MAILS,
            Reply::text(text("invalid_credential.txt")).with_status(401),
        );
        let r = build(&w).list(&address()).await;
        assert!(matches!(r, Err(Error::AddressExpired(_))), "{r:?}");
    }

    #[tokio::test]
    async fn list_without_state_is_not_supported() {
        let r = build(&wire())
            .list(&Address::new(VALUE, "cftempmail"))
            .await;
        assert!(matches!(r, Err(Error::NotSupported(_))), "{r:?}");
    }

    #[tokio::test]
    async fn get_parses_the_raw_message() {
        let (w, s) = (wire(), solver_wire());
        let m = build_with(&w, Some(&s)).get(&address(), MID).await.unwrap();
        assert_eq!(m.id, MID);
        assert_eq!(m.subject, "Your Email Test is Successful!");
        assert!(
            m.text
                .starts_with("Congratulations! Your email address is working."),
            "{}",
            m.text
        );
        assert!(m.html.contains("working successfully"));
        assert_eq!(m.received_at, Some("2026-09-25T02:19:59Z".parse().unwrap()));
        assert_eq!(
            sent(&w, MAIL)[0].header("Authorization"),
            Some("Bearer JWT-PLACEHOLDER")
        );
        assert!(s.seen().is_empty());
    }

    #[tokio::test]
    async fn a_missing_message_is_gone() {
        // The worker answers `null` with HTTP 200 for an id it does not have.
        let w = wire().route(MAIL, Reply::text(text("mail_gone.json")));
        let r = build(&w).get(&address(), "999999999").await;
        assert!(matches!(r, Err(Error::MessageGone { .. })), "{r:?}");
    }

    #[tokio::test]
    async fn delete_sends_the_bearer_jwt() {
        let w = wire();
        build(&w).delete(&address(), MID).await.unwrap();
        assert_eq!(
            sent(&w, DELETE)[0].header("Authorization"),
            Some("Bearer JWT-PLACEHOLDER")
        );
    }

    #[tokio::test]
    async fn an_instance_that_forbids_deletion_is_not_supported() {
        let w = wire().route(
            DELETE,
            Reply::text("User delete email is disabled").with_status(403),
        );
        let r = build(&w).delete(&address(), MID).await;
        assert!(matches!(r, Err(Error::NotSupported(_))), "{r:?}");
    }

    #[tokio::test]
    async fn a_malformed_answer_is_drift() {
        let cases = [
            (SETTINGS, Reply::json(json!({"x": 1}))),
            (
                SETTINGS,
                Reply::json(json!({"domains": [], "cfTurnstileSiteKey": SITEKEY})),
            ),
            (NEW, Reply::json(json!({"x": 1}))),
            (
                NEW,
                Reply::text("Failed to create address").with_status(400),
            ),
            (MAILS, Reply::json(json!({"x": 1}))),
            (
                MAILS,
                Reply::json(json!({"results": [{"raw": "no id"}], "count": 1})),
            ),
            (MAIL, Reply::json(json!({"x": 1}))),
        ];
        for (route, answer) in cases {
            let p = build(&wire().route(route, answer));
            let r = match route {
                SETTINGS | NEW => p.generate(&GenerateOptions::default()).await.map(|_| ()),
                MAIL => p.get(&address(), MID).await.map(|_| ()),
                _ => p.list(&address()).await.map(|_| ()),
            };
            assert!(
                matches!(r, Err(Error::SchemaDrift { .. })),
                "{route}: {r:?}"
            );
        }
    }
}
