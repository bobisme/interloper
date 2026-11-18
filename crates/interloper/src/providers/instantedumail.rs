//! instantedumail.com, a Supabase app used through its own REST endpoints.
//!
//! An anonymous Supabase sign-up issues an access token and a refresh token.
//! The client then inserts a mailbox row whose address it picks itself, and
//! reads the `emails` table filtered by that mailbox. Rows carry the body, text
//! and HTML both, so get() is a single-row read. Row-level security holds: a
//! token reads only its own user's mailboxes, so an inbox is private.
//!
//! None of the domains is a university's: mail-edu.eu and the .io.vn names are
//! ordinary registrations, and myacademy.edu.pl is under .edu.pl, which anyone
//! can register.
//!
//! The key below is the project's publishable anon key, shipped in the page
//! bundle. It is not a secret. The tokens in Address::state are.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::util::random_local;
use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::{J, parse_value_time};
use crate::transport::{HttpResponse, Req, Transport};

const PROJECT: &str = "https://qapwrbodvcsseymwmmxw.supabase.co";
pub const APIKEY: &str = "sb_publishable_k4cc22sdcI4IOUqlTHo3uA_yXyaJupH";
// The domains the page marks live.
const DOMAINS: &[&str] = &[
    "mail-edu.eu",
    "myacademy.edu.pl",
    "manila.io.vn",
    "chicago.io.vn",
];
const LIFETIME: std::time::Duration = hours(1);

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain, Kind::Edu],
    sites: &["instantedumail.com"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // The client asks for an hour; the server has been seen to grant two.
    address_ttl: Some(LIFETIME),
    message_ttl: None,
    custom_local: true,
    needs_state: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "instantedumail",
    caps: CAPS,
    build: |t| Arc::new(InstantEduMail::new(t)),
};

#[derive(Clone, Serialize, Deserialize)]
struct State {
    access_token: String,
    refresh_token: String,
    mailbox_id: String,
}

pub struct InstantEduMail {
    http: Transport,
    // Refreshed tokens, by address. Address::state is immutable, so a refresh
    // is remembered here for the life of this provider.
    tokens: Mutex<HashMap<String, State>>,
}

fn authed<'a>(req: Req<'a>, token: Option<&str>) -> Req<'a> {
    req.header("apikey", APIKEY).bearer(token.unwrap_or(APIKEY))
}

fn sender(r: &J<'_>) -> String {
    let (name, address) = (r.s("from_name"), r.s("from_address"));
    match (name.is_empty(), address.is_empty()) {
        (false, false) => format!("{name} <{address}>"),
        (true, false) => address,
        _ => name,
    }
}

fn parsed(resp: &HttpResponse) -> Option<Value> {
    serde_json::from_str(&resp.text).ok()
}

fn describe(v: &Option<Value>) -> String {
    v.as_ref()
        .map_or_else(|| "a non-JSON body".into(), |v| clip(&v.to_string(), 200))
}

impl InstantEduMail {
    fn new(http: Transport) -> Self {
        InstantEduMail {
            http,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    fn state(&self, a: &Address) -> Result<State> {
        if let Some(s) = self.tokens.lock().unwrap().get(&a.value) {
            return Ok(s.clone());
        }
        a.state
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .ok_or_else(|| {
                Error::unsupported("instantedumail needs the tokens issued by generate()")
            })
    }

    async fn refresh(&self, a: &Address, st: State) -> Result<State> {
        let resp = authed(self.http.post(format!("{PROJECT}/auth/v1/token")), None)
            .query("grant_type", "refresh_token")
            .json_body(&json!({"refresh_token": st.refresh_token}))
            .send_json()
            .await?;
        let data = parsed(&resp);
        let access = data
            .as_ref()
            .and_then(|d| d.get("access_token"))
            .and_then(Value::as_str);
        let (200, Some(access)) = (resp.status, access) else {
            return Err(Error::down(
                "instantedumail",
                format!("token refresh refused (HTTP {})", resp.status),
            ));
        };
        let refresh = data
            .as_ref()
            .and_then(|d| d.get("refresh_token"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map_or(st.refresh_token.clone(), String::from);
        let fresh = State {
            access_token: access.to_string(),
            refresh_token: refresh,
            ..st
        };
        self.tokens
            .lock()
            .unwrap()
            .insert(a.value.clone(), fresh.clone());
        Ok(fresh)
    }

    /// GET the emails table, refreshing an expired token once.
    async fn read(&self, a: &Address, params: &[(&str, String)]) -> Result<HttpResponse> {
        let mut st = self.state(a)?;
        for attempt in 0..2 {
            let mut req = authed(
                self.http.get(format!("{PROJECT}/rest/v1/emails")),
                Some(&st.access_token),
            );
            for (k, v) in params {
                req = req.query(*k, v);
            }
            let resp = req.send_json().await?;
            if resp.status != 401 {
                return Ok(resp);
            }
            if attempt == 0 {
                st = self.refresh(a, st).await?;
            }
        }
        Err(Error::down(
            "instantedumail",
            "a refreshed token was rejected",
        ))
    }
}

#[async_trait]
impl Provider for InstantEduMail {
    fn name(&self) -> &str {
        "instantedumail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = match &opts.domain {
            None => DOMAINS[0],
            Some(want) => DOMAINS
                .iter()
                .find(|d| d.eq_ignore_ascii_case(want))
                .copied()
                .ok_or_else(|| {
                    Error::unsupported(format!("instantedumail does not serve {want}"))
                })?,
        };
        let local = opts.local.clone().unwrap_or_else(random_local);
        let value = format!("{local}@{domain}");
        let auth = authed(self.http.post(format!("{PROJECT}/auth/v1/signup")), None)
            .json_body(&json!({"data": {}}))
            .json()
            .await?;
        let ok = auth.get("user").is_some_and(Value::is_object)
            && auth.get("access_token").is_some()
            && auth.get("refresh_token").is_some();
        if !ok {
            return Err(Error::drift(
                "instantedumail",
                "tokens and a user from signup",
                clip(&auth.to_string(), 200),
            ));
        }
        let j = J::new("instantedumail", &auth, "signup");
        let access = j.at("access_token")?.str()?.to_string();
        let refresh = j.at("refresh_token")?.str()?.to_string();
        let user_id = j.at("user")?.req_id("id")?;
        let expires = jiff::Timestamp::now()
            .checked_add(jiff::SignedDuration::try_from(LIFETIME).expect("an hour fits"))
            .expect("an hour from now is representable");
        let rows = authed(
            self.http.post(format!("{PROJECT}/rest/v1/mailboxes")),
            Some(&access),
        )
        .header("Prefer", "return=representation")
        .json_body(&json!({
            "user_id": user_id,
            "address": value,
            "mailbox_type": "random",
            "expires_at": expires.to_string(),
        }))
        .json()
        .await?;
        let row = match &rows {
            Value::Array(a) if !a.is_empty() => &a[0],
            other => other,
        };
        let mailbox_id = match row.get("id") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => {
                return Err(Error::drift(
                    "instantedumail",
                    "the created mailbox row",
                    clip(&rows.to_string(), 200),
                ));
            }
        };
        let state = serde_json::to_string(&State {
            access_token: access,
            refresh_token: refresh,
            mailbox_id,
        })
        .expect("serializes");
        let mut a = Address::new(value, "instantedumail").with_state(state);
        a.expires_at = Some(expires);
        Ok(a)
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let st = self.state(a)?;
        let resp = self
            .read(
                a,
                &[
                    ("select", "*".into()),
                    ("mailbox_id", format!("eq.{}", st.mailbox_id)),
                    ("folder", "eq.inbox".into()),
                    ("order", "received_at.desc".into()),
                    ("limit", "50".into()),
                ],
            )
            .await?;
        let rows = parsed(&resp);
        let Some(list) = rows
            .as_ref()
            .filter(|_| resp.status == 200)
            .and_then(Value::as_array)
        else {
            return Err(Error::drift(
                "instantedumail",
                "an array of email rows",
                describe(&rows),
            ));
        };
        list.iter()
            .enumerate()
            .map(|(i, r)| {
                let j = J::new("instantedumail", r, &format!("emails[{i}]"));
                let at = r.get("received_at").and_then(parse_value_time);
                Ok(MessageRow::new(j.req_id("id")?, sender(&j), j.s("subject")).at(at))
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .read(a, &[("select", "*".into()), ("id", format!("eq.{id}"))])
            .await?;
        let rows = parsed(&resp);
        // A malformed id is a 400 from Postgres; either way the message is not
        // there.
        if resp.status == 400
            || rows
                .as_ref()
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        {
            return Err(Error::gone("instantedumail", id));
        }
        let Some(row) = rows
            .as_ref()
            .filter(|_| resp.status == 200)
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .filter(|r| r.is_object())
        else {
            return Err(Error::drift(
                "instantedumail",
                "one email row",
                describe(&rows),
            ));
        };
        let j = J::new("instantedumail", row, "email");
        let body = Some(j.s("body")).filter(|s| !s.is_empty());
        Ok(Message::from_bodies(
            id,
            sender(&j),
            j.s("subject"),
            row.get("received_at").and_then(parse_value_time),
            j.s("html_body"),
            body,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::{Body, HttpRequest};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/instantedumail");
    const MAILBOX_ID: &str = "4f2310e8-4ad1-44a0-90c3-7d630a5190a7";
    const MESSAGE_ID: &str = "4fe6f6fe-3196-40fe-9816-03a976c64647";
    const SIGNUP: &str = "/auth/v1/signup";
    const REFRESH: &str = "grant_type=refresh_token";
    const CREATE: &str = "/rest/v1/mailboxes";
    const LIST: &str = "folder=eq.inbox";
    const GET: &str = "&id=eq.";

    fn load(name: &str) -> Value {
        Fixtures::load(DIR, name)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new()
            .route(SIGNUP, Reply::json(load("signup.json")))
            .route(CREATE, Reply::json(load("mailbox.json")).with_status(201))
            .route(LIST, Reply::json(load("emails_full.json")))
            .route(GET, Reply::json(load("emails_full.json")))
            .route(REFRESH, Reply::json(load("refresh.json")))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(InstantEduMail::new(w.transport("instantedumail", &CAPS)))
    }

    fn token(name: &str, key: &str) -> String {
        load(name)[key].as_str().unwrap().to_string()
    }

    fn address() -> Address {
        let st = State {
            access_token: token("signup.json", "access_token"),
            refresh_token: token("signup.json", "refresh_token"),
            mailbox_id: MAILBOX_ID.into(),
        };
        Address::new("campusab12@mail-edu.eu", "instantedumail")
            .with_state(serde_json::to_string(&st).unwrap())
    }

    fn calls(w: &Fixtures, needle: &str) -> Vec<HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| format!("{} {}", r.method.as_str(), r.full_url()).contains(needle))
            .collect()
    }

    fn body(r: &HttpRequest) -> Value {
        match &r.body {
            Body::Json(v) => v.clone(),
            other => panic!("not json: {other:?}"),
        }
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn generate_sends_apikey_and_bearer_and_creates_a_random_mailbox() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert!(a.value.ends_with("@mail-edu.eu"));
        assert_eq!(a.provider, "instantedumail");
        let signup = calls(&w, SIGNUP);
        assert_eq!(signup.len(), 1);
        assert_eq!(signup[0].header("apikey"), Some(APIKEY));
        let create = calls(&w, CREATE);
        assert_eq!(create.len(), 1);
        assert_eq!(create[0].header("apikey"), Some(APIKEY));
        assert_eq!(
            create[0].header("Authorization"),
            Some(format!("Bearer {}", token("signup.json", "access_token")).as_str())
        );
        let b = body(&create[0]);
        assert_eq!(b["mailbox_type"], "random");
        assert_eq!(b["address"], a.value.as_str());
        assert!(b["expires_at"].is_string());
        assert!(a.expires_at.is_some());
    }

    #[tokio::test]
    async fn generate_stores_tokens_and_mailbox_id_in_state() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        let st: State = serde_json::from_str(a.state.as_deref().unwrap()).unwrap();
        assert_eq!(st.access_token, token("signup.json", "access_token"));
        assert_eq!(st.refresh_token, token("signup.json", "refresh_token"));
        assert_eq!(st.mailbox_id, MAILBOX_ID);
    }

    #[tokio::test]
    async fn generate_honours_a_chosen_local() {
        let opts = GenerateOptions {
            local: Some("scholar99".into()),
            domain: Some("chicago.io.vn".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "scholar99@chicago.io.vn");
    }

    #[tokio::test]
    async fn a_domain_it_does_not_serve_is_refused() {
        let w = wire();
        let opts = GenerateOptions {
            domain: Some("gmail.com".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&w).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
        assert!(w.seen().is_empty());
    }

    #[tokio::test]
    async fn list_sends_apikey_and_bearer() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        let reads = calls(&w, "/rest/v1/emails");
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0].header("apikey"), Some(APIKEY));
        assert_eq!(
            reads[0].header("Authorization"),
            Some(format!("Bearer {}", token("signup.json", "access_token")).as_str())
        );
    }

    #[tokio::test]
    async fn list_parses_rows() {
        let rows = build(&wire()).list(&address()).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MESSAGE_ID]
        );
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d7b1130c)");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T08:31:42.671Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(LIST, Reply::json(load("emails_empty.json")));
        assert!(build(&w).list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_parses_body_and_links() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.id, MESSAGE_ID);
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert!(m.text.contains("everything is working as expected"));
        assert!(!m.html.is_empty());
        assert!(m.links.iter().any(|l| l.contains("joltmx.com")));
    }

    #[tokio::test]
    async fn an_unknown_id_is_gone() {
        let w = wire().route(GET, Reply::json(load("emails_empty.json")));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_malformed_uuid_is_gone() {
        let w = wire().route(GET, Reply::json(load("bad_id.json")).with_status(400));
        assert!(matches!(
            build(&w).get(&address(), "notauuid").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_list_that_is_not_an_array_is_drift() {
        let w = wire().route(LIST, Reply::json(load("drift.json")));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn an_expired_token_is_refreshed_once() {
        let w = wire().route_seq(
            LIST,
            [
                Reply::json(load("jwt_expired.json")).with_status(401),
                Reply::json(load("emails_full.json")),
            ],
        );
        let rows = build(&w).list(&address()).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MESSAGE_ID]
        );
        assert_eq!(calls(&w, REFRESH).len(), 1);
        // After refresh, the second read carries the new access token.
        let reads = calls(&w, "/rest/v1/emails");
        assert_eq!(
            reads.last().unwrap().header("Authorization"),
            Some(format!("Bearer {}", token("refresh.json", "access_token")).as_str())
        );
    }

    #[tokio::test]
    async fn a_refreshed_token_is_remembered_for_the_address() {
        let w = wire().route_seq(
            LIST,
            [
                Reply::json(load("jwt_expired.json")).with_status(401),
                Reply::json(load("emails_full.json")),
            ],
        );
        let p = build(&w);
        p.list(&address()).await.unwrap();
        p.list(&address()).await.unwrap();
        assert_eq!(calls(&w, REFRESH).len(), 1);
    }

    #[tokio::test]
    async fn a_token_rejected_after_refresh_is_not_retried_forever() {
        let w = wire().route(LIST, Reply::json(load("jwt_expired.json")).with_status(401));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
        assert_eq!(calls(&w, REFRESH).len(), 1);
    }

    #[tokio::test]
    async fn a_refresh_that_is_rejected_is_provider_down() {
        let w = wire()
            .route(LIST, Reply::json(load("jwt_expired.json")).with_status(401))
            .route(
                REFRESH,
                Reply::json(json!({"error": "invalid_grant"})).with_status(400),
            );
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn list_without_usable_state_is_refused() {
        let a = Address {
            state: Some("not json".into()),
            ..address()
        };
        assert!(matches!(
            build(&wire()).list(&a).await,
            Err(Error::NotSupported(_))
        ));
    }
}
