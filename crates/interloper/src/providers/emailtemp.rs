//! emailtemp.org and emailgenerator.org: one Laravel "TMail" script, two hosts.
//!
//! The mailbox is the encrypted `email` cookie. GET /en gives a CSRF token and
//! a Laravel session; POST /messages with both mints a mailbox (setting
//! `email`) when there is none, and lists it when there is. A fresh session
//! given only the `email` cookie reads the same mailbox, so every request runs
//! on a throwaway session and the host plus that cookie travel in
//! Address::state. An `email` cookie the site cannot read silently gets a
//! brand-new mailbox, which is why list() checks the mailbox it was answered
//! for.
//!
//! Rows carry the HTML body (`content`) and a UTC `receivedAt`, so get() reads
//! the listing and never touches /view.
//!
//! POST /create (name, domain) switches the session to a chosen address, but
//! only for a session that already holds a mailbox. A taken address is refused
//! with a redirect back to /change and no new cookie; the inbox stays private.
//!
//! mymail.edu.pl and webmail.edu.pl are under `.edu.pl`, which anyone can
//! register: they are not university mailboxes, so they are declared as
//! own-domain like the rest.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use rand::Rng;
use rand::seq::IndexedRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::{HttpResponse, Transport};

struct Site {
    host: &'static str,
    base: &'static str,
    session: &'static str,
    domains: &'static [&'static str],
}

const SITES: &[Site] = &[
    Site {
        host: "emailtemp.org",
        base: "https://emailtemp.org",
        session: "emailtemp_session",
        domains: &["tormails.com"],
    },
    // Bare emailgenerator.org 301s to www, which turns a POST into a GET.
    // Domains from the /en/change picker on 2026-11-18; cowbird's list had
    // pluniversity.edu.pl and ehost.cam, which the picker no longer offers
    // (/create refused pluniversity.edu.pl).
    Site {
        host: "emailgenerator.org",
        base: "https://www.emailgenerator.org",
        session: "emailgenerator_session",
        domains: &[
            "uxmil.com",
            "grnail.cam",
            "qmail.host",
            "gmaily.cc",
            "mymail.edu.pl",
            "webmail.edu.pl",
            "kezmail.com",
            "emailt.org",
        ],
    },
];

// Every domain of every site, in SITES order.
const DOMAINS: &[&str] = &[
    "tormails.com",
    "uxmil.com",
    "grnail.cam",
    "qmail.host",
    "gmaily.cc",
    "mymail.edu.pl",
    "webmail.edu.pl",
    "kezmail.com",
    "emailt.org",
];

static CSRF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<meta name="csrf-token" content="([^"]+)""#).unwrap());
const WHEN: &str = "%Y-%m-%d %H:%M:%S";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["emailtemp.org", "emailgenerator.org"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // The `email` cookie's Max-Age is 8h, but that only binds a browser; the
    // site's own retention is unpublished.
    address_ttl: None,
    message_ttl: None,
    custom_local: true,
    // The state is the inbox key: whoever holds the cookie reads the mail.
    needs_state: true,
    max_concurrency: 1,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "emailtemp",
    caps: CAPS,
    build: |t| Arc::new(EmailTemp { http: t }),
};

pub struct EmailTemp {
    http: Transport,
}

#[derive(Serialize, Deserialize)]
struct State {
    site: String,
    cookie: String,
}

/// The site serving `domain` (and the domain as that site spells it), or a
/// random site when none was asked for.
fn pick(domain: Option<&str>) -> Result<(&'static Site, Option<&'static str>)> {
    let Some(want) = domain else {
        return Ok((SITES.choose(&mut rand::rng()).expect("sites"), None));
    };
    SITES
        .iter()
        .find_map(|s| {
            s.domains
                .iter()
                .find(|d| d.eq_ignore_ascii_case(want))
                .map(|d| (s, Some(*d)))
        })
        .ok_or_else(|| Error::unsupported(format!("emailtemp has no host serving {want}")))
}

/// The site's own shape: seven letters and three digits.
fn random_local() -> String {
    let mut rng = rand::rng();
    let letters: String = (0..7)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect();
    format!("{letters}{:03}", rng.random_range(0..1000))
}

fn domain_of(value: &str) -> &str {
    value.rsplit_once('@').map_or("", |(_, d)| d)
}

fn row(r: &J<'_>) -> Result<MessageRow> {
    let received = match r.opt("receivedAt") {
        None => None,
        Some(w) => {
            let raw = w
                .str()
                .map_err(|_| w.drift(&format!("receivedAt as {WHEN}")))?;
            let dt = jiff::civil::DateTime::strptime(WHEN, raw)
                .map_err(|_| w.drift(&format!("receivedAt as {WHEN}")))?;
            Some(
                jiff::tz::TimeZone::UTC
                    .to_timestamp(dt)
                    .map_err(|_| w.drift("a representable receivedAt"))?,
            )
        }
    };
    let (name, email) = (r.s("from"), r.s("from_email"));
    let sender = match (name.is_empty(), email.is_empty()) {
        (false, false) => format!("{name} <{email}>"),
        (false, true) => name,
        _ => email,
    };
    Ok(MessageRow::new(r.req_id("id")?, sender, r.s("subject")).at(received))
}

impl EmailTemp {
    /// The site and the `email` cookie from Address::state.
    fn inbox(&self, a: &Address) -> Result<(&'static Site, String)> {
        let st: State = a
            .state
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .ok_or_else(|| {
                Error::unsupported("emailtemp needs the host and mailbox cookie from generate()")
            })?;
        let site = SITES
            .iter()
            .find(|s| s.host == st.site)
            .ok_or_else(|| Error::unsupported(format!("emailtemp does not serve {}", st.site)))?;
        Ok((site, st.cookie))
    }

    /// A CSRF token and the Laravel session cookie it belongs to.
    async fn home(&self, site: &Site) -> Result<(String, String)> {
        let home = self.http.get(format!("{}/en", site.base)).send().await?;
        // An error page (an origin or WAF refusing this IP) is an outage,
        // not a new page shape: it must not quarantine the adapter.
        if !home.is_success() {
            return Err(Error::down(
                "emailtemp",
                format!("/en answered HTTP {}", home.status),
            ));
        }
        let csrf = CSRF.captures(&home.text).map(|c| c[1].to_string());
        match (csrf, home.cookie(site.session)) {
            (Some(c), Some(s)) => Ok((c, s)),
            _ => Err(Error::drift(
                "emailtemp",
                format!("a csrf-token meta tag and {} from /en", site.session),
                clip(&home.text, 200),
            )),
        }
    }

    /// POST /messages: the response and its body, checked to be a
    /// {mailbox, messages} with an `id` on every row.
    async fn messages(
        &self,
        site: &Site,
        csrf: &str,
        session: &str,
        inbox: Option<&str>,
    ) -> Result<(HttpResponse, Value)> {
        let mut req = self
            .http
            .post(format!("{}/messages", site.base))
            .form([("_token", csrf), ("captcha", "")])
            .header("X-Requested-With", "XMLHttpRequest")
            .cookie(site.session, session);
        if let Some(c) = inbox {
            req = req.cookie("email", c);
        }
        let resp = req.send_json().await?;
        // An error page (Laravel's 419 "Page Expired" and kin) says nothing
        // about the shape of a listing; it is not drift.
        if resp.status >= 400 {
            return Err(Error::down(
                "emailtemp",
                format!("/messages answered HTTP {}", resp.status),
            ));
        }
        let data = resp.json("emailtemp")?;
        let ok = data.get("mailbox").is_some_and(Value::is_string)
            && data
                .get("messages")
                .and_then(Value::as_array)
                .is_some_and(|rows| {
                    rows.iter()
                        .all(|r| r.as_object().is_some_and(|o| o.contains_key("id")))
                });
        if !ok {
            return Err(Error::drift(
                "emailtemp",
                "a 'mailbox' and a list of 'messages' with 'id'",
                clip(&data.to_string(), 200),
            ));
        }
        Ok((resp, data))
    }

    async fn read(&self, a: &Address) -> Result<Vec<Value>> {
        let (site, cookie) = self.inbox(a)?;
        let (csrf, session) = self.home(site).await?;
        let (_, data) = self.messages(site, &csrf, &session, Some(&cookie)).await?;
        if !data["mailbox"]
            .as_str()
            .unwrap_or_default()
            .eq_ignore_ascii_case(&a.value)
        {
            return Err(Error::AddressExpired(format!(
                "emailtemp: {} is gone",
                a.value
            )));
        }
        Ok(data["messages"].as_array().cloned().unwrap_or_default())
    }
}

#[async_trait]
impl Provider for EmailTemp {
    fn name(&self) -> &str {
        "emailtemp"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let (site, asked) = pick(opts.domain.as_deref())?;
        let (csrf, session) = self.home(site).await?;
        let (resp, data) = self.messages(site, &csrf, &session, None).await?;
        let mut value = data["mailbox"].as_str().unwrap_or_default().to_string();
        let mut inbox = resp.cookie("email").ok_or_else(|| {
            Error::drift(
                "emailtemp",
                "an email cookie from /messages",
                clip(&data.to_string(), 200),
            )
        })?;
        let domain = asked.unwrap_or(domain_of(&value)).to_string();
        if opts.local.is_some() || domain != domain_of(&value) {
            let local = opts.local.clone().unwrap_or_else(random_local);
            // The new cookie is on the 302 itself; the page it leads to has
            // none. So this one request does not follow the redirect and the
            // cookie is read off the 302.
            let created = self
                .http
                .post(format!("{}/create", site.base))
                .form([
                    ("_token", csrf.as_str()),
                    ("name", local.as_str()),
                    ("domain", domain.as_str()),
                ])
                .cookie(site.session, &session)
                .cookie("email", &inbox)
                .no_redirect()
                .send()
                .await?;
            if created.status >= 400 {
                return Err(Error::down(
                    "emailtemp",
                    format!("/create answered HTTP {}", created.status),
                ));
            }
            value = format!("{local}@{domain}");
            inbox = created
                .cookie("email")
                .ok_or_else(|| Error::unsupported(format!("emailtemp: {value} is taken")))?;
        }
        let state = serde_json::to_string(&State {
            site: site.host.to_string(),
            cookie: inbox,
        })
        .expect("serializes");
        Ok(Address::new(value, "emailtemp").with_state(state))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let rows = self.read(a).await?;
        rows.iter()
            .enumerate()
            .map(|(i, r)| row(&J::new("emailtemp", r, &format!("messages[{i}]"))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let rows = self.read(a).await?;
        let Some(raw) = rows.iter().find(|r| match &r["id"] {
            Value::String(s) => s == id,
            other => other.as_i64().is_some_and(|n| id.parse() == Ok(n)),
        }) else {
            return Err(Error::gone("emailtemp", id));
        };
        let j = J::new("emailtemp", raw, "message");
        let html = j
            .at("content")?
            .str()
            .map_err(|_| j.drift("an HTML 'content' on the row"))?
            .to_string();
        let r = row(&j)?;
        Ok(Message::from_bodies(
            id,
            r.sender,
            r.subject,
            r.received_at,
            html,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use crate::transport::HttpRequest;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/emailtemp");
    const ET: &str = "https://emailtemp.org";
    const EG: &str = "https://www.emailgenerator.org";

    struct Host {
        base: &'static str,
        session: &'static str,
        tag: &'static str,
        first: &'static str,
    }

    const HOSTS: &[Host] = &[
        Host {
            base: ET,
            session: "emailtemp_session",
            tag: "emailtemp",
            first: "emailtemp_messages_1.json",
        },
        Host {
            base: EG,
            session: "emailgenerator_session",
            tag: "emailgenerator",
            first: "emailgenerator_messages_1_synthetic.json",
        },
    ];

    fn raw(name: &str) -> String {
        Fixtures::load_text(DIR, name)
    }

    fn json(name: &str) -> Reply {
        Reply::json(Fixtures::load(DIR, name))
    }

    /// The route for a listing of one mailbox: the CSRF form plus the session
    /// and `email` cookies, so it outranks the bare mint and never matches
    /// /create.
    fn listing(h: &Host, inbox: &str) -> String {
        format!(
            "POST {}/messages? _token=fixture-csrf-token&captcha= {}={}-session&email={}-{inbox}",
            h.base, h.session, h.tag, h.tag
        )
    }

    fn wire() -> Arc<Fixtures> {
        let mut w = Fixtures::new();
        for h in HOSTS {
            let tag = h.tag;
            w = w
                .route(
                    &format!("GET {}/en", h.base),
                    Reply::text(raw(&format!("{tag}_home.html")))
                        .set_cookie(h.session, &format!("{tag}-session")),
                )
                // generate(): the session cookie alone, so the site mints a mailbox.
                .route_seq(
                    &format!("POST {}/messages", h.base),
                    [
                        json(&format!("{tag}_messages_new_1.json"))
                            .set_cookie("email", &format!("{tag}-inbox-1")),
                        json(&format!("{tag}_messages_new_2.json"))
                            .set_cookie("email", &format!("{tag}-inbox-2")),
                    ],
                )
                .route(&listing(h, "inbox-1"), json(h.first))
                .route(
                    &listing(h, "inbox-2"),
                    json(&format!("{tag}_messages_new_2.json")),
                )
                .route(
                    &format!("POST {}/create", h.base),
                    Reply::status(302).set_cookie("email", &format!("{tag}-named")),
                );
        }
        w
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(EmailTemp {
            http: w.transport("emailtemp", &CAPS),
        })
    }

    fn state(site: &str, cookie: &str) -> String {
        serde_json::to_string(&State {
            site: site.into(),
            cookie: cookie.into(),
        })
        .unwrap()
    }

    fn emailtemp() -> Address {
        Address::new("cbtb77b22c1@tormails.com", "emailtemp")
            .with_state(state("emailtemp.org", "emailtemp-inbox-1"))
    }

    fn empty() -> Address {
        Address::new("jtxpyxa689@tormails.com", "emailtemp")
            .with_state(state("emailtemp.org", "emailtemp-inbox-2"))
    }

    fn generator() -> Address {
        Address::new("ljegjla768@grnail.cam", "emailtemp")
            .with_state(state("emailgenerator.org", "emailgenerator-inbox-1"))
    }

    fn sent(w: &Fixtures, method: &str, url: &str) -> Vec<HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| r.method.as_str() == method && r.url == url)
            .collect()
    }

    fn form(r: &HttpRequest) -> Vec<(String, String)> {
        match &r.body {
            crate::transport::Body::Form(p) => p.clone(),
            other => panic!("not a form: {other:?}"),
        }
    }

    fn field(r: &HttpRequest, k: &str) -> String {
        form(r).into_iter().find(|(n, _)| n == k).unwrap().1
    }

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn opts(local: Option<&str>, domain: Option<&str>) -> GenerateOptions {
        GenerateOptions {
            local: local.map(Into::into),
            domain: domain.map(Into::into),
            ..Default::default()
        }
    }

    fn parsed(a: &Address) -> State {
        serde_json::from_str(a.state.as_deref().unwrap()).unwrap()
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn it_asks_for_a_fresh_session_per_request() {
        // The mailbox is the `email` cookie; on a shared jar a second
        // generate() would get the first mailbox back.
        const { assert!(CAPS.fresh_session) };
        const { assert!(CAPS.needs_state) };
    }

    #[test]
    fn it_covers_both_hosts_of_the_script() {
        let hosts: Vec<&str> = SITES.iter().map(|s| s.host).collect();
        assert_eq!(CAPS.sites, hosts.as_slice());
        const { assert!(CAPS.custom_local) };
        let flat: Vec<&str> = SITES
            .iter()
            .flat_map(|s| s.domains.iter().copied())
            .collect();
        assert_eq!(DOMAINS, flat.as_slice());
    }

    #[tokio::test]
    async fn generate_goes_only_to_the_host_serving_the_domain() {
        for (domain, host) in [
            ("tormails.com", "emailtemp.org"),
            ("grnail.cam", "www.emailgenerator.org"),
        ] {
            let w = wire();
            let a = build(&w).generate(&opts(None, Some(domain))).await.unwrap();
            assert!(a.value.ends_with(&format!("@{domain}")), "{}", a.value);
            let hosts: std::collections::HashSet<String> = w
                .seen()
                .iter()
                .map(|r| r.url.split('/').nth(2).unwrap().to_string())
                .collect();
            assert_eq!(hosts, [host.to_string()].into());
        }
    }

    #[tokio::test]
    async fn generate_replays_the_session_and_csrf_into_messages() {
        let w = wire();
        let a = build(&w)
            .generate(&opts(None, Some("tormails.com")))
            .await
            .unwrap();
        let posts = sent(&w, "POST", &format!("{ET}/messages"));
        assert_eq!(posts.len(), 1);
        assert_eq!(
            form(&posts[0]),
            pairs(&[("_token", "fixture-csrf-token"), ("captcha", "")])
        );
        assert_eq!(
            posts[0].cookies,
            pairs(&[("emailtemp_session", "emailtemp-session")])
        );
        assert_eq!(posts[0].header("X-Requested-With"), Some("XMLHttpRequest"));
        assert_eq!(a.value, "cbtb77b22c1@tormails.com");
        let st = parsed(&a);
        assert_eq!(
            (st.site.as_str(), st.cookie.as_str()),
            ("emailtemp.org", "emailtemp-inbox-1")
        );
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn a_domain_the_random_mailbox_missed_is_claimed_through_create() {
        // emailgenerator hands out any of its domains; the first mailbox here
        // is on grnail.cam, so asking for mymail.edu.pl goes through /create.
        let w = wire();
        let a = build(&w)
            .generate(&opts(None, Some("mymail.edu.pl")))
            .await
            .unwrap();
        assert!(a.value.ends_with("@mymail.edu.pl"));
        let create = sent(&w, "POST", &format!("{EG}/create"));
        assert_eq!(create.len(), 1);
        assert_eq!(field(&create[0], "domain"), "mymail.edu.pl");
        assert_eq!(
            a.value,
            format!("{}@mymail.edu.pl", field(&create[0], "name"))
        );
        assert_eq!(parsed(&a).cookie, "emailgenerator-named");
    }

    #[tokio::test]
    async fn a_chosen_local_part_is_created() {
        let w = wire();
        let a = build(&w)
            .generate(&opts(Some("hello"), Some("tormails.com")))
            .await
            .unwrap();
        assert_eq!(a.value, "hello@tormails.com");
        let st = parsed(&a);
        assert_eq!(
            (st.site.as_str(), st.cookie.as_str()),
            ("emailtemp.org", "emailtemp-named")
        );
        let create = sent(&w, "POST", &format!("{ET}/create"));
        assert_eq!(create.len(), 1);
        assert_eq!(
            form(&create[0]),
            pairs(&[
                ("_token", "fixture-csrf-token"),
                ("name", "hello"),
                ("domain", "tormails.com")
            ])
        );
        // /create only works for a session that already holds a mailbox.
        assert_eq!(
            create[0].cookies,
            pairs(&[
                ("emailtemp_session", "emailtemp-session"),
                ("email", "emailtemp-inbox-1")
            ])
        );
    }

    #[tokio::test]
    async fn a_chosen_local_part_without_a_domain_takes_the_minted_domain() {
        let a = build(&wire())
            .generate(&opts(Some("hello"), None))
            .await
            .unwrap();
        // The first minted mailbox on either host: tormails.com or grnail.cam.
        assert!(
            ["hello@tormails.com", "hello@grnail.cam"].contains(&a.value.as_str()),
            "{}",
            a.value
        );
    }

    #[tokio::test]
    async fn a_taken_local_part_is_refused() {
        // The site redirects back to /change and sets no mailbox cookie.
        let w = wire().route(
            &format!("POST {ET}/create"),
            Reply::status(302).header("Location", &format!("{ET}/change")),
        );
        assert!(matches!(
            build(&w)
                .generate(&opts(Some("taken"), Some("tormails.com")))
                .await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_domain_no_host_serves_is_refused() {
        let w = wire();
        assert!(matches!(
            build(&w).generate(&opts(None, Some("gmail.com"))).await,
            Err(Error::NotSupported(_))
        ));
        assert!(w.seen().is_empty());
    }

    #[tokio::test]
    async fn a_home_page_without_a_csrf_token_is_drift() {
        let w = wire().route(&format!("GET {ET}/en"), Reply::text("<html></html>"));
        assert!(matches!(
            build(&w).generate(&opts(None, Some("tormails.com"))).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_forbidden_home_page_is_down_not_drift() {
        // Seen live: emailtemp.org's origin answers every path with Apache's
        // 403 page from some IPs.
        let w = wire().route(
            &format!("GET {ET}/en"),
            Reply::text("<title>403 Forbidden</title>").with_status(403),
        );
        assert!(matches!(
            build(&w).generate(&opts(None, Some("tormails.com"))).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_mailbox_answer_without_the_email_cookie_is_drift() {
        let w = wire().route(
            &format!("POST {ET}/messages"),
            json("emailtemp_messages_new_1.json"),
        );
        assert!(matches!(
            build(&w).generate(&opts(None, Some("tormails.com"))).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn the_mailbox_cookie_is_replayed_on_list_and_get() {
        let w = wire();
        let p = build(&w);
        p.list(&generator()).await.unwrap();
        p.get(&generator(), "SyntheticFixtureId000001")
            .await
            .unwrap();
        let expected = pairs(&[
            ("emailgenerator_session", "emailgenerator-session"),
            ("email", "emailgenerator-inbox-1"),
        ]);
        let posts = sent(&w, "POST", &format!("{EG}/messages"));
        assert_eq!(posts.len(), 2);
        for p in &posts {
            assert_eq!(p.cookies, expected);
            assert_eq!(field(p, "_token"), "fixture-csrf-token");
        }
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&emailtemp()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "86J5Nvyk04lJdJk0RpBwGPzo");
        assert_eq!(rows[0].sender, "Xeramail Test <test@xeramail.com>");
        assert_eq!(rows[0].subject, "Your Email Test is Successful!");
        assert_eq!(
            rows[0].received_at,
            Some("2026-09-25T03:45:37Z".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        assert!(build(&wire()).list(&empty()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_mailbox_the_site_no_longer_knows_is_expired() {
        // An email cookie the site cannot read gets a brand-new mailbox, silently.
        let w = wire().route(
            &listing(&HOSTS[0], "inbox-2"),
            json("emailtemp_messages_1.json"),
        );
        assert!(matches!(
            build(&w).list(&empty()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_listing_it_does_not_recognise_is_drift() {
        for answer in [
            "[]",
            r#"{"mailbox": "cbtb77b22c1@tormails.com"}"#,
            r#"{"mailbox": "cbtb77b22c1@tormails.com", "messages": "none"}"#,
            r#"{"mailbox": "cbtb77b22c1@tormails.com", "messages": [{"subject": "no id"}]}"#,
            r#"{"mailbox": "cbtb77b22c1@tormails.com", "messages": [{"id": "1", "receivedAt": "soon"}]}"#,
            "<html>Page Expired</html>",
        ] {
            let w = wire().route(&listing(&HOSTS[0], "inbox-1"), Reply::text(answer));
            let got = build(&w).list(&emailtemp()).await;
            assert!(
                matches!(got, Err(Error::SchemaDrift { .. })),
                "{answer}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_error_page_is_down_not_drift() {
        // Laravel's 419 for a stale CSRF pair: transient, not a new shape.
        let w = wire().route(
            &listing(&HOSTS[0], "inbox-1"),
            Reply::text("<html>Page Expired</html>").with_status(419),
        );
        assert!(matches!(
            build(&w).list(&emailtemp()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn list_without_usable_state_is_refused() {
        let p = build(&wire());
        for bad in [
            None,
            Some(""),
            Some("not json"),
            Some(r#"{"site": "example.com", "cookie": "x"}"#),
        ] {
            let a = Address {
                state: bad.map(String::from),
                ..emailtemp()
            };
            assert!(
                matches!(p.list(&a).await, Err(Error::NotSupported(_))),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn get_takes_the_body_from_the_row() {
        let m = build(&wire())
            .get(&emailtemp(), "86J5Nvyk04lJdJk0RpBwGPzo")
            .await
            .unwrap();
        assert_eq!(m.sender, "Xeramail Test <test@xeramail.com>");
        assert_eq!(m.received_at, Some("2026-09-25T03:45:37Z".parse().unwrap()));
        assert!(m.html.contains("Congratulations!"));
        assert!(m.text.starts_with("Congratulations!"), "{}", m.text);
    }

    #[tokio::test]
    async fn get_extracts_links() {
        let m = build(&wire())
            .get(&generator(), "SyntheticFixtureId000001")
            .await
            .unwrap();
        assert_eq!(m.links, ["https://example.test/confirm"]);
    }

    #[tokio::test]
    async fn a_message_the_listing_no_longer_has_is_gone() {
        assert!(matches!(
            build(&wire()).get(&emailtemp(), "nope").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_row_without_a_body_is_drift() {
        let answer = serde_json::json!({
            "mailbox": "cbtb77b22c1@tormails.com",
            "messages": [{"id": "1", "from": "a", "from_email": "a@x.test", "subject": "s", "content": null}],
        });
        let w = wire().route(&listing(&HOSTS[0], "inbox-1"), Reply::json(answer));
        assert!(matches!(
            build(&w).get(&emailtemp(), "1").await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
