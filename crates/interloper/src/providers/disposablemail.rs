//! disposablemail.com, fakemail.net and minuteinbox.com: one engine, three
//! front doors.
//!
//! The inbox is a cookie naming the address (TMA on the first two, MI on
//! minuteinbox). generate() loads the home page for its CSRF token and PHP
//! session, then asks /index/index for an address with both; the answer sets
//! the inbox cookie. On a shared jar that cookie makes a second generate()
//! hand back the first address, so every request runs on a fresh session and
//! the host plus the cookie travel in Address::state.
//!
//! /index/refresh lists the inbox and /email/id/<id> serves the decoded HTML
//! body. Both work from a fresh session given only the inbox cookie;
//! /index/email, which carries headers too, answers `false` there, so get()
//! takes sender and subject from the listing row. Rows carry only a relative
//! "13 sec. ago", so received_at is None.
//!
//! fakemail and minuteinbox prefix every body with a UTF-8 BOM, which a JSON
//! parser refuses, so bodies are read as text and stripped.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use rand::seq::IndexedRandom;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::util::no_custom_local;
use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours, minutes};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

struct Site {
    host: &'static str,
    cookie: &'static str,
    // Each host handed out one domain across every session seen in recon.
    domain: &'static str,
    // The life /index/zivot reports for a new inbox.
    // ponytail: /expirace/<secs> extends it up to 14 days; call it from
    // generate() once a caller needs an inbox to outlive this.
    life: Duration,
}

const SITES: [Site; 3] = [
    Site {
        host: "disposablemail.com",
        cookie: "TMA",
        domain: "dropoffs.org",
        life: hours(1),
    },
    Site {
        host: "fakemail.net",
        cookie: "TMA",
        domain: "forliion.com",
        life: hours(1),
    },
    Site {
        host: "minuteinbox.com",
        cookie: "MI",
        domain: "minafter.com",
        life: minutes(10),
    },
];

const XHR: (&str, &str) = ("X-Requested-With", "XMLHttpRequest");
const BOM: char = '\u{feff}';
// What /email/id/<id> answers, with a 200, for an id the inbox lacks.
const NO_BODY: &str = "There was en error";

static CSRF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"const CSRF\s*=\s*"([0-9a-f]+)""#).unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["disposablemail.com", "fakemail.net", "minuteinbox.com"],
    domains: &["dropoffs.org", "forliion.com", "minafter.com"],
    domain_count: 3,
    // The shortest host's (minuteinbox); expires_at carries each host's own.
    address_ttl: Some(minutes(10)),
    // Mail lives as long as its inbox.
    message_ttl: None,
    // The state is the inbox key: whoever holds the cookie reads the mail.
    needs_state: true,
    max_concurrency: 1,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "disposablemail",
    caps: CAPS,
    build: |t| Arc::new(DisposableMail { http: t }),
};

pub struct DisposableMail {
    http: Transport,
}

/// Address::state: the host and the inbox cookie's value, in this field
/// order so it reads the same as cowbird's.
#[derive(Serialize, Deserialize)]
struct State {
    site: String,
    cookie: String,
}

fn base(site: &Site) -> String {
    format!("https://www.{}", site.host)
}

fn unbom(s: &str) -> &str {
    s.trim_start_matches(BOM)
}

fn parse(body: &str) -> Result<Value> {
    serde_json::from_str(unbom(body))
        .map_err(|_| Error::drift("disposablemail", "a JSON body", clip(body, 200)))
}

fn pick(domain: Option<&str>) -> Result<&'static Site> {
    match domain {
        None => Ok(SITES.choose(&mut rand::rng()).expect("three sites")),
        Some(d) => SITES
            .iter()
            .find(|s| s.domain.eq_ignore_ascii_case(d))
            .ok_or_else(|| Error::unsupported(format!("disposablemail has no host serving {d}"))),
    }
}

/// The host and the inbox cookie from Address::state.
fn inbox(a: &Address) -> Result<(&'static Site, (&'static str, String))> {
    let refused = || {
        Error::unsupported("disposablemail needs the host and inbox cookie issued by generate()")
    };
    let state: State = a
        .state
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or_else(refused)?;
    let site = SITES
        .iter()
        .find(|s| s.host == state.site)
        .ok_or_else(refused)?;
    Ok((site, (site.cookie, state.cookie)))
}

#[async_trait]
impl Provider for DisposableMail {
    fn name(&self) -> &str {
        "disposablemail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        no_custom_local("disposablemail", opts)?;
        let site = pick(opts.domain.as_deref())?;
        let home = self.http.get(format!("{}/", base(site))).send().await?;
        let csrf = CSRF.captures(&home.text).map(|c| c[1].to_string());
        let (Some(csrf), Some(session)) = (csrf, home.cookie("PHPSESSID")) else {
            return Err(Error::drift(
                "disposablemail",
                "a CSRF token and PHPSESSID from the home page",
                clip(&home.text, 200),
            ));
        };
        let resp = self
            .http
            .get(format!("{}/index/index", base(site)))
            .query("csrf_token", csrf)
            .header(XHR.0, XHR.1)
            .cookie("PHPSESSID", session)
            .send()
            .await?;
        let v = parse(&resp.text)?;
        let email = v.get("email").and_then(Value::as_str);
        let (Some(email), Some(cookie)) = (email, resp.cookie(site.cookie)) else {
            return Err(Error::drift(
                "disposablemail",
                format!("an 'email' and a {} cookie", site.cookie),
                v,
            ));
        };
        let state = serde_json::to_string(&State {
            site: site.host.into(),
            cookie,
        })
        .expect("state serializes");
        Ok(Address::new(email, "disposablemail")
            .with_state(state)
            .expiring(Some(site.life)))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let (site, (name, value)) = inbox(a)?;
        let body = self
            .http
            .get(format!("{}/index/refresh", base(site)))
            .header(XHR.0, XHR.1)
            .cookie(name, value)
            .text()
            .await?;
        // An inbox the site no longer knows answers with nothing at all.
        if unbom(&body).is_empty() {
            return Err(Error::AddressExpired(format!(
                "disposablemail: {} is gone",
                a.value
            )));
        }
        let v = parse(&body)?;
        // The site's own script reads `false` as "no mail".
        if v == Value::Bool(false) {
            return Ok(vec![]);
        }
        J::new("disposablemail", &v, "refresh")
            .items()?
            .iter()
            .map(|r| Ok(MessageRow::new(r.req_id("id")?, r.s("od"), r.s("predmet"))))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let Some(row) = self.list(a).await?.into_iter().find(|r| r.id == id) else {
            return Err(Error::gone("disposablemail", id));
        };
        let (site, (name, value)) = inbox(a)?;
        let body = self
            .http
            .get(format!(
                "{}/email/id/{}",
                base(site),
                urlencoding::encode(id)
            ))
            .cookie(name, value)
            .text()
            .await?;
        let html = unbom(&body);
        if html.starts_with(NO_BODY) {
            return Err(Error::gone("disposablemail", id));
        }
        Ok(Message::from_bodies(
            id,
            row.sender,
            row.subject,
            row.received_at,
            html,
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/disposablemail");
    const DM: &str = "https://www.disposablemail.com";
    const FM: &str = "https://www.fakemail.net";

    fn raw(n: &str) -> Reply {
        // read_to_string keeps a leading BOM, as the real response text does.
        Reply::text(Fixtures::load_text(DIR, n))
    }

    fn wire() -> Arc<Fixtures> {
        let mut w = Fixtures::new();
        for site in &SITES {
            let tag = site.host.split('.').next().unwrap();
            let b = base(site);
            let f = |n: &str| raw(&format!("{tag}_{n}"));
            w = w
                .route_seq(
                    &format!("GET {b}/?"),
                    [
                        f("home_1.html").set_cookie("PHPSESSID", &format!("{tag}-session-1")),
                        f("home_2.html").set_cookie("PHPSESSID", &format!("{tag}-session-2")),
                    ],
                )
                .route_seq(
                    &format!("GET {b}/index/index"),
                    [
                        f("index_1.json")
                            .set_cookie(site.cookie, &format!("fixture.one%40{}", site.domain)),
                        f("index_2.json")
                            .set_cookie(site.cookie, &format!("fixture.two%40{}", site.domain)),
                    ],
                )
                .route(&format!("GET {b}/index/refresh"), f("refresh.json"))
                .route(&format!("GET {b}/email/id/1"), f("email_1.html"))
                .route(&format!("GET {b}/email/id/"), f("email_missing.html"));
        }
        w
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(DisposableMail {
            http: w.transport("disposablemail", &CAPS),
        })
    }

    fn state(site: &str, cookie: &str) -> String {
        format!(r#"{{"site":"{site}","cookie":"{cookie}"}}"#)
    }

    fn disposable() -> Address {
        Address::new("fixture.one@dropoffs.org", "disposablemail")
            .with_state(state("disposablemail.com", "fixture.one%40dropoffs.org"))
    }

    fn fakemail() -> Address {
        Address::new("fixture.one@forliion.com", "disposablemail")
            .with_state(state("fakemail.net", "fixture.one%40forliion.com"))
    }

    fn on(domain: &str) -> GenerateOptions {
        GenerateOptions {
            domain: Some(domain.into()),
            ..Default::default()
        }
    }

    fn sent(w: &Fixtures, url: &str) -> Vec<crate::transport::HttpRequest> {
        w.seen().into_iter().filter(|r| r.url == url).collect()
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn it_asks_for_a_fresh_session_per_request() {
        // On a shared jar the site answers a second generate() with the first
        // address, because the TMA cookie from the first is still in the jar.
        const { assert!(CAPS.fresh_session) };
    }

    #[test]
    fn it_covers_every_host_of_the_engine() {
        let hosts: Vec<_> = SITES.iter().map(|s| s.host).collect();
        assert_eq!(CAPS.sites, hosts);
        let domains: Vec<_> = SITES.iter().map(|s| s.domain).collect();
        assert_eq!(CAPS.domains, domains);
    }

    #[tokio::test]
    async fn generate_replays_the_home_session_and_csrf_into_index() {
        let w = wire();
        build(&w).generate(&on("dropoffs.org")).await.unwrap();
        let index = sent(&w, &format!("{DM}/index/index"));
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].query, [("csrf_token".into(), "0".repeat(64))]);
        assert_eq!(
            index[0].cookies,
            [("PHPSESSID".into(), "disposablemail-session-1".into())]
        );
        assert_eq!(index[0].header("X-Requested-With"), Some("XMLHttpRequest"));
    }

    #[tokio::test]
    async fn generate_picks_the_host_that_serves_the_domain() {
        let p = build(&wire());
        let before = jiff::Timestamp::now();
        let minute = p.generate(&on("minafter.com")).await.unwrap();
        let hour = p.generate(&on("dropoffs.org")).await.unwrap();
        assert_eq!(minute.value, "fixture.one@minafter.com");
        assert_eq!(hour.value, "fixture.one@dropoffs.org");
        let life = |a: &Address| a.expires_at.unwrap().duration_since(before).as_secs();
        assert!((9 * 60..=11 * 60).contains(&life(&minute)));
        assert!((59 * 60..=61 * 60).contains(&life(&hour)));
    }

    #[tokio::test]
    async fn a_domain_no_host_serves_is_refused() {
        assert!(matches!(
            build(&wire()).generate(&on("gmail.com")).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_chosen_local_part_is_refused() {
        let opts = GenerateOptions {
            local: Some("hello".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&wire()).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_bom_prefixed_answer_parses() {
        let p = build(&wire());
        let a = p.generate(&on("forliion.com")).await.unwrap();
        assert_eq!(a.value, "fixture.one@forliion.com");
        let rows = p.list(&a).await.unwrap();
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r.id.as_str(), r.subject.as_str()))
            .collect();
        assert_eq!(got, [("1", "Welcome to FakeMail:)")]);
    }

    #[tokio::test]
    async fn the_inbox_cookie_from_generate_is_sent_on_list_and_get() {
        let w = wire();
        let p = build(&w);
        let a = p.generate(&on("minafter.com")).await.unwrap();
        p.get(&a, "1").await.unwrap();
        let expected = vec![("MI".to_string(), "fixture.one%40minafter.com".to_string())];
        let b = "https://www.minuteinbox.com";
        let cookies =
            |url: String| -> Vec<_> { sent(&w, &url).into_iter().map(|r| r.cookies).collect() };
        assert_eq!(
            cookies(format!("{b}/index/refresh")),
            std::slice::from_ref(&expected)
        );
        assert_eq!(cookies(format!("{b}/email/id/1")), [expected]);
    }

    #[tokio::test]
    async fn an_index_answer_without_the_inbox_cookie_is_drift() {
        let w = wire().route(
            &format!("GET {DM}/index/index"),
            raw("disposablemail_index_1.json"),
        );
        assert!(matches!(
            build(&w).generate(&on("dropoffs.org")).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn a_home_page_without_a_csrf_token_is_drift() {
        let w = wire().route(
            &format!("GET {DM}/?"),
            Reply::text("<html></html>").set_cookie("PHPSESSID", "s"),
        );
        assert!(matches!(
            build(&w).generate(&on("dropoffs.org")).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn list_reads_the_rows() {
        let rows = build(&wire()).list(&disposable()).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "1");
        assert_eq!(
            rows[0].sender,
            "Disposable Mail Address <Admin@DisposableMail.com>"
        );
        assert_eq!(rows[0].subject, "Welcome to DisposableMail:)");
        // The site only says "13 sec. ago".
        assert!(rows[0].received_at.is_none());
    }

    #[tokio::test]
    async fn an_emptied_inbox_is_an_empty_list() {
        let w = wire().route(
            &format!("GET {FM}/index/refresh"),
            raw("fakemail_refresh_empty.json"),
        );
        assert!(build(&w).list(&fakemail()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn false_from_refresh_is_an_empty_list() {
        // The site's own script treats `false` as "no mail". This body is the
        // engine's real `false` (BOM included), as recorded from its email
        // endpoint.
        let w = wire().route(
            &format!("GET {FM}/index/refresh"),
            raw("fakemail_email_false.json"),
        );
        assert!(build(&w).list(&fakemail()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_inbox_the_site_no_longer_knows_is_expired() {
        let w = wire().route(
            &format!("GET {DM}/index/refresh"),
            raw("disposablemail_refresh_unknown.json"),
        );
        assert!(matches!(
            build(&w).list(&disposable()).await,
            Err(Error::AddressExpired(_))
        ));
    }

    #[tokio::test]
    async fn a_listing_it_does_not_recognise_is_drift() {
        for answer in [
            r#"{"email": "changed"}"#,
            r#"[{"od": "no id"}]"#,
            r#""ok""#,
            "<html>maintenance</html>",
        ] {
            let w = wire().route(&format!("GET {DM}/index/refresh"), Reply::text(answer));
            assert!(
                matches!(
                    build(&w).list(&disposable()).await,
                    Err(Error::SchemaDrift { .. })
                ),
                "{answer}"
            );
        }
    }

    #[tokio::test]
    async fn list_without_usable_state_is_refused() {
        for bad in [
            None,
            Some(""),
            Some("not json"),
            Some(r#"{"site": "example.com", "cookie": "x"}"#),
        ] {
            let mut a = disposable();
            a.state = bad.map(String::from);
            assert!(
                matches!(build(&wire()).list(&a).await, Err(Error::NotSupported(_))),
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn get_reads_the_body_and_takes_the_headers_from_the_row() {
        let m = build(&wire()).get(&fakemail(), "1").await.unwrap();
        assert_eq!(m.id, "1");
        assert_eq!(m.sender, "Fake Mail <Admin@FakeMail.net>");
        assert_eq!(m.subject, "Welcome to FakeMail:)");
        assert!(!m.html.starts_with(BOM));
        assert!(
            m.text.starts_with("Your private mailbox is protected"),
            "{}",
            m.text
        );
        assert!(
            m.links.iter().any(|l| l == "https://www.fakemail.net/"),
            "{:?}",
            m.links
        );
    }

    #[tokio::test]
    async fn a_message_the_listing_no_longer_has_is_gone() {
        assert!(matches!(
            build(&wire()).get(&disposable(), "2").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_body_the_site_cannot_load_is_gone() {
        let w = wire().route(
            &format!("GET {FM}/email/id/1"),
            raw("fakemail_email_missing.html"),
        );
        assert!(matches!(
            build(&w).get(&fakemail(), "1").await,
            Err(Error::MessageGone { .. })
        ));
    }
}
