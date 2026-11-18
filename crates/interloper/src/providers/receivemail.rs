//! receivemail.org: a PHP web client over one catch-all IMAP box.
//!
//! Inboxes are public: anyone can open any address on these domains and read
//! its mail, so do not use one for anything you would not post.
//!
//! The inbox is whichever address user.php last bound to the PHP session.
//! generate() asks user.php for an address (random, or one it names) and keeps
//! the PHPSESSID it sets; on one shared cookie jar a second generate() would
//! rebind the first caller's session, so every request runs on a fresh session
//! and the session id travels in Address::state.
//!
//! mail.php renders the whole inbox as HTML: one `div#mail<id>` per message,
//! the subject and sender in its accordion button, the date (UTC) in an `em`
//! title and the body in an iframe srcdoc. There is no per-message endpoint,
//! so get() reads the same page. PHP drops idle sessions, and mail.php then
//! answers "you cleared your browser cookies"; user.php binds any session id it
//! is sent, so list() binds the old one to the address again and reads once
//! more.
//!
//! actions.php?action=download hands out an .eml URL, but it answered
//! "UnAuthorized" for some sessions and the URL served the home page, so
//! bodies come from the srcdoc instead.

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days};
use crate::parse::unescape;
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::transport::Transport;

const SITE: &str = "https://www.receivemail.org";
const DOMAINS: &[&str] = &["getsomail.com", "ofisher.net", "barooko.com"];

static ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[^@\s<>]+@[^@\s<>]+$").unwrap());
static BLOCK_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"<div id="mail(\d+)">"#).unwrap());
static HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?s)<button class="accordion">(.*?)<br>From : (.*?)</button>"#).unwrap()
});
static DATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"<em title="([^"]+)""#).unwrap());
static BODY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"srcdoc="([^"]*)""#).unwrap());
// What an empty inbox renders: the site's spinner and nothing else.
const EMPTY: &str = "cssload-container";
const NO_SESSION: &str = "cleared your <b>browser cookies</b>";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["receivemail.org"],
    domains: DOMAINS,
    domain_count: DOMAINS.len(),
    // Any address can be opened at any time; nothing expires it.
    address_ttl: None,
    // A floor, not measured: the shared test@ inbox held a 3-day-old message.
    message_ttl: Some(days(3)),
    custom_local: true,
    needs_state: true,
    max_concurrency: 1,
    fresh_session: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "receivemail",
    caps: CAPS,
    build: |t| Arc::new(ReceiveMail { http: t }),
};

pub struct ReceiveMail {
    http: Transport,
}

/// The page's `25-09-2026 03:31:59 am`, which is UTC.
fn at(block: &str) -> Option<jiff::Timestamp> {
    let raw = DATE.captures(block)?.get(1)?.as_str().to_ascii_uppercase();
    let dt = jiff::civil::DateTime::strptime("%d-%m-%Y %I:%M:%S %p", &raw).ok()?;
    jiff::tz::TimeZone::UTC.to_timestamp(dt).ok()
}

/// `Name<addr>` as the page renders it becomes `Name <addr>`.
fn spaced_sender(s: &str) -> String {
    let mut prev: Option<char> = None;
    for (i, c) in s.char_indices() {
        if c == '<' && prev.is_some_and(|p| !p.is_whitespace()) {
            return format!("{} {}", &s[..i], &s[i..]);
        }
        prev = Some(c);
    }
    s.to_string()
}

/// Each `div#mail<id>` and everything up to the next one.
fn blocks(page: &str) -> Vec<(String, String)> {
    let starts: Vec<_> = BLOCK_START.captures_iter(page).collect();
    starts
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let whole = c.get(0).expect("match");
            let end = starts
                .get(i + 1)
                .map_or(page.len(), |n| n.get(0).expect("match").start());
            (c[1].to_string(), page[whole.end()..end].to_string())
        })
        .collect()
}

impl ReceiveMail {
    /// Bind `user` ("" for a random address) to a session; the address and
    /// the PHPSESSID the site set, if it set one.
    async fn bind(&self, user: &str, session: Option<&str>) -> Result<(String, Option<String>)> {
        let mut req = self
            .http
            .get(format!("{SITE}/user.php"))
            .query("user", user);
        if let Some(s) = session {
            req = req.cookie("PHPSESSID", s);
        }
        let resp = req.send().await?;
        // An error page (an origin or WAF refusing this IP) is an outage,
        // not a new page shape: it must not quarantine the adapter.
        if !resp.is_success() {
            return Err(Error::down(
                "receivemail",
                format!("user.php answered HTTP {}", resp.status),
            ));
        }
        let value = resp.text.trim();
        if !ADDRESS.is_match(value) {
            return Err(Error::drift(
                "receivemail",
                "an address from user.php",
                crate::error::clip(value, 200),
            ));
        }
        Ok((value.to_string(), resp.cookie("PHPSESSID")))
    }

    async fn page(&self, session: &str) -> Result<String> {
        let resp = self
            .http
            .get(format!("{SITE}/mail.php"))
            .cookie("PHPSESSID", session)
            .send()
            .await?;
        if !resp.is_success() {
            return Err(Error::down(
                "receivemail",
                format!("mail.php answered HTTP {}", resp.status),
            ));
        }
        Ok(resp.text)
    }

    async fn blocks(&self, a: &Address) -> Result<Vec<(String, String)>> {
        let session = a
            .state
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::unsupported("receivemail needs the session issued by generate()")
            })?;
        let mut page = self.page(session).await?;
        if page.contains(NO_SESSION) {
            self.bind(&a.value, Some(session)).await?;
            page = self.page(session).await?;
            if page.contains(NO_SESSION) {
                return Err(Error::drift(
                    "receivemail",
                    "user.php to bind the session",
                    crate::error::clip(&page, 200),
                ));
            }
        }
        let found = blocks(&page);
        if found.is_empty() && !page.contains(EMPTY) {
            return Err(Error::drift(
                "receivemail",
                "div#mail<id> blocks",
                crate::error::clip(&page, 200),
            ));
        }
        Ok(found)
    }

    fn row(&self, id: &str, block: &str) -> Result<MessageRow> {
        let head = HEAD.captures(block).ok_or_else(|| {
            Error::drift(
                "receivemail",
                "a subject and sender",
                crate::error::clip(block, 200),
            )
        })?;
        let sender = spaced_sender(unescape(&head[2]).trim());
        Ok(MessageRow::new(id, sender, unescape(&head[1]).trim()).at(at(block)))
    }
}

#[async_trait]
impl Provider for ReceiveMail {
    fn name(&self) -> &str {
        "receivemail"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        // Checked before any request: an unserved domain is a caller error.
        let domain = pick_domain("receivemail", opts, DOMAINS)?;
        let wanted = if opts.local.is_some() || opts.domain.is_some() {
            // user.php ignores a bare "@domain", so a domain alone gets a
            // local part here.
            format!("{}@{domain}", local_or_random(opts)).to_lowercase()
        } else {
            String::new()
        };
        let (value, session) = self.bind(&wanted, None).await?;
        if !wanted.is_empty() && value != wanted {
            return Err(Error::unsupported(format!(
                "receivemail would not issue {wanted}; it offered {value}"
            )));
        }
        let session = session
            .ok_or_else(|| Error::drift("receivemail", "a PHPSESSID from user.php", &value))?;
        Ok(Address::new(value, "receivemail").with_state(session))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        self.blocks(a)
            .await?
            .iter()
            .map(|(id, block)| self.row(id, block))
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let found = self.blocks(a).await?;
        let Some((_, block)) = found.iter().find(|(i, _)| i == id) else {
            return Err(Error::gone("receivemail", id));
        };
        let row = self.row(id, block)?;
        // Only HTML mail was seen with a srcdoc. Without one, the body is
        // whatever the panel renders after the date line, not a changed page.
        let html = match BODY.captures(block) {
            Some(c) => unescape(&c[1]),
            None => block
                .split_once("</p>")
                .map(|(_, rest)| rest.to_string())
                .unwrap_or_default(),
        };
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

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/receivemail");
    const USER: &str = "GET https://www.receivemail.org/user.php";
    const MAIL: &str = "GET https://www.receivemail.org/mail.php";
    // Recorded from a throwaway address of our own after one JoltMx test send.
    const OWN: &str = "cb97375b75@getsomail.com";
    const MESSAGE_ID: &str = "10120183";

    fn page(name: &str) -> String {
        Fixtures::load_text(DIR, name)
    }

    fn wire() -> Arc<Fixtures> {
        let mut w = Fixtures::new()
            .route_seq(
                USER,
                [
                    Reply::text("fixture.one@getsomail.com")
                        .set_cookie("PHPSESSID", "fixture-session-1"),
                    Reply::text("fixture.two@getsomail.com")
                        .set_cookie("PHPSESSID", "fixture-session-2"),
                ],
            )
            .route(MAIL, Reply::text(page("mail.html")));
        // The contract's chosen local part, echoed on whichever domain it drew.
        for d in DOMAINS {
            w = w.route(
                &format!("{USER}?user=interlopertest%40{d}"),
                Reply::text(format!("interlopertest@{d}")).set_cookie("PHPSESSID", "s"),
            );
        }
        w
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(ReceiveMail {
            http: w.transport("receivemail", &CAPS),
        })
    }

    fn own() -> Address {
        Address::new(OWN, "receivemail").with_state("fixture-session")
    }

    fn sent(w: &Fixtures, path: &str) -> Vec<crate::transport::HttpRequest> {
        w.seen()
            .into_iter()
            .filter(|r| r.url == format!("{SITE}{path}"))
            .collect()
    }

    fn q(r: &crate::transport::HttpRequest, k: &str) -> Option<String> {
        r.query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    fn utc(s: &str) -> Option<jiff::Timestamp> {
        Some(s.parse().unwrap())
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[test]
    fn it_asks_for_a_fresh_session_per_request() {
        // The inbox is whatever user.php last bound to the PHP session, so on
        // a shared jar two addresses would read one inbox.
        const { assert!(CAPS.fresh_session) };
    }

    #[tokio::test]
    async fn generate_asks_for_a_random_address_and_keeps_the_session() {
        let w = wire();
        let a = build(&w)
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert_eq!(a.value, "fixture.one@getsomail.com");
        assert_eq!(a.state.as_deref(), Some("fixture-session-1"));
        assert!(a.expires_at.is_none());
        let user = sent(&w, "/user.php");
        assert_eq!(user.len(), 1);
        assert_eq!(q(&user[0], "user").as_deref(), Some(""));
        assert!(w.fresh_flags().iter().all(|f| *f));
    }

    #[tokio::test]
    async fn generate_takes_a_chosen_local_part_and_domain() {
        let w = wire().route(
            USER,
            Reply::text("hello@barooko.com").set_cookie("PHPSESSID", "s"),
        );
        let opts = GenerateOptions {
            local: Some("Hello".into()),
            domain: Some("barooko.com".into()),
            ..Default::default()
        };
        let a = build(&w).generate(&opts).await.unwrap();
        assert_eq!(a.value, "hello@barooko.com");
        let user = sent(&w, "/user.php");
        assert_eq!(q(&user[0], "user").as_deref(), Some("hello@barooko.com"));
    }

    #[tokio::test]
    async fn a_domain_alone_gets_a_local_part_picked_for_it() {
        // user.php ignores a bare "@domain" and hands out a random ofisher.net one.
        let w = wire();
        let opts = GenerateOptions {
            domain: Some("barooko.com".into()),
            ..Default::default()
        };
        // The fixture answers getsomail.com, not the barooko.com asked for.
        assert!(matches!(
            build(&w).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
        let user = sent(&w, "/user.php");
        assert_eq!(user.len(), 1);
        let asked = q(&user[0], "user").unwrap();
        let (local, domain) = asked.split_once('@').unwrap();
        assert_eq!(domain, "barooko.com");
        assert!(
            Regex::new(r"^il[0-9a-f]{10}$").unwrap().is_match(local),
            "{local}"
        );
    }

    #[tokio::test]
    async fn a_domain_the_site_does_not_serve_is_refused() {
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
    async fn an_address_the_site_rewrote_is_refused() {
        // It drops characters it does not like: "cb test@" comes back
        // "cbtest@".
        let w = wire().route(
            USER,
            Reply::text("cbtest@getsomail.com").set_cookie("PHPSESSID", "s"),
        );
        let opts = GenerateOptions {
            local: Some("cb test".into()),
            domain: Some("getsomail.com".into()),
            ..Default::default()
        };
        assert!(matches!(
            build(&w).generate(&opts).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn a_user_answer_without_an_address_and_session_is_drift() {
        for answer in [
            Reply::text("fixture@getsomail.com"),
            Reply::text("<html>maintenance</html>").set_cookie("PHPSESSID", "s"),
        ] {
            let w = wire().route(USER, answer);
            assert!(matches!(
                build(&w).generate(&GenerateOptions::default()).await,
                Err(Error::SchemaDrift { .. })
            ));
        }
    }

    #[tokio::test]
    async fn list_reads_the_rows_with_the_session_from_state() {
        let w = wire();
        let rows = build(&w).list(&own()).await.unwrap();
        let mail = sent(&w, "/mail.php");
        assert_eq!(mail.len(), 1);
        assert_eq!(
            mail[0].cookies,
            vec![("PHPSESSID".to_string(), "fixture-session".to_string())]
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, MESSAGE_ID);
        assert_eq!(rows[0].subject, "JoltMx test email (ref 01a0d69eb352)");
        assert_eq!(
            rows[0].sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        // The page's time is UTC: it matched the "Sent: ... UTC" in the body.
        assert_eq!(rows[0].received_at, utc("2026-09-25T03:31:59Z"));
    }

    #[tokio::test]
    async fn an_empty_inbox_is_an_empty_list() {
        let w = wire().route(MAIL, Reply::text(page("mail_empty.html")));
        assert!(build(&w).list(&own()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_lost_session_is_bound_to_the_address_again() {
        // PHP drops idle sessions; user.php binds whatever session id it is sent.
        let w = wire()
            .route_seq(
                MAIL,
                [
                    Reply::text(page("session_lost.html")),
                    Reply::text(page("mail.html")),
                ],
            )
            .route(USER, Reply::text(OWN));
        let rows = build(&w).list(&own()).await.unwrap();
        assert_eq!(
            rows.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            [MESSAGE_ID]
        );
        let user = sent(&w, "/user.php");
        assert_eq!(user.len(), 1);
        assert_eq!(q(&user[0], "user").as_deref(), Some(OWN));
        assert_eq!(
            user[0].cookies,
            vec![("PHPSESSID".to_string(), "fixture-session".to_string())]
        );
    }

    #[tokio::test]
    async fn a_session_that_will_not_bind_is_drift() {
        let w = wire()
            .route(MAIL, Reply::text(page("session_lost.html")))
            .route(USER, Reply::text(OWN));
        assert!(matches!(
            build(&w).list(&own()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn an_error_page_is_down_not_drift() {
        let w = wire().route(MAIL, Reply::text("<h1>Forbidden</h1>").with_status(403));
        assert!(matches!(
            build(&w).list(&own()).await,
            Err(Error::ProviderDown { .. })
        ));
    }

    #[tokio::test]
    async fn a_page_it_does_not_recognise_is_drift() {
        let w = wire().route(MAIL, Reply::text("<html>maintenance</html>"));
        assert!(matches!(
            build(&w).list(&own()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn list_without_the_session_is_refused() {
        let p = build(&wire());
        for bad in [None, Some(String::new())] {
            let a = Address {
                state: bad,
                ..Address::new(OWN, "receivemail")
            };
            assert!(matches!(p.list(&a).await, Err(Error::NotSupported(_))));
        }
    }

    #[tokio::test]
    async fn get_reads_the_body_from_the_srcdoc() {
        let m = build(&wire()).get(&own(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.id, MESSAGE_ID);
        assert_eq!(m.subject, "JoltMx test email (ref 01a0d69eb352)");
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert_eq!(m.received_at, utc("2026-09-25T03:31:59Z"));
        assert!(m.html.contains("<h2"));
        assert!(
            m.text.contains("everything is working as expected"),
            "{}",
            m.text
        );
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
    }

    #[tokio::test]
    async fn a_message_the_page_no_longer_has_is_gone() {
        assert!(matches!(
            build(&wire()).get(&own(), "1").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_message_without_an_iframe_body_still_reads_as_text() {
        // Only HTML mail was seen live. A plain-text mail may render without a
        // srcdoc, and that must not quarantine the provider.
        let plain = Regex::new(r#"<iframe srcdoc="[^"]*"[^>]*>(</iframe>)?"#)
            .unwrap()
            .replace(&page("mail.html"), "<pre>Your code is 482913.</pre>")
            .into_owned();
        let w = wire().route(MAIL, Reply::text(plain));
        let m = build(&w).get(&own(), MESSAGE_ID).await.unwrap();
        assert!(m.text.contains("Your code is 482913."), "{}", m.text);
        assert!(!m.text.contains("Delete"), "{}", m.text);
    }
}
