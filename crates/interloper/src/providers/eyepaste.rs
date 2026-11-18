//! eyepaste.com: a public inbox read through its RSS feed.
//!
//! Any local part at eyepaste.com receives, and anyone who knows the address
//! can read the box: there is no login, no token and no PIN. Callers should
//! use an unguessable local part; generate() picks a long random one.
//!
//! The feed is the only machine-readable view (the HTML inbox hides addresses
//! behind Cloudflare's email obfuscation). Each item carries a
//! From/To/Subject/Date block, then the mail's raw body with every newline
//! swapped for `<br/>`. The mail's own headers are gone, so a multipart body
//! arrives as bare boundary lines. Items have no id, so one is derived from
//! the date, sender and subject, as cowbird derived it.
//!
//! Core has no RSS reader, so this module carries a minimal one for the
//! feed's fixed item shape. A multipart body gets its stripped top-level
//! header back and goes to [`crate::mime::parse`].

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use rand::Rng;
use regex::Regex;

use super::util::pick_domain;
use crate::error::{Error, Result, clip};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, hours};
use crate::parse::unescape;
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::transport::Transport;

const SITE: &str = "https://www.eyepaste.com";
const DOMAIN: &str = "eyepaste.com";

static HTML: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<(html|body|div|p|table|a|br)\b").unwrap());
static ITEM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)<item>(.*?)</item>").unwrap());

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &[DOMAIN],
    domains: &[DOMAIN],
    domain_count: 1,
    address_ttl: None,
    // The site says mail drops after an hour; mail 35 hours old was still in
    // a feed when this adapter was written.
    message_ttl: Some(hours(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "eyepaste",
    caps: CAPS,
    build: |t| Arc::new(Eyepaste { http: t }),
};

pub struct Eyepaste {
    http: Transport,
}

struct Item {
    id: String,
    sender: String,
    subject: String,
    received_at: Option<jiff::Timestamp>,
    body: String,
}

/// The server encodes its UTF-8 bytes as UTF-8 a second time: an em dash
/// arrives as "â\u{80}\u{94}". Undo that, and leave a feed alone that it
/// breaks.
fn repair(feed: String) -> String {
    let bytes: Option<Vec<u8>> = feed.chars().map(|c| u8::try_from(c).ok()).collect();
    bytes
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or(feed)
}

/// cowbird's id: the first 16 hex digits of SHA-256 over date, sender and
/// subject joined by newlines.
fn digest(s: &str) -> String {
    crate::hash::sha256_hex(s.as_bytes(), 16)
}

fn at(value: &str) -> Option<jiff::Timestamp> {
    jiff::fmt::rfc2822::parse(value.trim())
        .map(|z| z.timestamp())
        .ok()
        .or_else(|| crate::shape::parse_time(value))
}

/// The text of `<name>` in an item: CDATA verbatim, the rest unescaped.
fn text_of(item: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = item.find(&open)? + open.len();
    let end = start + item[start..].find(&format!("</{name}>"))?;
    let mut inner = &item[start..end];
    let mut out = String::new();
    while let Some(i) = inner.find("<![CDATA[") {
        out.push_str(&unescape(&inner[..i]));
        let rest = &inner[i + 9..];
        let j = rest.find("]]>").unwrap_or(rest.len());
        out.push_str(&rest[..j]);
        inner = rest.get(j + 3..).unwrap_or("");
    }
    out.push_str(&unescape(inner));
    Some(out)
}

fn item(node: &str) -> Item {
    let description = text_of(node, "description").unwrap_or_default();
    let (head, rest) = description.split_once("</p>").unwrap_or((&description, ""));
    let mut sender = String::new();
    let mut subject = String::new();
    let mut date = String::new();
    for line in head.replace("<p>", "").split("<br/>") {
        // Python's partition: a line without ": " is a key with no value.
        let line = line.trim();
        let (k, v) = line.split_once(": ").unwrap_or((line, ""));
        match k {
            "From" => sender = v.trim().to_string(),
            "Subject" => subject = v.trim().to_string(),
            "Date" => date = v.trim().to_string(),
            _ => {}
        }
    }
    let rest = rest.trim();
    let rest = rest.strip_prefix("<p>").unwrap_or(rest);
    let body = rest.strip_suffix("</p>").unwrap_or(rest).trim();
    let date = text_of(node, "pubdate")
        .filter(|d| !d.is_empty())
        .unwrap_or(date)
        .trim()
        .to_string();
    Item {
        id: digest(&format!("{date}\n{sender}\n{subject}")),
        received_at: at(&date),
        sender,
        subject,
        body: body
            .replace("<br/>", "\n")
            .trim_start_matches('\u{feff}')
            .to_string(),
    }
}

/// (html, text) from a body whose own headers were stripped.
fn split(body: &str) -> Result<(String, String)> {
    let first = body.split('\n').next().unwrap_or("").trim();
    if first.len() > 2
        && let Some(boundary) = first.strip_prefix("--")
    {
        let mail = crate::mime::parse(&format!(
            "Content-Type: multipart/mixed; boundary=\"{boundary}\"\n\n{body}"
        ));
        if let Some(charset) = mail.unknown_charset {
            return Err(Error::drift(
                "eyepaste",
                "a charset this adapter knows",
                charset,
            ));
        }
        let html = mail.html.unwrap_or_default();
        let text = mail
            .text
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| crate::parse::html_to_text(&html));
        return Ok((html, text));
    }
    if HTML.is_match(body) {
        return Ok((body.to_string(), crate::parse::html_to_text(body)));
    }
    Ok((String::new(), body.to_string()))
}

impl Eyepaste {
    async fn items(&self, a: &Address) -> Result<Vec<Item>> {
        let feed = repair(
            self.http
                .get(format!("{SITE}/inbox/{}.rss", a.value))
                .text()
                .await?,
        )
        // What an XML parser does to line ends, so ids match cowbird's.
        .replace("\r\n", "\n")
        .replace('\r', "\n");
        // RSS never needs a DTD, and a DTD is the only way entity expansion
        // reaches a parser. Refuse it outright. Only the prolog counts: a mail
        // body in CDATA may carry its own <!DOCTYPE html>.
        let prolog = feed.split("<rss").next().unwrap_or("").to_ascii_lowercase();
        if prolog.contains("<!doctype") || prolog.contains("<!entity") {
            return Err(Error::drift(
                "eyepaste",
                "an RSS feed without a DTD",
                clip(&feed, 200),
            ));
        }
        if !feed.contains("<rss") || !feed.contains("<channel>") || !feed.contains("</channel>") {
            return Err(Error::drift(
                "eyepaste",
                "an RSS <channel>",
                clip(&feed, 200),
            ));
        }
        Ok(ITEM.captures_iter(&feed).map(|c| item(&c[1])).collect())
    }
}

#[async_trait]
impl Provider for Eyepaste {
    fn name(&self) -> &str {
        "eyepaste"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let domain = pick_domain("eyepaste", opts, &[DOMAIN])?;
        // Longer than util::random_local: the inbox is readable by anyone who
        // guesses the address.
        let local = opts
            .local
            .clone()
            .unwrap_or_else(|| format!("il{:016x}", rand::rng().random::<u64>()));
        Ok(Address::new(format!("{local}@{domain}"), "eyepaste"))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        Ok(self
            .items(a)
            .await?
            .into_iter()
            .map(|i| MessageRow::new(i.id, i.sender, i.subject).at(i.received_at))
            .collect())
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        // ponytail: re-reads the whole feed per message; the feed is the only
        // source.
        let Some(i) = self.items(a).await?.into_iter().find(|i| i.id == id) else {
            return Err(Error::gone("eyepaste", id));
        };
        let (html, text) = split(&i.body)?;
        Ok(Message::from_bodies(
            id,
            i.sender,
            i.subject,
            i.received_at,
            html,
            Some(text),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/eyepaste");
    const INBOX: &str = "GET https://www.eyepaste.com/inbox/";

    // Synthetic, not recorded: a single-part HTML mail in the recorded item
    // shape. The feed drops the mail's own headers, so no boundary line opens
    // the body.
    const SINGLE_PART: &str = r#"<rss version='2.0'><channel><title>x</title>
<item>
<title><![CDATA[ Sender <s@example.test>: Hello there ]]></title>
<link>https://www.eyepaste.com/inbox/x@eyepaste.com</link>
<description>
<![CDATA[
    <p>
      From: Sender <s@example.test>
      <br/>
      To: x@eyepaste.com
      <br/>
      Subject: Hello there
      <br/>
      Date: Thu, 24 Sep 2026 22:58:55 +0700
      <br/>
    </p>
    <p>
      <html><br/><body><br/><p>Your code is 123456</p><br/><a href="https://example.test/go">go</a><br/></body><br/></html>
    </p>
]]>
</description>
<pubdate>
Thu, 24 Sep 2026 22:58:55 +0700
</pubdate>
</item></channel></rss>"#;

    fn feed(n: &str) -> String {
        Fixtures::load_text(DIR, n)
    }

    fn wire() -> Arc<Fixtures> {
        Fixtures::new().route(INBOX, Reply::text(feed("inbox.rss")))
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Eyepaste {
            http: w.transport("eyepaste", &CAPS),
        })
    }

    fn with_feed(body: impl Into<String>) -> Arc<dyn Provider> {
        build(&wire().route(INBOX, Reply::text(body)))
    }

    fn address() -> Address {
        Address::new("cb3635adc9019e@eyepaste.com", "eyepaste")
    }

    fn ts(s: &str) -> Option<jiff::Timestamp> {
        Some(s.parse().unwrap())
    }

    async fn only(p: &Arc<dyn Provider>) -> MessageRow {
        let mut rows = p.list(&address()).await.unwrap();
        assert_eq!(rows.len(), 1);
        rows.remove(0)
    }

    crate::contract_tests!(SPEC, build(&wire()));

    #[tokio::test]
    async fn the_inbox_feed_is_read_by_address() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        assert_eq!(
            w.seen().pop().unwrap().url,
            format!("https://www.eyepaste.com/inbox/{}.rss", address().value)
        );
    }

    #[tokio::test]
    async fn a_row_carries_sender_subject_and_utc_date() {
        let row = only(&build(&wire())).await;
        assert_eq!(
            row.sender,
            "JoltMx Delivery Test <test@sendtest.joltmx.com>"
        );
        assert_eq!(row.subject, "JoltMx test email (ref 01a0d69e20c2)");
        assert_eq!(row.received_at, ts("2026-09-25T03:31:22Z"));
    }

    #[tokio::test]
    async fn ids_match_cowbird_byte_for_byte() {
        // Expected values from cowbird's `_item` run on the same feeds.
        assert_eq!(only(&build(&wire())).await.id, "8715ea1667857075");
        assert_eq!(only(&with_feed(SINGLE_PART)).await.id, "f732b7f4d23ddf9b");
    }

    #[test]
    fn non_utf8_parts_decode_exactly() {
        // Previously a KOI8-R or ISO-2022-JP part decoded as lossy UTF-8.
        // cowbird's `_split` gives the same pair for this body.
        let body = "--b\nContent-Type: text/plain; charset=koi8-r\nContent-Transfer-Encoding: base64\n\n8NLJ18XU\n--b\nContent-Type: text/html; charset=iso-2022-jp\nContent-Transfer-Encoding: base64\n\nGyRCRnxLXDhsGyhC\n--b--";
        assert_eq!(split(body).unwrap(), ("日本語".into(), "Привет".into()));
    }

    #[tokio::test]
    async fn the_derived_id_is_stable_across_reads() {
        let first = only(&build(&wire())).await;
        let second = only(&build(&wire())).await;
        assert!(!first.id.is_empty());
        assert_eq!(first.id, second.id);
    }

    #[tokio::test]
    async fn an_empty_feed_is_an_empty_list() {
        let p = with_feed(feed("inbox_empty.rss"));
        assert!(p.list(&address()).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn get_splits_the_multipart_body() {
        let p = build(&wire());
        let row = only(&p).await;
        let m = p.get(&address(), &row.id).await.unwrap();
        assert_eq!(m.id, row.id);
        assert_eq!(m.subject, row.subject);
        assert!(m.text.contains("everything is working as expected"));
        assert!(!m.text.contains("Content-Type"), "{}", m.text);
        assert!(m.html.contains("<h2"));
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/"))
        );
    }

    #[tokio::test]
    async fn the_double_encoded_feed_is_repaired() {
        let p = build(&wire());
        let row = only(&p).await;
        let m = p.get(&address(), &row.id).await.unwrap();
        assert!(m.text.contains("JoltMx — email routing"), "{}", m.text);
    }

    #[tokio::test]
    async fn a_single_part_html_body_is_kept_as_html() {
        let p = with_feed(SINGLE_PART);
        let row = only(&p).await;
        let m = p.get(&address(), &row.id).await.unwrap();
        assert_eq!(row.received_at, ts("2026-09-24T15:58:55Z"));
        assert!(m.text.contains("123456"));
        assert!(!m.html.contains("<br/>"));
        assert_eq!(m.links, ["https://example.test/go"]);
    }

    #[tokio::test]
    async fn a_part_in_an_unknown_charset_is_drift_not_a_crash() {
        let unknown = feed("inbox.rss").replace("charset=utf-8", "charset=x-no-such-charset");
        let p = with_feed(unknown);
        let row = only(&p).await;
        assert!(matches!(
            p.get(&address(), &row.id).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn an_id_no_longer_in_the_feed_is_gone() {
        assert!(matches!(
            build(&wire()).get(&address(), "0123456789abcdef").await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_feed_that_is_not_xml_is_drift() {
        assert!(matches!(
            with_feed("<html>oops").list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[tokio::test]
    async fn generate_honours_a_chosen_local_part() {
        let opts = GenerateOptions {
            local: Some("hello".into()),
            domain: Some("eyepaste.com".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "hello@eyepaste.com");
    }

    #[tokio::test]
    async fn a_generated_local_part_is_long_enough_to_be_unguessable() {
        let a = build(&wire())
            .generate(&GenerateOptions::default())
            .await
            .unwrap();
        assert!(a.local().len() >= 18, "{}", a.value);
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
    async fn a_feed_that_declares_a_dtd_is_refused_before_parsing() {
        // RSS never needs a DTD; one is the only way to smuggle entity
        // expansion into a parser, so it is refused outright.
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>"#;
        assert!(matches!(
            with_feed(bomb).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }

    #[test]
    fn quoted_printable_and_base64_parts_decode() {
        let body = "--b\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\ncaf=C3=A9 =\nok\n--b\nContent-Type: text/html; charset=utf-8\nContent-Transfer-Encoding: base64\n\nPHA+aGk8L3A+\n--b--";
        let (html, text) = split(body).unwrap();
        assert_eq!(text, "café ok");
        assert_eq!(html, "<p>hi</p>");
    }

    #[test]
    fn nested_alternative_inside_mixed_is_found() {
        let body = "--o\nContent-Type: multipart/alternative; boundary=\"i\"\n\n--i\nContent-Type: text/html\n\n<b>x</b>\n--i--\n--o\nContent-Type: text/html\nContent-Disposition: attachment\n\n<i>no</i>\n--o--";
        let (html, _) = split(body).unwrap();
        assert_eq!(html, "<b>x</b>");
    }
}
