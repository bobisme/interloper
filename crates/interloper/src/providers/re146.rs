//! mail.re146.dev: an open REST API, described at /api/swagger-json.
//!
//! Any local part at a served domain receives, so generate() only fetches the
//! domain list. The inbox is keyed by md5 of the address, not the address
//! itself, and a message is served as its raw RFC 822 source.
//!
//! The domains churn (several are throwaway registrations), so they are
//! fetched, never hardcoded.
//!
//! Core has neither an MD5 nor a MIME parser, so both live at the bottom of
//! this file, cut down to what this backend serves.

use std::sync::Arc;

use async_trait::async_trait;

use super::util::{local_or_random, pick_domain};
use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow, days, hours};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;
use crate::shape::J;
use crate::transport::Transport;

const SITE: &str = "https://mail.re146.dev";

pub const CAPS: Capabilities = Capabilities {
    kind: &[Kind::OwnDomain],
    sites: &["mail.re146.dev"],
    domain_count: 13,
    // From the site's own listing; not measured here.
    address_ttl: Some(days(1)),
    message_ttl: Some(hours(1)),
    custom_local: true,
    ..Capabilities::DEFAULT
};

pub const SPEC: ProviderSpec = ProviderSpec {
    name: "re146",
    caps: CAPS,
    build: |t| Arc::new(Re146 { http: t }),
};

pub struct Re146 {
    http: Transport,
}

fn key(a: &Address) -> String {
    md5_hex(a.value.to_lowercase().as_bytes())
}

#[async_trait]
impl Provider for Re146 {
    fn name(&self) -> &str {
        "re146"
    }

    fn caps(&self) -> &Capabilities {
        &CAPS
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        let v = self.http.get(format!("{SITE}/api/domains")).json().await?;
        let j = J::new("re146", &v, "/api/domains");
        let domains = j
            .items()?
            .iter()
            .map(|d| d.str().map(String::from))
            .collect::<Result<Vec<_>>>()?;
        if domains.is_empty() {
            return Err(j.drift("a non-empty list of domain names"));
        }
        let domain = pick_domain("re146", opts, &domains)?;
        Ok(Address::new(
            format!("{}@{domain}", local_or_random(opts)),
            "re146",
        ))
    }

    async fn list(&self, a: &Address) -> Result<Vec<MessageRow>> {
        let v = self
            .http
            .get(format!("{SITE}/api/messages/{}", key(a)))
            .json()
            .await?;
        J::new("re146", &v, "/api/messages")
            .items()?
            .iter()
            .map(|r| {
                Ok(
                    MessageRow::new(r.req_id("id")?, r.s("from"), r.s("subject"))
                        .at(r.time("receivedAt")),
                )
            })
            .collect()
    }

    async fn get(&self, a: &Address, id: &str) -> Result<Message> {
        let resp = self
            .http
            .get(format!(
                "{SITE}/storage/{}/{}",
                key(a),
                urlencoding::encode(id)
            ))
            .send()
            .await?;
        if resp.status == 404 {
            return Err(Error::gone("re146", id));
        }
        if resp.status >= 400 {
            return Err(Error::down(
                "re146",
                format!("storage answered HTTP {}", resp.status),
            ));
        }
        let raw = &resp.text;
        let (headers, _) = mime::split(raw);
        let html = mime::body(raw, "html").unwrap_or_default();
        let text = mime::body(raw, "plain");
        let received = mime::header(&headers, "Date")
            .and_then(|d| jiff::fmt::rfc2822::parse(d.trim()).ok())
            .map(|z| z.timestamp());
        Ok(Message::from_bodies(
            id,
            mime::header(&headers, "From")
                .map(mime::decode_words)
                .unwrap_or_default(),
            mime::header(&headers, "Subject")
                .map(mime::decode_words)
                .unwrap_or_default(),
            received,
            html,
            text,
        ))
    }
}

/// RFC 1321. Only ever fed an address, so speed is beside the point.
fn md5_hex(input: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let mut st: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = input.to_vec();
    let bits = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(bits.to_le_bytes());
    for chunk in msg.chunks(64) {
        let m: Vec<u32> = chunk
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let [mut a, mut b, mut c, mut d] = st;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i]));
        }
        for (s, v) in st.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    st.iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Just enough RFC 2045/2047 to pull the text and HTML bodies out of a
/// message: nested multipart, base64 and quoted-printable, and encoded-word
/// headers.
mod mime {
    use std::sync::LazyLock;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use regex::Regex;

    pub type Headers = Vec<(String, String)>;

    /// Headers (unfolded) and the body after the first blank line.
    pub fn split(raw: &str) -> (Headers, &str) {
        let (head, body) = match raw.find("\r\n\r\n") {
            Some(i) if raw.find("\n\n").is_none_or(|j| i < j) => (&raw[..i], &raw[i + 4..]),
            _ => match raw.find("\n\n") {
                Some(j) => (&raw[..j], &raw[j + 2..]),
                None => (raw, ""),
            },
        };
        let mut headers: Headers = Vec::new();
        for line in head.lines() {
            if line.starts_with([' ', '\t']) {
                if let Some((_, v)) = headers.last_mut() {
                    v.push(' ');
                    v.push_str(line.trim());
                }
            } else if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
        (headers, body)
    }

    pub fn header<'a>(h: &'a Headers, name: &str) -> Option<&'a str> {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `type/subtype` (lowercased) and one parameter of a header value.
    fn param(value: &str, name: &str) -> Option<String> {
        value.split(';').skip(1).find_map(|p| {
            let (k, v) = p.split_once('=')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().trim_matches('"').to_string())
        })
    }

    fn mime_type(value: &str) -> String {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
    }

    /// The first `text/<subtype>` body that is not an attachment, decoded.
    pub fn body(raw: &str, subtype: &str) -> Option<String> {
        let (h, body) = split(raw);
        let ctype = header(&h, "Content-Type").unwrap_or("text/plain");
        let kind = mime_type(ctype);
        if kind.starts_with("multipart/") {
            let boundary = param(ctype, "boundary")?;
            let delim = format!("--{boundary}");
            let mut parts = body.split(delim.as_str()).skip(1);
            return parts.find_map(|p| {
                if p.starts_with("--") {
                    return None;
                }
                let p = p
                    .strip_prefix("\r\n")
                    .or_else(|| p.strip_prefix('\n'))
                    .unwrap_or(p);
                body_of_part(p, subtype)
            });
        }
        if header(&h, "Content-Disposition").is_some_and(|d| mime_type(d) == "attachment") {
            return None;
        }
        if kind != format!("text/{subtype}") {
            return None;
        }
        let cte = header(&h, "Content-Transfer-Encoding")
            .unwrap_or("7bit")
            .trim()
            .to_ascii_lowercase();
        let bytes = match cte.as_str() {
            "base64" => {
                let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
                STANDARD
                    .decode(clean)
                    .unwrap_or_else(|_| body.as_bytes().to_vec())
            }
            "quoted-printable" => quoted_printable(body, false),
            _ => body.as_bytes().to_vec(),
        };
        Some(decode_charset(&bytes, param(ctype, "charset").as_deref()))
    }

    fn body_of_part(p: &str, subtype: &str) -> Option<String> {
        // Trailing CRLF before the next delimiter belongs to the delimiter.
        let p = p
            .strip_suffix("\r\n")
            .or_else(|| p.strip_suffix('\n'))
            .unwrap_or(p);
        body(p, subtype)
    }

    /// UTF-8 and the Latin-1 family decode exactly. Anything else decodes as
    /// lossy UTF-8: cowbird raised drift for a charset Python lacked, but one
    /// odd message must not quarantine the provider, and this list is far
    /// shorter than Python's.
    fn decode_charset(bytes: &[u8], charset: Option<&str>) -> String {
        let cs = charset.unwrap_or("us-ascii").to_ascii_lowercase();
        match cs.as_str() {
            "iso-8859-1" | "latin1" | "latin-1" | "windows-1252" | "cp1252" => {
                bytes.iter().map(|&b| b as char).collect()
            }
            _ => String::from_utf8_lossy(bytes).into_owned(),
        }
    }

    fn quoted_printable(s: &str, underscores: bool) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'=' if b.get(i + 1) == Some(&b'\r') && b.get(i + 2) == Some(&b'\n') => i += 3,
                b'=' if b.get(i + 1) == Some(&b'\n') => i += 2,
                b'=' if i + 2 < b.len() => {
                    let hex = |c: u8| (c as char).to_digit(16);
                    match (hex(b[i + 1]), hex(b[i + 2])) {
                        (Some(hi), Some(lo)) => {
                            out.push((hi * 16 + lo) as u8);
                            i += 3;
                        }
                        _ => {
                            out.push(b'=');
                            i += 1;
                        }
                    }
                }
                b'_' if underscores => {
                    out.push(b' ');
                    i += 1;
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }

    static WORD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"=\?([^?]+)\?([bBqQ])\?([^?]*)\?=").unwrap());
    static BETWEEN_WORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\?=)\s+(=\?)").unwrap());

    /// RFC 2047 encoded words in a header value. Whitespace between two
    /// adjacent encoded words is not part of the text.
    pub fn decode_words(value: &str) -> String {
        let joined = BETWEEN_WORDS.replace_all(value, "$1$2");
        WORD.replace_all(&joined, |c: &regex::Captures<'_>| {
            let bytes = if c[2].eq_ignore_ascii_case("b") {
                STANDARD.decode(&c[3]).unwrap_or_default()
            } else {
                quoted_printable(&c[3], true)
            };
            decode_charset(&bytes, Some(&c[1]))
        })
        .into_owned()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn quoted_printable_and_soft_breaks() {
            let raw = "Content-Type: text/plain; charset=utf-8\n\
                       Content-Transfer-Encoding: quoted-printable\n\n\
                       caf=C3=A9 code=3D1 lo=\nng";
            assert_eq!(body(raw, "plain").unwrap(), "café code=1 long");
        }

        #[test]
        fn base64_part_inside_nested_multipart() {
            let raw = "Content-Type: multipart/mixed; boundary=\"o\"\n\n--o\n\
                       Content-Type: multipart/alternative; boundary=i\n\n--i\n\
                       Content-Type: text/html\nContent-Transfer-Encoding: base64\n\n\
                       PHA+aGk8L3A+\n--i--\n--o--\n";
            assert_eq!(body(raw, "html").unwrap(), "<p>hi</p>");
            assert_eq!(body(raw, "plain"), None);
        }

        #[test]
        fn encoded_words() {
            assert_eq!(
                decode_words("=?UTF-8?B?Q29kZTo=?= =?utf-8?Q?_caf=C3=A9?= now"),
                "Code: café now"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Fixtures, Reply};
    use serde_json::json;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/re146");
    const MESSAGE_ID: &str = "6814ac84-62ad-4619-96a0-2e44d99b7438";

    fn wire() -> Arc<Fixtures> {
        let f = |n| Reply::json(Fixtures::load(DIR, n));
        Fixtures::new()
            .route("/api/domains", f("domains.json"))
            .route("/api/messages/", f("messages.json"))
            .route(
                "/storage/",
                Reply::text(Fixtures::load_text(DIR, "message.eml")),
            )
    }

    fn build(w: &Arc<Fixtures>) -> Arc<dyn Provider> {
        Arc::new(Re146 {
            http: w.transport("re146", &CAPS),
        })
    }

    crate::contract_tests!(SPEC, build(&wire()));

    fn address() -> Address {
        Address::new("cbbe51e1e579@zenvixsmp.xyz", "re146")
    }

    #[test]
    fn md5_matches_the_rfc_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[tokio::test]
    async fn the_inbox_is_keyed_by_the_md5_of_the_address() {
        let w = wire();
        build(&w).list(&address()).await.unwrap();
        let k = md5_hex(address().value.as_bytes());
        assert!(
            w.seen()
                .iter()
                .any(|r| r.url.ends_with(&format!("/api/messages/{k}")))
        );
    }

    #[tokio::test]
    async fn a_custom_local_part_and_a_served_domain_are_honoured() {
        let opts = GenerateOptions {
            local: Some("chosen".into()),
            domain: Some("re146.dev".into()),
            ..Default::default()
        };
        let a = build(&wire()).generate(&opts).await.unwrap();
        assert_eq!(a.value, "chosen@re146.dev");
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
    async fn the_body_is_parsed_out_of_the_raw_source() {
        let m = build(&wire()).get(&address(), MESSAGE_ID).await.unwrap();
        assert!(m.subject.starts_with("JoltMx test email"), "{}", m.subject);
        assert_eq!(m.sender, "JoltMx Delivery Test <test@sendtest.joltmx.com>");
        assert!(
            m.text.contains("everything is working as expected"),
            "{}",
            m.text
        );
        assert!(
            m.links
                .iter()
                .any(|l| l.contains("joltmx.com/tools/test-email/opt-out/")),
            "{:?}",
            m.links
        );
        assert_eq!(m.received_at, Some("2026-09-24T10:29:37Z".parse().unwrap()));
    }

    #[tokio::test]
    async fn a_404_from_storage_is_gone() {
        let w = wire().route("/storage/", Reply::text("{}").with_status(404));
        assert!(matches!(
            build(&w).get(&address(), MESSAGE_ID).await,
            Err(Error::MessageGone { .. })
        ));
    }

    #[tokio::test]
    async fn a_body_in_an_unknown_charset_is_read_not_quarantined() {
        // cowbird raised drift here (Python lacked the codec). Interloper knows
        // far fewer codecs than Python, so it decodes lossily instead: one odd
        // message must not quarantine the provider.
        let source = "From: a@b.test\nSubject: x\n\
                      Content-Type: text/html; charset=x-no-such-charset\n\n<p>hi</p>\n";
        let w = wire().route("/storage/", Reply::text(source));
        let m = build(&w).get(&address(), MESSAGE_ID).await.unwrap();
        assert_eq!(m.text.trim(), "hi");
    }

    #[tokio::test]
    async fn a_list_that_is_not_an_array_is_drift() {
        let w = wire().route("/api/messages/", Reply::json(json!({"changed": true})));
        assert!(matches!(
            build(&w).list(&address()).await,
            Err(Error::SchemaDrift { .. })
        ));
    }
}
