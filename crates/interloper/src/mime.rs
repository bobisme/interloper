//! Reading RFC 822 mail: the headers a [`crate::Message`] needs and the first
//! HTML and plain-text bodies, for backends that serve a message as its raw
//! source.
//!
//! Built on `mail-parser` with its `full_encoding` feature, so a body or an
//! encoded word in any charset a mail client sends (ISO-2022-JP, KOI8-R,
//! windows-1251, GB18030, ...) decodes exactly.
//!
//! Sources here are `&str`, because transports hand back text: the HTTP body
//! (or the JSON string holding the source) was already decoded once. So a part
//! without a transfer encoding is taken as the characters it already is;
//! only base64 and quoted-printable parts are bytes to decode by charset.

use std::borrow::Cow;

use jiff::Timestamp;
use mail_parser::{Charset, Encoding, HeaderForm, MessageParser, MessagePart, PartKind};

/// The parts of a message a backend adapter needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mail {
    /// `Name <addr>`, or the bare address when the From has no name.
    pub sender: String,
    /// RFC 2047 encoded words decoded.
    pub subject: String,
    pub date: Option<Timestamp>,
    /// The first `text/html` body that is not an attachment.
    pub html: Option<String>,
    /// The first `text/plain` body that is not an attachment.
    pub text: Option<String>,
    /// The first charset label of a chosen body that is not known. An
    /// encoded body in it was read as UTF-8, lossily; an adapter decides
    /// whether that is drift.
    pub unknown_charset: Option<String>,
}

/// Parse a raw RFC 822 message. Never fails: a source without headers is a
/// message with an empty sender and subject.
pub fn parse(raw: &str) -> Mail {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return Mail::default();
    };
    let sender = msg
        .from()
        .and_then(|f| f.first())
        .and_then(|mb| {
            let addr = mb.address()?;
            Some(match mb.name() {
                Some(n) if !n.trim().is_empty() => format!("{} <{addr}>", n.trim()),
                _ => addr.to_string(),
            })
        })
        .or_else(|| {
            msg.headers()
                .value("From")
                .and_then(|v| v.as_text().map(str::to_string))
        })
        .unwrap_or_default();
    let mut unknown_charset = None;
    let mut pick = |html: bool| -> Option<String> {
        // The RFC 8621 body lists also carry a part of the other kind (in a
        // multipart/mixed, every inline text part is in both), so only the
        // first part of the asked-for kind counts.
        let wanted = |part: &MessagePart<'_>| {
            !part.is_attachment()
                && match part.kind() {
                    PartKind::Html => html,
                    // mail-parser files any non-HTML text/* here; only plain
                    // counts.
                    PartKind::Text => {
                        !html
                            && part
                                .content_type()
                                .is_none_or(|ct| ct.subtype().is_none_or(|s| s == "plain"))
                    }
                    _ => false,
                }
        };
        let part = if html {
            msg.html_body().find(wanted)
        } else {
            msg.text_body().find(wanted)
        }?;
        let (text, unknown) = part_text(&part);
        if unknown_charset.is_none() {
            unknown_charset = unknown;
        }
        Some(text)
    };
    let html = pick(true);
    let text = pick(false);
    Mail {
        sender,
        subject: msg.subject().unwrap_or("").to_string(),
        date: msg
            .date()
            .and_then(|d| Timestamp::from_second(d.to_timestamp()).ok()),
        html,
        text,
        unknown_charset,
    }
}

/// A text part's characters, and its charset label when that is unknown.
fn part_text(part: &MessagePart<'_>) -> (String, Option<String>) {
    let label = part
        .content_type()
        .and_then(|ct| ct.attribute("charset"))
        .map(str::to_string);
    let unknown = label.filter(|l| !known_charset(l));
    let text = if part.encoding() == Encoding::None {
        String::from_utf8_lossy(part.raw_body()).into_owned()
    } else {
        part.text().map(Cow::into_owned).unwrap_or_default()
    };
    (text, unknown)
}

/// Decode RFC 2047 encoded words in an unstructured header value
/// (`=?KOI8-R?B?...?=`). Whitespace between adjacent encoded words is
/// dropped, as the RFC says.
pub fn decode_header(value: &str) -> String {
    HeaderForm::Text
        .parse(value.as_bytes())
        .value()
        .as_text()
        .unwrap_or("")
        .to_string()
}

/// Whether `label` names a charset [`decode_body`] decodes exactly.
pub fn known_charset(label: &str) -> bool {
    Charset::from_label(label.trim().as_bytes()).is_some()
}

/// Decode a body by its Content-Transfer-Encoding (`base64`,
/// `quoted-printable`; anything else is taken as is) and then by its charset
/// (UTF-8 when absent or unknown; invalid sequences become U+FFFD).
pub fn decode_body(body: &[u8], transfer_encoding: &str, charset: Option<&str>) -> String {
    let encoding = match transfer_encoding.trim().to_ascii_lowercase().as_str() {
        "base64" => Encoding::Base64,
        "quoted-printable" => Encoding::QuotedPrintable,
        _ => Encoding::None,
    };
    let bytes = encoding.decode(body);
    charset
        .and_then(|c| Charset::from_label(c.trim().as_bytes()))
        .unwrap_or_default()
        .decode(&bytes)
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_and_both_bodies() {
        let raw = "From: =?utf-8?Q?Caf=C3=A9?= <a@b.test>\r\n\
                   Subject: =?UTF-8?B?Q29kZTo=?= =?utf-8?Q?_caf=C3=A9?= now\r\n\
                   Date: Thu, 24 Sep 2026 10:29:37 +0200\r\n\
                   Content-Type: multipart/alternative; boundary=b\r\n\r\n\
                   --b\r\nContent-Type: text/plain; charset=utf-8\r\n\
                   Content-Transfer-Encoding: quoted-printable\r\n\r\n\
                   caf=C3=A9 code=3D1 lo=\r\nng\r\n\
                   --b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n\
                   PHA+aGk8L3A+\r\n--b--\r\n";
        let m = parse(raw);
        assert_eq!(m.sender, "Café <a@b.test>");
        assert_eq!(m.subject, "Code: café now");
        assert_eq!(m.date, Some("2026-09-24T08:29:37Z".parse().unwrap()));
        assert_eq!(m.text.as_deref(), Some("café code=1 long"));
        assert_eq!(m.html.as_deref(), Some("<p>hi</p>"));
        assert_eq!(m.unknown_charset, None);
    }

    #[test]
    fn a_bare_address_and_no_bodies_of_the_other_kind() {
        let m = parse("From: a@b.test\nSubject: x\nContent-Type: text/html\n\n<p>hi</p>\n");
        assert_eq!(m.sender, "a@b.test");
        assert_eq!(m.html.as_deref().map(str::trim), Some("<p>hi</p>"));
        assert_eq!(m.text, None);
    }

    #[test]
    fn an_attachment_is_not_a_body() {
        let raw = "Content-Type: multipart/mixed; boundary=o\n\n--o\n\
                   Content-Type: text/html\nContent-Disposition: attachment\n\n<i>no</i>\n--o--\n";
        assert_eq!(parse(raw).html, None);
    }

    #[test]
    fn iso_2022_jp_subject_and_body() {
        // "日本語" in ISO-2022-JP, as a mailer sends it.
        let raw = "Subject: =?ISO-2022-JP?B?GyRCRnxLXDhsGyhC?=\n\
                   Content-Type: text/plain; charset=ISO-2022-JP\n\
                   Content-Transfer-Encoding: base64\n\nGyRCRnxLXDhsGyhC\n";
        let m = parse(raw);
        assert_eq!(m.subject, "日本語");
        assert_eq!(m.text.as_deref(), Some("日本語"));
        assert_eq!(m.unknown_charset, None);
    }

    #[test]
    fn koi8_r_and_windows_1251_base64_parts() {
        // "Привет" in KOI8-R (8NLJ18XU) and windows-1251 (z/Do4uXy).
        let raw = "Subject: =?KOI8-R?B?8NLJ18XU?=\n\
                   Content-Type: multipart/alternative; boundary=b\n\n\
                   --b\nContent-Type: text/plain; charset=koi8-r\n\
                   Content-Transfer-Encoding: base64\n\n8NLJ18XU\n\
                   --b\nContent-Type: text/html; charset=windows-1251\n\
                   Content-Transfer-Encoding: base64\n\nz/Do4uXy\n--b--\n";
        let m = parse(raw);
        assert_eq!(m.subject, "Привет");
        assert_eq!(m.text.as_deref(), Some("Привет"));
        assert_eq!(m.html.as_deref(), Some("Привет"));
    }

    #[test]
    fn an_unknown_charset_is_reported_and_read_lossily() {
        let raw = "Content-Type: text/plain; charset=x-no-such-charset\n\
                   Content-Transfer-Encoding: base64\n\naGk=\n";
        let m = parse(raw);
        assert_eq!(m.text.as_deref(), Some("hi"));
        assert_eq!(m.unknown_charset.as_deref(), Some("x-no-such-charset"));
    }

    #[test]
    fn an_unencoded_part_is_already_text() {
        // The source was decoded once already; re-reading its UTF-8 as
        // Latin-1 would garble it.
        let raw = "Content-Type: text/plain; charset=iso-8859-1\n\ncafé\n";
        assert_eq!(parse(raw).text.as_deref().map(str::trim), Some("café"));
    }

    #[test]
    fn decode_header_handles_charsets() {
        assert_eq!(decode_header("plain"), "plain");
        assert_eq!(
            decode_header("=?windows-1251?B?z/Do4uXy?= =?utf-8?Q?_mir?="),
            "Привет mir"
        );
    }

    #[test]
    fn decode_body_by_encoding_and_charset() {
        assert_eq!(decode_body(b"8NLJ18XU", "base64", Some("KOI8-R")), "Привет");
        assert_eq!(
            decode_body(b"caf=E9 =\nok", "Quoted-Printable", Some("iso-8859-1")),
            "café ok"
        );
        assert_eq!(decode_body(b"as is", "8bit", None), "as is");
        assert!(known_charset("Shift_JIS"));
        assert!(!known_charset("x-no-such-charset"));
    }
}
