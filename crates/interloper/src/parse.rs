//! Turning mail bodies into what callers actually want: text, links, codes.

use std::sync::LazyLock;

use regex::Regex;
use scraper::{Html, Node};

const DROP_TAGS: &[&str] = &["script", "style", "head", "title", "noscript", "template"];
const BLOCK_TAGS: &[&str] = &[
    "p",
    "div",
    "br",
    "tr",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "section",
    "article",
    "header",
    "footer",
    "blockquote",
    "pre",
    "hr",
    "td",
];

/// Visible text of an HTML document. Block elements become line breaks so a
/// code in its own `<td>` is not glued to the words around it, which is what
/// both a human and the OTP scorer need.
pub fn html_to_text(html: &str) -> String {
    if html.trim().is_empty() {
        return String::new();
    }
    let doc = Html::parse_document(html);
    let mut out = String::new();
    walk(doc.tree.root(), &mut out);
    // Collapse runs of whitespace within lines, and blank lines between them.
    let mut lines: Vec<String> = Vec::new();
    for line in out.lines() {
        let squashed = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !squashed.is_empty() {
            lines.push(squashed);
        }
    }
    lines.join("\n")
}

fn walk(node: ego_tree::NodeRef<'_, Node>, out: &mut String) {
    match node.value() {
        Node::Text(t) => out.push_str(t),
        Node::Element(e) => {
            let name = e.name();
            if DROP_TAGS.contains(&name) {
                return;
            }
            let block = BLOCK_TAGS.contains(&name);
            if block {
                out.push('\n');
            }
            for child in node.children() {
                walk(child, out);
            }
            if block {
                out.push('\n');
            } else if name == "a" || name == "span" || name == "td" {
                out.push(' ');
            }
        }
        _ => {
            for child in node.children() {
                walk(child, out);
            }
        }
    }
}

/// Every http(s) `href`, deduplicated, in document order. Other schemes
/// (`javascript:`, `mailto:`) are dropped: nothing a caller would follow.
pub fn extract_links(html: &str) -> Vec<String> {
    if html.trim().is_empty() {
        return Vec::new();
    }
    let doc = Html::parse_document(html);
    let mut seen = Vec::new();
    for node in doc.tree.nodes() {
        if let Node::Element(e) = node.value()
            && e.name() == "a"
            && let Some(href) = e.attr("href")
        {
            let href = href.trim();
            let lower = href.to_ascii_lowercase();
            if (lower.starts_with("http://") || lower.starts_with("https://"))
                && !seen.iter().any(|s: &String| s == href)
            {
                seen.push(href.to_string());
            }
        }
    }
    seen
}

static TEXT_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s<>"'\)\]]+"#).unwrap());

/// Bare URLs in a plain-text body, for mail that has no HTML part at all.
/// cowbird returned no links for those, so `link()` could never match a
/// plain-text verification mail.
pub fn extract_text_links(text: &str) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for m in TEXT_URL.find_iter(text) {
        let url = m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if !seen.iter().any(|s| s == url) {
            seen.push(url.to_string());
        }
    }
    seen
}

// Words that announce a code, in the languages these inboxes actually see.
static KEYWORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(code|codes|otp|verification|verify|verifying|passcode|password|pin|one[- ]time|security|confirm|confirmation|authenticat\w*|2fa|mfa|login|log in|sign[- ]in|token|código|codigo|verificación|verificacao|verificação|bestätigung|bestätigungscode|sicherheitscode|kod|kodu|код|пароль)\b|验证码|認証|인증",
    )
    .unwrap()
});

// Words that announce a number that is NOT the code.
static NEGATIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(order|invoice|ticket|ref|reference|account|acct|phone|tel|fax|call|zip|postal|suite|unit|no\.|number|#|\$|€|£|¥|usd|eur|copyright|©|version|v\.)\s*[:#]?\s*$",
    )
    .unwrap()
});

static DIGIT_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+(?:[ -]\d+)?").unwrap());
static ALNUM_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[A-Z0-9]{5,10}\b").unwrap());

#[derive(Debug, Clone, PartialEq)]
struct Candidate {
    code: String,
    score: i32,
    pos: usize,
}

/// The one-time code in a message, or `None`.
///
/// With `pattern`, the first match wins; capture group 1 is returned when the
/// pattern has one, otherwise the whole match.
///
/// Without one, every number-shaped token in `subject` and `text` is scored
/// rather than taking the first six-digit run the way cowbird did. "Order
/// #482913 — your code is 7731" yields 7731, not the order number; a year in
/// a footer or a phone number in a signature loses to a code next to the word
/// "code". Six digits remains the strongest shape signal on its own.
pub fn extract_otp(subject: &str, text: &str, pattern: Option<&Regex>) -> Option<String> {
    let haystack = format!("{subject}\n{text}");
    if let Some(re) = pattern {
        let caps = re.captures(&haystack)?;
        return Some(caps.get(1).or_else(|| caps.get(0))?.as_str().to_string());
    }
    best_candidate(&haystack, subject.len())
}

fn best_candidate(hay: &str, subject_end: usize) -> Option<String> {
    let mut cands: Vec<Candidate> = Vec::new();
    for m in DIGIT_RUN.find_iter(hay) {
        // A separated group ("123 456", "123-456") is one candidate only when
        // both halves are 3 digits; otherwise score the halves separately.
        let raw = m.as_str();
        let parts: Vec<&str> = raw.split([' ', '-']).collect();
        if parts.len() == 2 && !(parts[0].len() == 3 && parts[1].len() == 3) {
            let first_end = m.start() + parts[0].len();
            push_digits(hay, m.start(), first_end, parts[0], subject_end, &mut cands);
            let second_start = m.end() - parts[1].len();
            push_digits(
                hay,
                second_start,
                m.end(),
                parts[1],
                subject_end,
                &mut cands,
            );
            continue;
        }
        let code: String = raw.chars().filter(char::is_ascii_digit).collect();
        push_digits(hay, m.start(), m.end(), &code, subject_end, &mut cands);
    }
    for m in ALNUM_CODE.find_iter(hay) {
        let s = m.as_str();
        let has_digit = s.chars().any(|c| c.is_ascii_digit());
        let has_alpha = s.chars().any(|c| c.is_ascii_alphabetic());
        if !(has_digit && has_alpha) {
            continue;
        }
        // Mixed codes are only believable when announced.
        if keyword_score(hay, m.start(), m.end()) > 0 {
            cands.push(Candidate {
                code: s.to_string(),
                score: 9 + in_subject(m.start(), subject_end),
                pos: m.start(),
            });
        }
    }
    cands
        .into_iter()
        .filter(|c| c.score > 0)
        .max_by(|a, b| a.score.cmp(&b.score).then(b.pos.cmp(&a.pos)))
        .map(|c| c.code)
}

fn in_subject(pos: usize, subject_end: usize) -> i32 {
    if pos < subject_end { 2 } else { 0 }
}

fn push_digits(
    hay: &str,
    start: usize,
    end: usize,
    code: &str,
    subject_end: usize,
    out: &mut Vec<Candidate>,
) {
    let len = code.len();
    if !(4..=8).contains(&len) {
        return;
    }
    let before = &hay[..start];
    let after = &hay[end..];
    let prev = before.chars().next_back();
    let next = after.chars().next();
    // Glued to letters or part of a longer token (a hash, an ID).
    if prev.is_some_and(|c| c.is_alphanumeric() || c == '_')
        || next.is_some_and(|c| c.is_alphanumeric() || c == '_')
    {
        return;
    }
    let mut score = match len {
        6 => 10,
        4 | 8 => 5,
        _ => 4,
    };
    score += keyword_score(hay, start, end);
    score += in_subject(start, subject_end);
    // Part of a date, time, decimal, version, or phone number. (A 3+3 group
    // joined by '-' or ' ' was already merged into one candidate above.)
    let joins = |c: Option<char>| matches!(c, Some('/' | ':' | '.' | ',' | '+' | '(' | ')' | '-'));
    let next2 = after.chars().nth(1);
    if (joins(prev)
        && before
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|c| c.is_ascii_digit()))
        || (joins(next) && next2.is_some_and(|c| c.is_ascii_digit()))
        || prev == Some('+')
    {
        score -= 12;
    }
    if prev == Some('%') || next == Some('%') {
        score -= 12;
    }
    if len == 4
        && let Ok(n) = code.parse::<u32>()
        && (1900..=2099).contains(&n)
    {
        score -= 7;
    }
    let window_start = floor_boundary(before, before.len().saturating_sub(16));
    if NEGATIVE.is_match(&before[window_start..]) {
        score -= 14;
    }
    out.push(Candidate {
        code: code.to_string(),
        score,
        pos: start,
    });
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i.min(s.len())
}

/// An announcement before the number ("your code is 1234") is the common
/// shape and scores higher than one after it ("1234 is your code"), so a
/// stray number just before an announced code does not tie with it.
fn keyword_score(hay: &str, start: usize, end: usize) -> i32 {
    let lo = floor_boundary(hay, start.saturating_sub(64));
    let hi = ceil_boundary(hay, end + 24);
    if KEYWORDS.is_match(&hay[lo..start]) {
        8
    } else if KEYWORDS.is_match(&hay[end..hi]) {
        5
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn otp(text: &str) -> Option<String> {
        extract_otp("", text, None)
    }

    #[test]
    fn text_drops_script_and_style_and_splits_blocks() {
        let html = "<html><head><title>T</title><style>p{}</style></head><body>\
            <p>Hello <b>there</b></p><script>var x=123456</script><div>Code: 482913</div></body></html>";
        assert_eq!(html_to_text(html), "Hello there\nCode: 482913");
    }

    #[test]
    fn links_are_http_only_and_deduplicated() {
        let html = r#"<a href="https://a.test/x">1</a><a href="javascript:alert(1)">2</a>
            <a href="mailto:x@y">3</a><a href="https://a.test/x">4</a><a href="HTTP://b.test">5</a>"#;
        assert_eq!(
            extract_links(html),
            vec!["https://a.test/x", "HTTP://b.test"]
        );
    }

    #[test]
    fn text_links_trim_trailing_punctuation() {
        let t = "Click https://x.test/verify?t=1. Or (https://y.test/a)";
        assert_eq!(
            extract_text_links(t),
            vec!["https://x.test/verify?t=1", "https://y.test/a"]
        );
    }

    #[test]
    fn plain_six_digit_code() {
        assert_eq!(otp("Your code is 123456").as_deref(), Some("123456"));
    }

    #[test]
    fn announced_short_code_beats_unannounced_order_number() {
        let t = "Order #48291377 confirmed. Your verification code is 7731.";
        assert_eq!(otp(t).as_deref(), Some("7731"));
    }

    #[test]
    fn year_and_phone_lose_to_the_code() {
        let t = "© 2026 Example Inc. Call +1 (555) 123-4567.\nYour login code: 9042";
        assert_eq!(otp(t).as_deref(), Some("9042"));
    }

    #[test]
    fn grouped_code_is_joined() {
        assert_eq!(otp("Enter 482 913 to continue").as_deref(), Some("482913"));
        assert_eq!(otp("Your code: 482-913").as_deref(), Some("482913"));
    }

    #[test]
    fn dates_and_times_are_not_codes() {
        assert_eq!(otp("Sent 2026/11/18 at 10:45:12"), None);
    }

    #[test]
    fn alphanumeric_code_needs_an_announcement() {
        assert_eq!(
            otp("Your verification code is K7PX2Q").as_deref(),
            Some("K7PX2Q")
        );
        assert_eq!(otp("Shipment AB12CD dispatched"), None);
    }

    #[test]
    fn subject_code_counts() {
        assert_eq!(
            extract_otp("123456 is your Example code", "Thanks for signing up", None).as_deref(),
            Some("123456")
        );
    }

    #[test]
    fn hex_ids_are_not_codes() {
        assert_eq!(otp("message id 6a1f2c9e4b7d"), None);
    }

    #[test]
    fn explicit_pattern_prefers_group_one() {
        let re = Regex::new(r"PIN-(\d+)").unwrap();
        assert_eq!(
            extract_otp("", "use PIN-0042 now", Some(&re)).as_deref(),
            Some("0042")
        );
        let re = Regex::new(r"\d{3}").unwrap();
        assert_eq!(
            extract_otp("", "abc 987", Some(&re)).as_deref(),
            Some("987")
        );
    }

    #[test]
    fn non_ascii_text_does_not_panic() {
        let t = "验证码：834201，请勿泄露。ünïcödé 🎉 ".repeat(5);
        assert_eq!(otp(&t).as_deref(), Some("834201"));
    }
}
