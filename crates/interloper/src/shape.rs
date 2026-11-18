//! Reading untrusted JSON without writing the drift error by hand each time.
//!
//! cowbird adapters each grew `_field()` helpers that raised SchemaDrift with
//! the missing key. [`J`] does that once: every accessor that fails reports
//! the provider, the JSON path it was reading, and what it found there, so a
//! quarantine reason reads `mailtm: expected string at messages[3].id, got
//! null` instead of a stack trace.

use jiff::Timestamp;
use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct J<'a> {
    provider: &'a str,
    v: &'a Value,
    path: String,
}

fn describe(v: &Value) -> String {
    match v {
        Value::Object(m) => format!(
            "object with keys {:?}",
            m.keys().take(12).collect::<Vec<_>>()
        ),
        Value::Array(a) => format!("array of {}", a.len()),
        other => crate::error::clip(&other.to_string(), 120),
    }
}

impl<'a> J<'a> {
    /// `where_` names the response, e.g. `"check_email"`.
    pub fn new(provider: &'a str, v: &'a Value, where_: &str) -> Self {
        J {
            provider,
            v,
            path: where_.to_string(),
        }
    }

    pub fn value(&self) -> &'a Value {
        self.v
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn drift(&self, expected: &str) -> Error {
        Error::SchemaDrift {
            provider: self.provider.to_string(),
            expected: format!("{expected} at {}", self.path),
            got: describe(self.v),
        }
    }

    fn child(&self, v: &'a Value, seg: String) -> J<'a> {
        J {
            provider: self.provider,
            v,
            path: seg,
        }
    }

    /// A required key. Missing (or the parent not being an object) is drift.
    pub fn at(&self, key: &str) -> Result<J<'a>> {
        match self.v.as_object().and_then(|m| m.get(key)) {
            Some(v) => Ok(self.child(v, format!("{}.{key}", self.path))),
            None => Err(self.drift(&format!("key {key:?}"))),
        }
    }

    /// An optional key; `null` counts as absent.
    pub fn opt(&self, key: &str) -> Option<J<'a>> {
        let v = self.v.as_object()?.get(key).filter(|v| !v.is_null())?;
        Some(self.child(v, format!("{}.{key}", self.path)))
    }

    /// The elements of an array. Anything else is drift.
    pub fn items(&self) -> Result<Vec<J<'a>>> {
        let arr = self.v.as_array().ok_or_else(|| self.drift("an array"))?;
        Ok(arr
            .iter()
            .enumerate()
            .map(|(i, v)| self.child(v, format!("{}[{i}]", self.path)))
            .collect())
    }

    pub fn str(&self) -> Result<&'a str> {
        self.v.as_str().ok_or_else(|| self.drift("a string"))
    }

    /// A string, or a number rendered as one. IDs flip between the two.
    pub fn id(&self) -> Result<String> {
        match self.v {
            Value::String(s) => Ok(s.clone()),
            Value::Number(n) => Ok(n.to_string()),
            _ => Err(self.drift("a string or number id")),
        }
    }

    pub fn i64(&self) -> Result<i64> {
        match self.v {
            Value::Number(n) => n.as_i64().ok_or_else(|| self.drift("an integer")),
            Value::String(s) => s.trim().parse().map_err(|_| self.drift("an integer")),
            _ => Err(self.drift("an integer")),
        }
    }

    pub fn bool(&self) -> Result<bool> {
        self.v.as_bool().ok_or_else(|| self.drift("a boolean"))
    }

    /// Optional string field, `""` when absent or not a string.
    pub fn s(&self, key: &str) -> String {
        match self.v.get(key) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    }

    /// Required id-like field.
    pub fn req_id(&self, key: &str) -> Result<String> {
        self.at(key)?.id()
    }

    /// Optional time field in any format [`parse_time`] knows.
    pub fn time(&self, key: &str) -> Option<Timestamp> {
        parse_value_time(self.v.get(key)?)
    }
}

/// Parse a timestamp the way these backends write them: RFC 3339, a naive
/// `YYYY-MM-DD HH:MM:SS` (taken as UTC), or epoch seconds/milliseconds.
pub fn parse_time(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(t) = s.parse::<Timestamp>() {
        return Some(t);
    }
    if let Ok(n) = s.parse::<i64>() {
        return epoch(n);
    }
    let naive = s.replace(' ', "T");
    if let Ok(dt) = naive.parse::<jiff::civil::DateTime>() {
        return jiff::tz::TimeZone::UTC.to_timestamp(dt).ok();
    }
    None
}

fn epoch(n: i64) -> Option<Timestamp> {
    if n <= 0 {
        return None;
    }
    if n > 100_000_000_000 {
        Timestamp::from_millisecond(n).ok()
    } else {
        Timestamp::from_second(n).ok()
    }
}

pub fn parse_value_time(v: &Value) -> Option<Timestamp> {
    match v {
        Value::String(s) => parse_time(s),
        Value::Number(n) => epoch(n.as_i64()?),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn drift_names_the_path() {
        let v = json!({"list": [{"mail_id": 1}, {"subject": "x"}]});
        let j = J::new("g", &v, "check_email");
        let rows = j.at("list").unwrap();
        let rows = rows.items().unwrap();
        assert_eq!(rows[0].req_id("mail_id").unwrap(), "1");
        let err = rows[1].req_id("mail_id").unwrap_err().to_string();
        assert!(err.contains("check_email.list[1]"), "{err}");
        assert!(err.contains("subject"), "{err}");
    }

    #[test]
    fn times_in_every_dialect() {
        let want = "2026-09-05T10:12:03Z".parse::<Timestamp>().unwrap();
        for s in [
            "2026-09-05T10:12:03+00:00",
            "2026-09-05 10:12:03",
            "1788603123",
            "1788603123000",
        ] {
            assert_eq!(parse_time(s), Some(want), "{s}");
        }
        assert_eq!(parse_time("0"), None);
        assert_eq!(parse_time("garbage"), None);
    }
}
