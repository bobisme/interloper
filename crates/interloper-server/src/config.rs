//! Server settings, from the environment.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub api_keys: Vec<String>,
    pub allowed_origins: Vec<String>,
    /// Requests per window, per bucket.
    pub rate_limit: (u32, Duration),
    /// Ceiling for a held `wait` request. Well under an edge proxy's ceiling on
    /// a proxied subrequest: the client re-issues rather than holding one long
    /// request open through the edge.
    pub wait_max: Duration,
    pub wait_default: Duration,
    /// Ceiling for a webhook's wait. Separate from `wait_max` on purpose: a
    /// webhook holds no request open, and sharing the clamp is how cowbird once
    /// capped webhooks at the long-poll ceiling.
    pub webhook_max: Duration,
    pub webhook_secret: Option<String>,
    pub webhook_allow_private: bool,
    /// SQLite file for issued addresses. `None` keeps them in memory.
    pub database: Option<PathBuf>,
    /// How often health is flushed to disk and expired addresses reaped.
    pub maintenance_every: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            api_keys: Vec::new(),
            allowed_origins: Vec::new(),
            rate_limit: (30, Duration::from_secs(60)),
            wait_max: Duration::from_secs(25),
            wait_default: Duration::from_secs(25),
            webhook_max: Duration::from_secs(600),
            webhook_secret: None,
            webhook_allow_private: false,
            database: None,
            maintenance_every: Duration::from_secs(30),
        }
    }
}

fn env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

fn csv(v: Option<String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn secs(names: &[&str], default: Duration) -> Result<Duration, String> {
    match env(names) {
        None => Ok(default),
        Some(v) => match v.trim().parse::<u64>() {
            Ok(n) if n >= 1 => Ok(Duration::from_secs(n)),
            _ => Err(format!(
                "{} must be a whole number of seconds >= 1, got {v:?}",
                names[0]
            )),
        },
    }
}

/// `"30/minute"`, `"5/second"`, `"1000/hour"`.
pub fn parse_rate(s: &str) -> Result<(u32, Duration), String> {
    let (n, per) = s
        .split_once('/')
        .ok_or_else(|| format!("rate limit {s:?} is not N/unit"))?;
    let n: u32 = n
        .trim()
        .parse()
        .map_err(|_| format!("rate limit {s:?} is not N/unit"))?;
    let window = match per.trim() {
        "second" | "s" => Duration::from_secs(1),
        "minute" | "m" => Duration::from_secs(60),
        "hour" | "h" => Duration::from_secs(3600),
        "day" | "d" => Duration::from_secs(86400),
        other => return Err(format!("unknown rate-limit unit {other:?}")),
    };
    if n == 0 {
        return Err("rate limit must allow at least one request".into());
    }
    Ok((n, window))
}

impl Config {
    /// `INTERLOPER_*` names, falling back to cowbird's bare ones.
    pub fn from_env() -> Result<Self, String> {
        let d = Config::default();
        let bind = match env(&["INTERLOPER_BIND", "BIND"]) {
            Some(b) => b
                .parse()
                .map_err(|e| format!("INTERLOPER_BIND {b:?}: {e}"))?,
            // Render, Koyeb and Fly inject PORT and route only to it, on every
            // interface. An explicit INTERLOPER_BIND still wins.
            None => match env(&["PORT"]) {
                Some(p) => std::net::SocketAddr::from((
                    [0, 0, 0, 0],
                    p.trim().parse::<u16>().map_err(|e| format!("PORT {p:?}: {e}"))?,
                )),
                None => d.bind,
            },
        };
        let rate_limit = match env(&["INTERLOPER_RATE_LIMIT", "RATE_LIMIT"]) {
            Some(r) => parse_rate(&r)?,
            None => d.rate_limit,
        };
        let allow_private = env(&["INTERLOPER_WEBHOOK_ALLOW_PRIVATE", "WEBHOOK_ALLOW_PRIVATE"])
            .is_some_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        Ok(Config {
            bind,
            api_keys: csv(env(&["INTERLOPER_API_KEYS", "API_KEYS"])),
            allowed_origins: csv(env(&["INTERLOPER_ALLOWED_ORIGINS", "ALLOWED_ORIGINS"])),
            rate_limit,
            wait_max: secs(&["INTERLOPER_WAIT_MAX", "WAIT_MAX"], d.wait_max)?,
            wait_default: secs(&["INTERLOPER_WAIT_DEFAULT", "WAIT_DEFAULT"], d.wait_default)?,
            webhook_max: secs(&["INTERLOPER_WEBHOOK_MAX", "WEBHOOK_MAX"], d.webhook_max)?,
            webhook_secret: env(&["INTERLOPER_WEBHOOK_SECRET", "WEBHOOK_SECRET"]),
            webhook_allow_private: allow_private,
            database: env(&["INTERLOPER_DATABASE", "DATABASE_PATH"]).map(PathBuf::from),
            maintenance_every: d.maintenance_every,
        })
    }

    /// Default when unset, capped at the ceiling either way.
    pub fn clamp_wait(&self, requested: Option<u64>) -> Duration {
        requested
            .map_or(self.wait_default, Duration::from_secs)
            .min(self.wait_max)
    }

    pub fn clamp_webhook(&self, requested: Option<u64>) -> Duration {
        requested
            .map_or(self.webhook_max, Duration::from_secs)
            .min(self.webhook_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates() {
        assert_eq!(
            parse_rate("30/minute").unwrap(),
            (30, Duration::from_secs(60))
        );
        assert!(parse_rate("0/minute").is_err());
        assert!(parse_rate("thirty").is_err());
    }

    #[test]
    fn clamps_are_separate() {
        let c = Config::default();
        assert_eq!(c.clamp_wait(Some(9999)), c.wait_max);
        assert_eq!(c.clamp_wait(None), c.wait_default);
        assert_eq!(c.clamp_webhook(Some(300)), Duration::from_secs(300));
        assert_eq!(c.clamp_webhook(None), c.webhook_max);
    }
}
