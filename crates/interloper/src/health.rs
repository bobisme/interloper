//! What the pool knows about which providers still work. Measured, never
//! declared: every call a provider makes is timed and recorded here.
//!
//! Differences from cowbird, on purpose:
//!
//! * **DOWN recovers.** cowbird's pool never routed to a DOWN provider and
//!   nothing else moved it, so in a long-running server one blip retired a
//!   backend until restart. Here DOWN is a circuit breaker: after a cooldown
//!   (30s, doubling per consecutive failure, capped at 15 min) the provider is
//!   routable again on *probation*, ranked behind every healthy one. One
//!   success closes the breaker; another failure doubles the cooldown.
//! * **DOWN persists, with its cooldown.** Because it now expires on its own,
//!   restoring it is safe, and the next CLI run does not re-hammer a backend
//!   that failed seconds ago.
//! * **Concurrent writers merge.** Saving re-reads the file and only replaces
//!   entries this process touched, so parallel `interloper` processes do not
//!   erase each other's measurements.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::error::{Error, HealthEffect};

/// How far past its own trailing median a call may run before the provider is
/// SLOW. Self-relative on purpose: a 39-second body read is normal for one
/// backend and pathological for another. Absolute slowness is the pool's job
/// via p50 ranking.
pub const SLOW_FACTOR: f64 = 3.0;
pub const WINDOW: usize = 20;
const BASELINE_MIN: usize = 5;
pub const COOLDOWN_BASE: Duration = Duration::from_secs(30);
pub const COOLDOWN_MAX: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    #[default]
    Ok,
    Slow,
    Down,
    Quarantined,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Slow => "slow",
            Status::Down => "down",
            Status::Quarantined => "quarantined",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Routing tier of a routable provider; lower is preferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Healthy = 0,
    Slow = 1,
    Probation = 2,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProviderHealth {
    pub status: Status,
    #[serde(default)]
    pub latencies: VecDeque<f64>,
    #[serde(default)]
    pub last_checked: Option<Timestamp>,
    #[serde(default)]
    pub last_failure: Option<String>,
    #[serde(default)]
    pub needs_residential_ip: bool,
    /// Consecutive failures; drives the cooldown.
    #[serde(default)]
    pub failures: u32,
    /// When a DOWN provider may be tried again.
    #[serde(default)]
    pub retry_at: Option<Timestamp>,
}

impl ProviderHealth {
    pub fn p50(&self) -> Option<f64> {
        median(&self.latencies)
    }
}

fn median(xs: &VecDeque<f64>) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut v: Vec<f64> = xs.iter().copied().collect();
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

pub fn cooldown(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    (COOLDOWN_BASE * 2u32.pow(shift)).min(COOLDOWN_MAX)
}

type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;

pub struct HealthStore {
    entries: Mutex<HashMap<String, ProviderHealth>>,
    touched: Mutex<HashSet<String>>,
    clock: Clock,
}

impl Default for HealthStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HealthStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthStore")
            .field("entries", &self.entries.lock().unwrap().len())
            .finish()
    }
}

impl HealthStore {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Timestamp::now))
    }

    pub fn with_clock(clock: Clock) -> Self {
        HealthStore {
            entries: Mutex::new(HashMap::new()),
            touched: Mutex::new(HashSet::new()),
            clock,
        }
    }

    fn now(&self) -> Timestamp {
        (self.clock)()
    }

    fn update<R>(&self, provider: &str, f: impl FnOnce(&mut ProviderHealth) -> R) -> R {
        self.touched.lock().unwrap().insert(provider.to_string());
        let mut map = self.entries.lock().unwrap();
        f(map.entry(provider.to_string()).or_default())
    }

    fn read<R>(&self, provider: &str, f: impl FnOnce(Option<&ProviderHealth>) -> R) -> R {
        f(self.entries.lock().unwrap().get(provider))
    }

    pub fn record_success(&self, provider: &str, elapsed: Duration) {
        let now = self.now();
        let secs = elapsed.as_secs_f64();
        self.update(provider, |e| {
            e.last_checked = Some(now);
            // Quarantine means the adapter is wrong; one passing call does not
            // make it right. Only a human clears it.
            if e.status == Status::Quarantined {
                return;
            }
            let baseline = (e.latencies.len() >= BASELINE_MIN)
                .then(|| median(&e.latencies))
                .flatten();
            e.latencies.push_back(secs);
            while e.latencies.len() > WINDOW {
                e.latencies.pop_front();
            }
            e.last_failure = None;
            e.failures = 0;
            e.retry_at = None;
            // A success through this egress disproves the residential-IP hint.
            e.needs_residential_ip = false;
            e.status = match baseline {
                Some(b) if secs > b * SLOW_FACTOR => Status::Slow,
                _ => Status::Ok,
            };
        });
    }

    /// Record what `err` says about the provider. Neutral errors (an answer
    /// about one message, a solver outage) are ignored.
    pub fn record_error(&self, provider: &str, err: &Error) {
        let effect = err.health_effect();
        if effect == HealthEffect::Neutral {
            return;
        }
        let now = self.now();
        self.update(provider, |e| {
            e.last_checked = Some(now);
            e.last_failure = Some(err.to_string());
            if matches!(err, Error::Challenge { .. }) {
                e.needs_residential_ip = true;
            }
            if e.status == Status::Quarantined {
                return;
            }
            if effect == HealthEffect::Drift {
                e.status = Status::Quarantined;
                e.retry_at = None;
                return;
            }
            e.failures = e.failures.saturating_add(1);
            let mut wait = cooldown(e.failures);
            if let Error::RateLimited {
                retry_after: Some(ra),
                ..
            } = err
            {
                wait = wait.max(*ra).min(COOLDOWN_MAX);
            }
            e.retry_at = now
                .checked_add(SignedDuration::try_from(wait).unwrap_or(SignedDuration::MAX))
                .ok();
            e.status = Status::Down;
        });
    }

    pub fn status(&self, provider: &str) -> Status {
        self.read(provider, |e| e.map_or(Status::Ok, |e| e.status))
    }

    /// The routing tier, or `None` when the provider must not be routed to.
    pub fn tier(&self, provider: &str) -> Option<Tier> {
        let now = self.now();
        self.read(provider, |e| match e {
            None => Some(Tier::Healthy),
            Some(e) => match e.status {
                Status::Ok => Some(Tier::Healthy),
                Status::Slow => Some(Tier::Slow),
                Status::Down if e.retry_at.is_none_or(|t| t <= now) => Some(Tier::Probation),
                Status::Down | Status::Quarantined => None,
            },
        })
    }

    pub fn p50(&self, provider: &str) -> Option<f64> {
        self.read(provider, |e| e.and_then(ProviderHealth::p50))
    }

    pub fn get(&self, provider: &str) -> Option<ProviderHealth> {
        self.read(provider, |e| e.cloned())
    }

    /// Mark an adapter broken. Terminal until [`unquarantine`](Self::unquarantine).
    pub fn quarantine(&self, provider: &str, reason: &str) {
        self.update(provider, |e| {
            e.status = Status::Quarantined;
            e.last_failure = Some(reason.to_string());
        });
    }

    /// Return a quarantined provider to routing, keeping its measurements.
    /// Returns whether it was quarantined. Guarded so a reconcile cannot stamp
    /// OK over a live DOWN or SLOW.
    pub fn unquarantine(&self, provider: &str) -> bool {
        self.update(provider, |e| {
            let was = e.status == Status::Quarantined;
            if was {
                e.status = Status::Ok;
                e.failures = 0;
                e.retry_at = None;
            }
            was
        })
    }

    pub fn snapshot(&self) -> HashMap<String, ProviderHealth> {
        self.entries.lock().unwrap().clone()
    }

    /// Fold persisted entries in, overwriting per provider. Call before any
    /// live measurement exists.
    pub fn seed(&self, other: HashMap<String, ProviderHealth>) {
        let mut map = self.entries.lock().unwrap();
        for (k, mut v) in other {
            while v.latencies.len() > WINDOW {
                v.latencies.pop_front();
            }
            v.latencies.retain(|x| x.is_finite() && *x >= 0.0);
            map.insert(k, v);
        }
    }

    /// Read a health file. Never fails: a missing or corrupt cache degrades
    /// to empty. Losing history is an inconvenience; refusing to start is not.
    pub fn read_file(path: &Path) -> HashMap<String, ProviderHealth> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn load(&self, path: &Path) {
        self.seed(Self::read_file(path));
    }

    /// Write atomically, merging with whatever another process wrote since we
    /// loaded: entries this process touched win, the rest are kept from disk.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut merged = Self::read_file(path);
        let ours = self.snapshot();
        let touched = self.touched.lock().unwrap().clone();
        for (k, v) in ours {
            if touched.contains(&k) || !merged.contains_key(&k) {
                merged.insert(k, v);
            }
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let body = serde_json::to_string_pretty(&merged).expect("health serializes");
        std::fs::write(&tmp, body)
            .and_then(|_| std::fs::rename(&tmp, path))
            .inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })
    }
}

/// `INTERLOPER_HEALTH_PATH`, else `$XDG_STATE_HOME/interloper/health.json`,
/// else `~/.local/state/interloper/health.json`.
pub fn default_health_path() -> PathBuf {
    if let Ok(p) = std::env::var("INTERLOPER_HEALTH_PATH")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("interloper").join("health.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn clocked() -> (HealthStore, Arc<AtomicI64>) {
        let t = Arc::new(AtomicI64::new(1_800_000_000));
        let c = t.clone();
        (
            HealthStore::with_clock(Arc::new(move || {
                Timestamp::from_second(c.load(Ordering::SeqCst)).unwrap()
            })),
            t,
        )
    }

    #[test]
    fn down_recovers_on_probation_after_cooldown() {
        let (h, t) = clocked();
        h.record_error("p", &Error::down("p", "boom"));
        assert_eq!(h.status("p"), Status::Down);
        assert_eq!(h.tier("p"), None);
        t.fetch_add(31, Ordering::SeqCst);
        assert_eq!(h.tier("p"), Some(Tier::Probation));
        // Failing on probation doubles the cooldown.
        h.record_error("p", &Error::down("p", "boom"));
        t.fetch_add(31, Ordering::SeqCst);
        assert_eq!(h.tier("p"), None);
        t.fetch_add(30, Ordering::SeqCst);
        assert_eq!(h.tier("p"), Some(Tier::Probation));
        h.record_success("p", Duration::from_millis(100));
        assert_eq!(h.tier("p"), Some(Tier::Healthy));
        assert_eq!(h.get("p").unwrap().failures, 0);
    }

    #[test]
    fn cooldown_doubles_and_caps() {
        assert_eq!(cooldown(1), Duration::from_secs(30));
        assert_eq!(cooldown(2), Duration::from_secs(60));
        assert_eq!(cooldown(50), COOLDOWN_MAX);
    }

    #[test]
    fn rate_limit_honours_retry_after() {
        let (h, t) = clocked();
        h.record_error(
            "p",
            &Error::RateLimited {
                provider: "p".into(),
                retry_after: Some(Duration::from_secs(120)),
            },
        );
        t.fetch_add(60, Ordering::SeqCst);
        assert_eq!(h.tier("p"), None);
        t.fetch_add(61, Ordering::SeqCst);
        assert_eq!(h.tier("p"), Some(Tier::Probation));
    }

    #[test]
    fn slow_is_relative_to_own_baseline() {
        let h = HealthStore::new();
        for _ in 0..5 {
            h.record_success("p", Duration::from_secs(1));
        }
        h.record_success("p", Duration::from_secs(4));
        assert_eq!(h.status("p"), Status::Slow);
        h.record_success("p", Duration::from_secs(1));
        assert_eq!(h.status("p"), Status::Ok);
        // A provider whose normal pace is slow is not SLOW.
        for _ in 0..6 {
            h.record_success("q", Duration::from_secs(39));
        }
        assert_eq!(h.status("q"), Status::Ok);
    }

    #[test]
    fn quarantine_is_sticky_until_cleared() {
        let h = HealthStore::new();
        h.record_error("p", &Error::drift("p", "x", "y"));
        h.record_success("p", Duration::from_secs(1));
        h.record_error("p", &Error::down("p", "z"));
        assert_eq!(h.status("p"), Status::Quarantined);
        assert_eq!(h.tier("p"), None);
        assert!(h.unquarantine("p"));
        assert_eq!(h.tier("p"), Some(Tier::Healthy));
        assert!(!h.unquarantine("p"));
    }

    #[test]
    fn neutral_errors_teach_nothing() {
        let h = HealthStore::new();
        h.record_error("p", &Error::gone("p", "1"));
        h.record_error("p", &Error::SolverUnavailable("x".into()));
        assert!(h.get("p").is_none());
    }

    #[test]
    fn challenge_sets_residential_hint_and_success_clears_it() {
        let h = HealthStore::new();
        h.record_error(
            "p",
            &Error::Challenge {
                provider: "p".into(),
                status: 403,
            },
        );
        assert!(h.get("p").unwrap().needs_residential_ip);
        h.record_success("p", Duration::from_millis(1));
        assert!(!h.get("p").unwrap().needs_residential_ip);
    }

    #[test]
    fn save_merges_with_concurrent_writer() {
        let dir = std::env::temp_dir().join(format!("ilp-health-{}", std::process::id()));
        let path = dir.join("h.json");
        let a = HealthStore::new();
        a.record_success("alpha", Duration::from_secs(1));
        a.save(&path).unwrap();
        // A second process loads, measures something else, saves.
        let b = HealthStore::new();
        b.load(&path);
        b.record_success("beta", Duration::from_secs(2));
        // Meanwhile the first process measures alpha again and saves last.
        a.record_success("alpha", Duration::from_secs(3));
        b.save(&path).unwrap();
        a.save(&path).unwrap();
        let disk = HealthStore::read_file(&path);
        assert!(disk.contains_key("beta"), "a must not erase b's entry");
        assert_eq!(disk["alpha"].latencies.len(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn corrupt_file_loads_empty() {
        let dir = std::env::temp_dir().join(format!("ilp-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(HealthStore::read_file(&path).is_empty());
        std::fs::write(&path, r#"{"p": {"status": "bogus"}}"#).unwrap();
        assert!(HealthStore::read_file(&path).is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
