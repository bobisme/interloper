//! Token buckets, keyed so one noisy client cannot spend another's budget.
//!
//! A *valid* API key gets its own bucket per client address. An invalid or
//! missing key buckets on the address alone: the header is attacker-controlled
//! before auth runs, so if any header value bought its own bucket, rotating a
//! bogus key per request would mint a fresh bucket each time and leave
//! unauthenticated floods unmetered.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Limiter {
    capacity: f64,
    per_sec: f64,
    buckets: Mutex<HashMap<String, (f64, Instant)>>,
}

impl Limiter {
    pub fn new(n: u32, window: Duration) -> Self {
        Limiter {
            capacity: n as f64,
            per_sec: n as f64 / window.as_secs_f64(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut b = self.buckets.lock().unwrap();
        // Bound memory: drop buckets that have fully refilled.
        if b.len() > 50_000 {
            let full = self.capacity / self.per_sec;
            b.retain(|_, (_, at)| now.duration_since(*at).as_secs_f64() < full);
        }
        let (tokens, at) = b.entry(key.to_string()).or_insert((self.capacity, now));
        let refill = now.duration_since(*at).as_secs_f64() * self.per_sec;
        *tokens = (*tokens + refill).min(self.capacity);
        *at = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_drains_and_refills() {
        let l = Limiter::new(2, Duration::from_secs(60));
        let t = Instant::now();
        assert!(l.allow_at("a", t));
        assert!(l.allow_at("a", t));
        assert!(!l.allow_at("a", t));
        assert!(l.allow_at("b", t), "buckets are independent");
        assert!(l.allow_at("a", t + Duration::from_secs(30)));
    }
}
