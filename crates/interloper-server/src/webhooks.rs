//! One-shot outbound webhooks: "POST me the next message to this address".
//!
//! Registrations live in this process; a restart drops pending hooks. A hook
//! is one-shot and capped at `webhook_max`, so durability would buy little.
//!
//! SSRF: the URL's host is resolved once, every address is checked against
//! private/loopback/link-local/reserved ranges, and the delivery connection is
//! **pinned to the addresses that passed**. cowbird checked, then let curl
//! re-resolve at connect time, and documented the DNS-rebinding window it left
//! open; pinning closes it. Redirects are never followed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::task::JoinHandle;

use crate::service::Service;

const RETRIES: u32 = 3;
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(15);
pub const SIGNATURE_HEADER: &str = "x-interloper-signature";

fn blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1])) // CGNAT
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // unique local
                || (seg[0] & 0xffc0) == 0xfe80 // link local
                || seg[0] == 0x2001 && seg[1] == 0x0db8 // documentation
        }
    }
}

/// A validated destination: the URL plus the addresses it may connect to.
#[derive(Debug, Clone)]
pub struct Target {
    pub url: url::Url,
    pub pinned: Option<Vec<SocketAddr>>,
}

pub async fn validate(raw: &str, allow_private: bool) -> Result<Target, String> {
    let url =
        url::Url::parse(raw).map_err(|_| "url must be an absolute http(s) URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("url must be http or https".into());
    }
    let host = url.host_str().ok_or("url missing host")?.to_string();
    if !url.username().is_empty() || url.password().is_some() {
        return Err("url must not carry credentials".into());
    }
    if allow_private {
        return Ok(Target { url, pinned: None });
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::net::lookup_host((bare, port))
            .await
            .map_err(|e| format!("cannot resolve webhook host: {e}"))?
            .collect(),
    };
    if addrs.is_empty() {
        return Err("webhook host resolves to nothing".into());
    }
    if addrs.iter().any(|a| blocked(a.ip())) {
        return Err(
            "webhook host resolves to a private or loopback address (set INTERLOPER_WEBHOOK_ALLOW_PRIVATE=1 to override)"
                .into(),
        );
    }
    Ok(Target {
        url,
        pinned: Some(addrs),
    })
}

pub fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac takes any key");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Hook {
    pub id: String,
    pub address: String,
    pub url: String,
    pub timeout: u64,
}

pub struct Webhooks {
    service: Arc<Service>,
    allow_private: bool,
    secret: Option<String>,
    hooks: Mutex<HashMap<String, (Hook, JoinHandle<()>)>>,
}

impl Webhooks {
    pub fn new(service: Arc<Service>, allow_private: bool, secret: Option<String>) -> Arc<Self> {
        Arc::new(Webhooks {
            service,
            allow_private,
            secret,
            hooks: Mutex::new(HashMap::new()),
        })
    }

    pub async fn create(
        self: &Arc<Self>,
        address: String,
        url: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let target = validate(url, self.allow_private).await?;
        let id = format!("{:012x}", rand::random::<u64>() & 0xffff_ffff_ffff);
        let hook = Hook {
            id: id.clone(),
            address: address.clone(),
            url: url.to_string(),
            timeout: timeout.as_secs(),
        };
        let me = self.clone();
        let hook_id = id.clone();
        // Hold the lock across spawn+insert so the task's own cleanup can
        // never run before its entry exists.
        let mut hooks = self.hooks.lock().unwrap();
        let task = tokio::spawn(async move {
            me.run(&address, &target, timeout).await;
            me.hooks.lock().unwrap().remove(&hook_id);
        });
        hooks.insert(id.clone(), (hook, task));
        Ok(id)
    }

    pub fn list(&self) -> Vec<Hook> {
        let mut v: Vec<Hook> = self
            .hooks
            .lock()
            .unwrap()
            .values()
            .map(|(h, _)| h.clone())
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v
    }

    pub fn cancel(&self, id: &str) -> bool {
        match self.hooks.lock().unwrap().remove(id) {
            Some((_, task)) => {
                task.abort();
                true
            }
            None => false,
        }
    }

    pub fn shutdown(&self) {
        for (_, (_, task)) in self.hooks.lock().unwrap().drain() {
            task.abort();
        }
    }

    async fn run(&self, address: &str, target: &Target, timeout: Duration) {
        let payload = match self
            .service
            .wait(address, timeout, None, false, &Default::default())
            .await
        {
            Ok(Some((m, code))) => {
                let mut p = crate::message_json(&m, code.as_deref());
                p["event"] = json!("message");
                p["address"] = json!(address);
                p
            }
            Ok(None) => json!({"event": "timeout", "address": address}),
            Err(e) => {
                tracing::warn!(address, error = ?e, "webhook wait failed");
                json!({"event": "error", "address": address})
            }
        };
        self.deliver(target, &payload).await;
    }

    async fn deliver(&self, target: &Target, payload: &Value) {
        let body = serde_json::to_vec(payload).expect("json");
        let mut b = wreq::Client::builder()
            .redirect(wreq::redirect::Policy::none())
            .timeout(DELIVERY_TIMEOUT);
        if let (Some(addrs), Some(host)) = (&target.pinned, target.url.host_str()) {
            b = b.resolve_to_addrs(host.to_string(), addrs.iter().copied());
        }
        let Ok(client) = b.build() else {
            tracing::warn!("webhook client could not be built");
            return;
        };
        for attempt in 1..=RETRIES {
            let mut req = client
                .post(target.url.as_str())
                .header("content-type", "application/json")
                .body(body.clone());
            if let Some(secret) = &self.secret {
                req = req.header(SIGNATURE_HEADER, sign(secret, &body));
            }
            match req.send().await {
                Ok(r) if r.status().as_u16() < 400 => return,
                Ok(r) => {
                    tracing::info!(url = %target.url, status = r.status().as_u16(), attempt, "webhook delivery refused")
                }
                Err(e) => {
                    tracing::info!(url = %target.url, error = %e, attempt, "webhook delivery error")
                }
            }
            tokio::time::sleep(Duration::from_secs(2 * attempt as u64)).await;
        }
        tracing::warn!(url = %target.url, "webhook delivery failed after {RETRIES} attempts");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn private_targets_are_refused() {
        for u in [
            "http://127.0.0.1/x",
            "http://10.0.0.5/",
            "http://[::1]:8080/",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.1.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://localhost/",
        ] {
            assert!(validate(u, false).await.is_err(), "{u}");
        }
    }

    #[tokio::test]
    async fn bad_shapes_are_refused() {
        for u in ["ftp://x.test/", "not a url", "http://user:pw@example.com/"] {
            assert!(validate(u, false).await.is_err(), "{u}");
        }
    }

    #[tokio::test]
    async fn public_literal_is_pinned() {
        let t = validate("https://93.184.215.14/hook", false).await.unwrap();
        assert_eq!(
            t.pinned.unwrap(),
            vec!["93.184.215.14:443".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn allow_private_skips_resolution() {
        assert!(
            validate("http://127.0.0.1:9/", true)
                .await
                .unwrap()
                .pinned
                .is_none()
        );
    }

    #[test]
    fn signature_is_hmac_sha256() {
        // RFC 4231 test case 2.
        let sig = sign("Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
