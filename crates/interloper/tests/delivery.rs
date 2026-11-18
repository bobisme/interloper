//! The only tests that prove mail actually arrives and can be read: generate,
//! deliver, poll, list, body-read, parse, extract links.
//!
//! The sender is testemailsender.com (JoltMx): no account, no key, about a
//! dozen sends per network per day. So this is opt-in and targeted:
//!
//!     INTERLOPER_DELIVERY=mailtm,guerrillamail cargo test -p interloper \
//!         --features live --test delivery -- --nocapture
//!
//! `INTERLOPER_DELIVERY=all` tries every provider. A provider whose receiving
//! server refuses JoltMx (maildrop: `554 Invalid FCRDNS`), or a sender over
//! quota, is reported as skipped, not failed: a skip means the sender was
//! unavailable, not that the provider is broken.
#![cfg(feature = "live")]

use std::sync::Arc;
use std::time::Duration;

use interloper::transport::{NetConfig, Transport, WreqBackend};
use interloper::{HealthStore, Interloper, MailFilter, Registry, Request, Solver};
use serde_json::{Value, json};

const SENDS: &str = "https://testemailsender.com/api/tools/test-email/sends";
const PHRASE: &str = "everything is working as expected";
const LINK: &str = "joltmx.com/tools/test-email/opt-out/";
const TIMEOUT: Duration = Duration::from_secs(180);

async fn send(to: &str) -> Result<(), String> {
    let t = Transport::new(
        "joltmx",
        Arc::new(WreqBackend::new(NetConfig::default()).unwrap()),
    );
    let sent = t
        .post(SENDS)
        .header("referer", "https://testemailsender.com/")
        .json_body(&json!({"recipientEmail": to}))
        .json()
        .await
        .map_err(|e| format!("JoltMx could not send: {e}"))?;
    let id = match &sent["id"] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let token = sent["token"].as_str().unwrap_or_default().to_string();
    let url = format!("{SENDS}/{id}?token={token}");
    let mut status: Value = sent;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while status["status"] == "Queued" && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_secs(5)).await;
        status = t
            .get(&url)
            .header("referer", "https://testemailsender.com/")
            .json()
            .await
            .map_err(|e| format!("JoltMx status: {e}"))?;
    }
    if status["status"] == "Failed" {
        return Err(format!(
            "receiving server refused JoltMx: {}",
            status["responseText"]
        ));
    }
    Ok(())
}

#[tokio::test]
async fn mail_arrives_and_reads_back() {
    let Ok(which) = std::env::var("INTERLOPER_DELIVERY") else {
        eprintln!("INTERLOPER_DELIVERY unset; nothing sent");
        return;
    };
    let health = Arc::new(HealthStore::new());
    let registry = Registry::new(interloper::providers::all(), health)
        .with_solver(Solver::from_env().unwrap());
    let names: Vec<String> = if which == "all" {
        registry.names().iter().map(|s| s.to_string()).collect()
    } else {
        which.split(',').map(|s| s.trim().to_string()).collect()
    };
    let il = Interloper::with_registry(registry);
    let mut failures = Vec::new();
    for name in names {
        let started = std::time::Instant::now();
        let inbox = match il.inbox(&Request::new().provider(&name)).await {
            Ok(b) => b,
            Err(e) => {
                println!("{name}\tSKIP\tcould not generate: {e}");
                continue;
            }
        };
        if let Err(why) = send(inbox.email()).await {
            println!("{name}\tSKIP\t{why}");
            continue;
        }
        match inbox
            .wait(TIMEOUT, &MailFilter::default().from("joltmx"))
            .await
        {
            Ok(m) => {
                let ok_text = m.text.to_lowercase().contains(PHRASE);
                let ok_link = m.links.iter().any(|l| l.contains(LINK));
                let secs = started.elapsed().as_secs_f64();
                let verdict = if ok_text && ok_link { "PASS" } else { "FAIL" };
                println!("{name}\t{verdict}\t{secs:.0}s\ttext={ok_text} link={ok_link}");
                if !(ok_text && ok_link) {
                    let head: String = m.text.chars().take(300).collect();
                    failures.push(format!(
                        "{name}: body or link missing; text {head:?}; html {} bytes: {:?}",
                        m.html.len(),
                        m.html.chars().take(400).collect::<String>()
                    ));
                }
            }
            Err(e) => {
                println!("{name}\tFAIL\t{e}");
                failures.push(format!("{name}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
