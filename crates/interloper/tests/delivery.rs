//! The only tests that prove mail actually arrives and can be read: generate,
//! deliver, poll, list, body-read, parse, extract the code and the link.
//!
//! Opt-in, and live. Pick the providers with `INTERLOPER_DELIVERY` (a comma
//! list, `provider:domain` to pin a domain, or `all`):
//!
//!     INTERLOPER_DELIVERY=mailtm,guerrillamail cargo test -p interloper \
//!         --features live --test delivery -- --nocapture
//!
//! Sender, in order of preference:
//! - **Resend** when `INTERLOPER_RESEND_KEY` and `INTERLOPER_SENDER_FROM` (an
//!   address at a domain verified in Resend) are set. Each inbox gets its own
//!   message carrying a random code and a unique link, so the test checks the
//!   exact OTP and link that were sent, not a fixed phrase.
//! - **JoltMx** (testemailsender.com) otherwise: no account, about a dozen
//!   sends per network per day, fixed content.
//!
//! A provider that cannot generate, or whose server refuses the sender, is
//! SKIP, not FAIL: a skip says nothing about whether the adapter reads mail.
#![cfg(feature = "live")]

use std::sync::Arc;
use std::time::Duration;

use interloper::transport::{NetConfig, Transport, WreqBackend};
use interloper::{HealthStore, Inbox, Interloper, MailFilter, Registry, Request, Solver};
use rand::Rng;
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(180);
const PARALLEL: usize = 6;

fn wire(name: &str) -> Transport {
    Transport::new(
        name,
        Arc::new(WreqBackend::new(NetConfig::default()).unwrap()),
    )
}

/// What one inbox should receive, and how to recognize it.
struct Expect {
    /// Substring of the subject or sender that singles this message out.
    filter: MailFilter,
    /// The code `extract_otp` must find, when the sender controls content.
    otp: Option<String>,
    /// A substring some extracted link must contain.
    link: String,
    /// A phrase the plain text must contain.
    phrase: String,
}

enum Sender {
    Resend { key: String, from: String },
    JoltMx,
}

impl Sender {
    fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        match (get("INTERLOPER_RESEND_KEY"), get("INTERLOPER_SENDER_FROM")) {
            (Some(key), Some(from)) => Sender::Resend {
                key: key.trim().to_string(),
                from,
            },
            _ => Sender::JoltMx,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Sender::Resend { .. } => "resend",
            Sender::JoltMx => "joltmx",
        }
    }

    async fn send(&self, to: &str) -> Result<Expect, String> {
        match self {
            Sender::Resend { key, from } => resend(key, from, to).await,
            Sender::JoltMx => joltmx(to).await,
        }
    }
}

async fn resend(key: &str, from: &str, to: &str) -> Result<Expect, String> {
    let (nonce, code) = {
        let mut r = rand::rng();
        (
            format!("{:012x}", r.random::<u64>() & 0xffff_ffff_ffff),
            format!("{:06}", r.random_range(0..1_000_000u32)),
        )
    };
    let link = format!("https://example.com/interloper/verify/{nonce}");
    let subject = format!("interloper delivery check {nonce}");
    let html = format!(
        "<p>Hello from the interloper delivery test.</p>\
         <p>Your verification code is <b>{code}</b>.</p>\
         <p><a href=\"{link}\">Confirm this address</a></p>\
         <p style=\"color:#888\">Sent {year} to a disposable inbox; no reply needed.</p>",
        year = 2026
    );
    let text = format!(
        "Hello from the interloper delivery test.\n\nYour verification code is {code}.\n\nConfirm this address: {link}\n"
    );
    let t = wire("resend");
    let sent = t
        .post("https://api.resend.com/emails")
        .bearer(key)
        .json_body(&json!({
            "from": from, "to": [to], "subject": subject, "html": html, "text": text,
        }))
        .send()
        .await
        .map_err(|e| format!("Resend could not send: {e}"))?;
    if !sent.is_success() {
        return Err(format!(
            "Resend refused (HTTP {}): {}",
            sent.status,
            sent.text.chars().take(200).collect::<String>()
        ));
    }
    Ok(Expect {
        filter: MailFilter::default().subject(&nonce),
        otp: Some(code),
        link: format!("/verify/{nonce}"),
        phrase: "interloper delivery test".into(),
    })
}

const SENDS: &str = "https://testemailsender.com/api/tools/test-email/sends";

async fn joltmx(to: &str) -> Result<Expect, String> {
    let t = wire("joltmx");
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
    Ok(Expect {
        filter: MailFilter::default().from("joltmx"),
        otp: None,
        link: "joltmx.com/tools/test-email/opt-out/".into(),
        phrase: "everything is working as expected".into(),
    })
}

enum Outcome {
    Pass(String),
    Fail(String),
    Skip(String),
}

async fn check(il: &Interloper, sender: &Sender, name: &str) -> Outcome {
    let started = std::time::Instant::now();
    // `provider:domain` pins the domain, to tell a dead domain from a broken
    // adapter.
    let mut req = Request::new();
    req = match name.split_once(':') {
        Some((p, d)) => req.provider(p).domain(d),
        None => req.provider(name),
    };
    let inbox: Inbox = match il.inbox(&req).await {
        Ok(b) => b,
        Err(e) => return Outcome::Skip(format!("could not generate: {e}")),
    };
    let expect = match sender.send(inbox.email()).await {
        Ok(x) => x,
        Err(why) => return Outcome::Skip(why),
    };
    let m = match inbox.wait(TIMEOUT, &expect.filter).await {
        Ok(m) => m,
        Err(e) => return Outcome::Fail(format!("{e} ({})", inbox.email())),
    };
    let secs = started.elapsed().as_secs_f64();
    let ok_text = m.text.to_lowercase().contains(&expect.phrase);
    let ok_link = m.links.iter().any(|l| l.contains(&expect.link));
    let got_otp = interloper::parse::extract_otp(&m.subject, &m.text, None);
    let ok_otp = match &expect.otp {
        Some(code) => got_otp.as_deref() == Some(code.as_str()),
        None => true,
    };
    let summary = format!(
        "{secs:.0}s text={ok_text} link={ok_link} otp={ok_otp} ({})",
        inbox.email()
    );
    if ok_text && ok_link && ok_otp {
        Outcome::Pass(summary)
    } else {
        Outcome::Fail(format!(
            "{summary}; want otp {:?} got {got_otp:?}; text {:?}; html {} bytes {:?}; links {:?}",
            expect.otp,
            m.text.chars().take(300).collect::<String>(),
            m.html.len(),
            m.html.chars().take(300).collect::<String>(),
            m.links,
        ))
    }
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
    let il = Arc::new(Interloper::with_registry(registry));
    let sender = Arc::new(Sender::from_env());
    // JoltMx's daily budget is tiny; never spend it in parallel bursts.
    let parallel = if matches!(*sender, Sender::JoltMx) {
        1
    } else {
        PARALLEL
    };
    println!("sender: {}", sender.name());
    let gate = Arc::new(tokio::sync::Semaphore::new(parallel));
    let mut tasks = Vec::new();
    for name in names {
        let (il, sender, gate) = (il.clone(), sender.clone(), gate.clone());
        tasks.push(tokio::spawn(async move {
            let _permit = gate.acquire().await.unwrap();
            let out = check(&il, &sender, &name).await;
            match &out {
                Outcome::Pass(s) => println!("{name}\tPASS\t{s}"),
                Outcome::Fail(s) => println!("{name}\tFAIL\t{s}"),
                Outcome::Skip(s) => println!("{name}\tSKIP\t{s}"),
            }
            (name, out)
        }));
    }
    let mut failures = Vec::new();
    for t in tasks {
        if let (name, Outcome::Fail(why)) = t.await.unwrap() {
            failures.push(format!("{name}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
