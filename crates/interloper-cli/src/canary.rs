//! Live probe of every provider: `generate()` then `list()`.
//!
//! The offline suite proves the repo is internally consistent; only this
//! catches a backend changing its API underneath an adapter, which is the
//! failure every library of this kind eventually dies of. Probes run
//! concurrently (cowbird probed one at a time), each provider bounded by its
//! own transport gate.
//!
//! "down" alone does not fail the run: a datacenter IP drawing a Cloudflare
//! challenge is not a defect. Only "quarantined" (schema drift: the adapter is
//! wrong) exits non-zero.

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use futures::StreamExt;
use interloper::health::Status;
use interloper::{Error, GenerateOptions, Interloper};
use serde_json::json;

struct Outcome {
    status: &'static str,
    seconds: f64,
    detail: Option<String>,
}

pub async fn run(
    il: &Interloper,
    only: Vec<String>,
    concurrency: usize,
    json_out: bool,
) -> Result<ExitCode, Error> {
    for name in &only {
        if !il.registry().contains(name) {
            return Err(Error::unsupported(format!("unknown provider {name:?}")));
        }
    }
    let names: Vec<&'static str> = il
        .registry()
        .names()
        .into_iter()
        .filter(|n| only.is_empty() || only.iter().any(|o| o == n))
        .collect();
    let has_solver = il.registry().solver().is_some();
    let results: BTreeMap<&str, Outcome> = futures::stream::iter(names)
        .map(|name| async move {
            let p = il.registry().get(name).expect("listed");
            // Never equipped to reach it: "down" would be a lie that sticks.
            if p.caps().needs_solver && !has_solver {
                return (
                    name,
                    Outcome {
                        status: "skipped",
                        seconds: 0.0,
                        detail: Some("needs a solver".into()),
                    },
                );
            }
            let started = Instant::now();
            let probe = async {
                let a = p.generate(&GenerateOptions::default()).await?;
                p.list(&a).await?;
                Ok::<_, Error>(())
            };
            let result = tokio::time::timeout(Duration::from_secs(90), probe).await;
            let seconds = started.elapsed().as_secs_f64();
            let detail = match &result {
                Ok(Err(e)) => Some(e.to_string()),
                Err(_) => {
                    il.health()
                        .record_error(name, &Error::down(name, "canary timed out after 90s"));
                    Some("timed out after 90s".into())
                }
                Ok(Ok(())) => None,
            };
            let status = match il.health().status(name) {
                Status::Ok | Status::Slow if detail.is_none() => "ok",
                Status::Quarantined => "quarantined",
                _ if detail.is_some() && matches!(result, Ok(Err(ref e)) if !e.reroutable()) => {
                    "error"
                }
                _ => "down",
            };
            (
                name,
                Outcome {
                    status,
                    seconds,
                    detail,
                },
            )
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    if json_out {
        let map: BTreeMap<_, _> = results
            .iter()
            .map(|(n, o)| (*n, json!({"status": o.status, "seconds": (o.seconds * 10.0).round() / 10.0, "detail": o.detail})))
            .collect();
        println!("{}", serde_json::to_string_pretty(&map).unwrap());
    } else {
        for (n, o) in &results {
            let detail = o
                .detail
                .as_deref()
                .map(|d| format!("\t{d}"))
                .unwrap_or_default();
            println!("{n}\t{}\t{:.1}s{detail}", o.status, o.seconds);
        }
    }
    let drifted = results.values().any(|o| o.status == "quarantined");
    Ok(if drifted {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
