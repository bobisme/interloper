//! `interloper`: disposable inboxes from the shell.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use futures::StreamExt;
use interloper::health::Status;
use interloper::{Address, Error, Inbox, Interloper, Kind, MailFilter, Message, Request};
use serde_json::{Value, json};

mod canary;

#[derive(Parser)]
#[command(
    name = "interloper",
    version,
    about = "Disposable inboxes from every backend, behind one interface."
)]
struct Cli {
    /// Log routing decisions and retries to stderr (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire an address. Prints `ADDRESS<TAB>PROVIDER<TAB>TTL<TAB>TOKEN`.
    New(NewArgs),
    /// Wait for mail and print it, its one-time code, or a link.
    Wait(WaitArgs),
    /// Stream mail as it arrives, one line (or JSON object) per message.
    Watch(TargetArgs),
    /// List an inbox, or print one message.
    Read(ReadArgs),
    /// The provider health matrix: measured, not declared.
    Providers(JsonFlag),
    /// Probe every provider live (generate, then list) and record health.
    Canary(CanaryArgs),
    /// Inspect or clear recorded health.
    #[command(subcommand)]
    Health(HealthCmd),
}

#[derive(Args)]
struct JsonFlag {
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct NewArgs {
    #[arg(long, short)]
    provider: Option<String>,
    /// gmail-alias, outlook-alias, own-domain or edu.
    #[arg(long)]
    kind: Option<Kind>,
    /// Shorthand for --kind gmail-alias.
    #[arg(long, conflicts_with = "kind")]
    gmail: bool,
    /// Choose the local part (only backends that allow it are considered).
    #[arg(long)]
    local: Option<String>,
    #[arg(long)]
    domain: Option<String>,
    /// Never hand out an address at this domain (repeatable).
    #[arg(long = "not-domain")]
    not_domain: Vec<String>,
    /// The address must live at least this long, e.g. 30m, 2h, 1d.
    #[arg(long, value_parser = parse_duration)]
    min_ttl: Option<Duration>,
    /// Acquire this many, spread across providers.
    #[arg(long, short = 'n', default_value_t = 1)]
    count: usize,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct TargetArgs {
    /// A token from `new`, or a bare address for backends that need no state.
    target: String,
    /// The provider, when TARGET is a bare address it cannot be inferred from.
    #[arg(long, short)]
    provider: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct WaitArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Print the one-time code instead of the message.
    #[arg(long, conflicts_with = "link")]
    otp: bool,
    /// Regex for the code; capture group 1 wins when present.
    #[arg(long, requires = "otp")]
    pattern: Option<String>,
    /// Print the first link, optionally only one containing this text.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    link: Option<String>,
    /// Only mail whose sender contains this (case-insensitive).
    #[arg(long)]
    from: Option<String>,
    /// Only mail whose subject contains this (case-insensitive).
    #[arg(long)]
    subject: Option<String>,
    #[arg(long, short, default_value = "120s", value_parser = parse_duration)]
    timeout: Duration,
}

#[derive(Args)]
struct ReadArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// A message id from the listing.
    id: Option<String>,
}

#[derive(Args)]
struct CanaryArgs {
    #[arg(long)]
    json: bool,
    /// Providers probed at once.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Only these providers.
    only: Vec<String>,
}

#[derive(Subcommand)]
enum HealthCmd {
    /// Return a quarantined provider to routing.
    Clear { provider: String },
    /// Show the raw recorded health.
    Show,
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len()),
    );
    let n: f64 = num.parse().map_err(|_| format!("not a duration: {s:?}"))?;
    let secs = match unit {
        "" | "s" => n,
        "ms" => n / 1000.0,
        "m" => n * 60.0,
        "h" => n * 3600.0,
        "d" => n * 86400.0,
        _ => return Err(format!("unknown unit in {s:?}; use ms, s, m, h or d")),
    };
    Ok(Duration::from_secs_f64(secs))
}

fn fmt_ttl(d: Option<Duration>) -> String {
    match d {
        None => "forever".into(),
        Some(d) => {
            let s = d.as_secs();
            match s {
                s if s % 86400 == 0 => format!("{}d", s / 86400),
                s if s % 3600 == 0 => format!("{}h", s / 3600),
                s if s % 60 == 0 => format!("{}m", s / 60),
                s => format!("{s}s"),
            }
        }
    }
}

fn message_json(m: &Message, code: Option<&str>) -> Value {
    json!({
        "id": m.id,
        "sender": m.sender,
        "subject": m.subject,
        "received_at": m.received_at.map(|t| t.to_string()),
        "text": m.text,
        "links": m.links,
        "otp": code,
    })
}

/// Resolve a token or bare address to an inbox.
fn open(il: &Interloper, t: &TargetArgs) -> Result<Inbox, Error> {
    if Address::looks_like_token(&t.target) {
        return il.resume_token(&t.target);
    }
    let value = t.target.trim().to_string();
    let provider = match &t.provider {
        Some(p) => p.clone(),
        None => infer_provider(il, &value)?,
    };
    il.resume(Address::new(value, provider))
}

/// A bare address names its provider when exactly one declares its domain.
fn infer_provider(il: &Interloper, address: &str) -> Result<String, Error> {
    let domain = address
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .unwrap_or_default();
    let owners: Vec<&str> = il
        .registry()
        .specs()
        .filter(|s| {
            s.caps
                .domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&domain))
        })
        .map(|s| s.name)
        .collect();
    match owners.as_slice() {
        [one] => Ok(one.to_string()),
        [] => Err(Error::unsupported(format!(
            "no provider declares {domain}; pass --provider, or use the token from `new`"
        ))),
        many => Err(Error::unsupported(format!(
            "{domain} is served by {}; pass --provider",
            many.join(", ")
        ))),
    }
}

async fn cmd_new(il: &Interloper, a: NewArgs) -> Result<(), Error> {
    let mut req = Request::new();
    req.provider = a.provider;
    req.kind = if a.gmail {
        Some(Kind::GmailAlias)
    } else {
        a.kind
    };
    req.local = a.local;
    req.domain = a.domain;
    req.domain_not_in = a.not_domain;
    req.address_ttl = a.min_ttl;
    let boxes = if a.count == 1 {
        vec![il.inbox(&req).await?]
    } else {
        il.inboxes(a.count, &req).await?
    };
    for b in &boxes {
        let ttl = b.provider().caps().address_ttl;
        if a.json {
            let line = json!({
                "address": b.email(),
                "provider": b.provider().name(),
                "address_ttl": ttl.map(|d| d.as_secs()),
                "expires_at": b.address().expires_at.map(|t| t.to_string()),
                "token": b.token(),
            });
            println!("{line}");
        } else {
            println!(
                "{}\t{}\t{}\t{}",
                b.email(),
                b.provider().name(),
                fmt_ttl(ttl),
                b.token()
            );
        }
    }
    Ok(())
}

async fn cmd_wait(il: &Interloper, a: WaitArgs) -> Result<(), Error> {
    let inbox = open(il, &a.target)?;
    let filter = MailFilter {
        from: a.from,
        subject: a.subject,
    };
    let json = a.target.json;
    if a.otp {
        let pattern = a.pattern.as_deref().map(regex_lite).transpose()?;
        let code = inbox
            .otp_matching(a.timeout, &filter, pattern.as_ref())
            .await?;
        if json {
            println!("{}", json!({"otp": code}));
        } else {
            println!("{code}");
        }
    } else if let Some(needle) = a.link {
        let needle = (!needle.is_empty()).then_some(needle);
        let link = inbox
            .link_matching(a.timeout, &filter, needle.as_deref())
            .await?;
        if json {
            println!("{}", json!({"link": link}));
        } else {
            println!("{link}");
        }
    } else {
        let m = inbox.wait(a.timeout, &filter).await?;
        if json {
            println!("{}", message_json(&m, None));
        } else {
            println!("{}\t{}", m.sender, m.subject);
        }
    }
    Ok(())
}

fn regex_lite(p: &str) -> Result<interloper::regex::Regex, Error> {
    interloper::regex::Regex::new(p).map_err(|e| Error::unsupported(format!("bad --pattern: {e}")))
}

async fn cmd_watch(il: &Interloper, t: TargetArgs) -> Result<(), Error> {
    let inbox = open(il, &t)?;
    let mut stream = inbox.watch(None);
    while let Some(m) = stream.next().await {
        let m = m?;
        if t.json {
            let code = interloper::parse::extract_otp(&m.subject, &m.text, None);
            println!("{}", message_json(&m, code.as_deref()));
        } else {
            println!("{}\t{}\t{}", m.id, m.sender, m.subject);
        }
    }
    Ok(())
}

async fn cmd_read(il: &Interloper, a: ReadArgs) -> Result<(), Error> {
    let inbox = open(il, &a.target)?;
    match a.id {
        Some(id) => {
            let m = inbox.get(&id).await?;
            if a.target.json {
                let code = interloper::parse::extract_otp(&m.subject, &m.text, None);
                println!("{}", message_json(&m, code.as_deref()));
            } else {
                println!("From: {}\nSubject: {}\n\n{}", m.sender, m.subject, m.text);
                if !m.links.is_empty() {
                    println!("\nLinks:");
                    for l in &m.links {
                        println!("  {l}");
                    }
                }
            }
        }
        None => {
            for r in inbox.messages().await? {
                if a.target.json {
                    println!(
                        "{}",
                        json!({"id": r.id, "sender": r.sender, "subject": r.subject,
                               "received_at": r.received_at.map(|t| t.to_string()), "locked": r.locked})
                    );
                } else {
                    println!("{}\t{}\t{}", r.id, r.sender, r.subject);
                }
            }
        }
    }
    Ok(())
}

fn cmd_providers(il: &Interloper, json: bool) {
    let health = il.health();
    let solver = il.registry().solver().is_some();
    let rows: Vec<_> = il
        .registry()
        .specs()
        .map(|s| {
            let h = health.get(s.name);
            let mut status = health.status(s.name).to_string();
            if s.caps.needs_solver && !solver {
                status = "no-solver".into();
            } else if health.status(s.name) == Status::Down && health.tier(s.name).is_some() {
                status = "probation".into();
            }
            (s, status, health.p50(s.name), h)
        })
        .collect();
    if json {
        let out: Vec<Value> = rows
            .iter()
            .map(|(s, status, p50, h)| {
                json!({
                    "provider": s.name,
                    "status": status,
                    "p50": p50,
                    "kind": s.caps.kind.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
                    "sites": s.caps.sites,
                    "address_ttl": s.caps.address_ttl.map(|d| d.as_secs()),
                    "custom_local": s.caps.custom_local,
                    "needs_solver": s.caps.needs_solver,
                    "last_failure": h.as_ref().and_then(|h| h.last_failure.clone()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }
    println!(
        "{:<16}{:<13}{:<9}{:<9}{:<36}SITES",
        "PROVIDER", "STATUS", "P50", "TTL", "KIND"
    );
    for (s, status, p50, _) in rows {
        let kinds = s
            .caps
            .kind
            .iter()
            .map(|k| k.as_str())
            .collect::<Vec<_>>()
            .join(",");
        // `is_some`, not truthiness: a p50 of 0.0 is a real measurement
        // (a catch-all generates without any HTTP call).
        let p50 = p50.map_or("-".into(), |p| format!("{p:.1}s"));
        println!(
            "{:<16}{:<13}{:<9}{:<9}{:<36}{}",
            s.name,
            status,
            p50,
            fmt_ttl(s.caps.address_ttl),
            kinds,
            s.caps.sites.join(",")
        );
    }
}

fn cmd_health(il: &Interloper, cmd: HealthCmd) -> Result<(), Error> {
    match cmd {
        HealthCmd::Clear { provider } => {
            if !il.registry().contains(&provider) {
                return Err(Error::unsupported(format!("unknown provider {provider:?}")));
            }
            let was = il.health().unquarantine(&provider);
            println!(
                "{provider}: {}",
                if was {
                    "cleared"
                } else {
                    "was not quarantined"
                }
            );
        }
        HealthCmd::Show => {
            let snap = il.health().snapshot();
            let sorted: std::collections::BTreeMap<_, _> = snap.into_iter().collect();
            println!("{}", serde_json::to_string_pretty(&sorted).unwrap());
        }
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<ExitCode, Error> {
    let il = Arc::new(Interloper::from_env()?);
    let result = match cli.command {
        Command::New(a) => cmd_new(&il, a).await.map(|_| ExitCode::SUCCESS),
        Command::Wait(a) => cmd_wait(&il, a).await.map(|_| ExitCode::SUCCESS),
        Command::Watch(t) => cmd_watch(&il, t).await.map(|_| ExitCode::SUCCESS),
        Command::Read(a) => cmd_read(&il, a).await.map(|_| ExitCode::SUCCESS),
        Command::Providers(j) => {
            cmd_providers(&il, j.json);
            Ok(ExitCode::SUCCESS)
        }
        Command::Canary(a) => canary::run(&il, a.only, a.concurrency, a.json).await,
        Command::Health(h) => cmd_health(&il, h).map(|_| ExitCode::SUCCESS),
    };
    // A read-only or full disk must not fail the user's command.
    if let Err(e) = il.save_health() {
        tracing_subscriber_warn(&e);
    }
    result
}

fn tracing_subscriber_warn(e: &std::io::Error) {
    eprintln!("warning: could not save provider health: {e}");
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "warn",
        1 => "interloper=debug",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("INTERLOPER_LOG")
        .unwrap_or_else(|_| level.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    match run(cli).await {
        Ok(code) => code,
        Err(Error::Timeout(msg)) => {
            eprintln!("timeout: {msg}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("1.5m").unwrap(), Duration::from_secs(90));
        assert!(parse_duration("2 weeks").is_err());
    }

    #[test]
    fn ttl_formatting() {
        assert_eq!(fmt_ttl(None), "forever");
        assert_eq!(fmt_ttl(Some(Duration::from_secs(3600))), "1h");
        assert_eq!(fmt_ttl(Some(Duration::from_secs(600))), "10m");
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
