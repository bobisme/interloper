//! `interloper`: disposable inboxes from the shell.
//!
//! Built to be driven by scripts and AI agents as much as by people: every
//! failure has a stable code and a documented exit status (see `failure`),
//! `--json` (or `INTERLOPER_JSON=1`) makes both results and errors
//! machine-readable, and `interloper guide` prints a manual generated from the
//! same tables the code uses.

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::builder::FalseyValueParser;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use interloper::health::Status;
use interloper::{Address, Inbox, Interloper, Kind, MailFilter, Message, ProviderSpec, Request};
use serde_json::{Value, json};

mod canary;
mod docs;
mod failure;
mod suggest;

use failure::Failure;

type Result<T, E = Failure> = std::result::Result<T, E>;

#[derive(Parser)]
#[command(
    name = "interloper",
    version,
    about = docs::ABOUT,
    long_about = docs::top_long_about(),
    after_help = docs::top_after_help(),
)]
struct Cli {
    /// Log routing decisions and retries to stderr (repeat for more).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Machine-readable output: JSON results on stdout and, on failure, one
    /// JSON error object on stderr. INTERLOPER_JSON=1 turns it on everywhere.
    #[arg(
        long,
        global = true,
        env = "INTERLOPER_JSON",
        action = clap::ArgAction::SetTrue,
        value_parser = FalseyValueParser::new(),
        hide_env_values = true,
    )]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Acquire an address. Prints `ADDRESS<TAB>PROVIDER<TAB>TTL<TAB>TOKEN`.
    #[command(after_help = docs::sub_help("new"))]
    New(NewArgs),
    /// Wait for mail and print it, its one-time code, or a link.
    #[command(after_help = docs::sub_help("wait"))]
    Wait(WaitArgs),
    /// Stream mail as it arrives, one line (or JSON object) per message.
    #[command(after_help = docs::sub_help("watch"))]
    Watch(TargetArgs),
    /// List an inbox, or print one message.
    #[command(after_help = docs::sub_help("read"))]
    Read(ReadArgs),
    /// The provider health matrix: measured, not declared.
    #[command(after_help = docs::sub_help("providers"))]
    Providers,
    /// Probe every provider live (generate, then list) and record health.
    #[command(after_help = docs::sub_help("canary"))]
    Canary(CanaryArgs),
    /// Inspect or clear recorded health.
    #[command(subcommand, after_help = docs::sub_help("health"))]
    Health(HealthCmd),
    /// Run the HTTP API (configured by INTERLOPER_* env; see the server docs).
    #[command(after_help = docs::sub_help("serve"))]
    Serve(ServeArgs),
    /// Print the agent manual: workflow, tokens, commands, JSON shapes, exit
    /// and error codes, environment.
    #[command(after_help = docs::sub_help("guide"))]
    Guide,
    /// Print a shell completion script.
    #[command(after_help = docs::sub_help("completions"))]
    Completions {
        /// The shell to generate for.
        shell: clap_complete::Shell,
    },
    /// Print the man page (roff) to stdout.
    #[command(after_help = docs::sub_help("man"))]
    Man,
}

#[derive(Args)]
struct ServeArgs {
    /// Address to listen on (overrides INTERLOPER_BIND).
    #[arg(long)]
    bind: Option<std::net::SocketAddr>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PrintField {
    /// The email address to type into a form.
    Address,
    /// The ilp1.… token to pass to wait/read/watch.
    Token,
    /// The provider that issued the address.
    Provider,
    /// RFC 3339 expiry time, or `never`.
    Expires,
}

#[derive(Args)]
struct NewArgs {
    /// Use only this provider (see `interloper providers`). Default: the
    /// healthiest provider that satisfies the other options.
    #[arg(long, short, value_name = "NAME")]
    provider: Option<String>,
    #[arg(long, value_name = "KIND", help = docs::kind_help())]
    kind: Option<String>,
    /// Shorthand for --kind gmail-alias.
    #[arg(long, conflicts_with = "kind")]
    gmail: bool,
    /// Choose the local part (only backends that allow it are considered).
    #[arg(long, value_name = "LOCAL")]
    local: Option<String>,
    /// Require this domain, e.g. mail.tm (only providers serving it).
    #[arg(long, value_name = "DOMAIN")]
    domain: Option<String>,
    /// Never hand out an address at this domain (repeatable).
    #[arg(long = "not-domain", value_name = "DOMAIN")]
    not_domain: Vec<String>,
    /// The address must live at least this long, e.g. 30m, 2h, 1d.
    #[arg(long, value_parser = parse_duration, value_name = "DURATION")]
    min_ttl: Option<Duration>,
    /// Acquire this many, spread across providers.
    #[arg(long, short = 'n', default_value_t = 1, value_name = "N")]
    count: usize,
    /// Print only this field, one bare value per address (overrides --json
    /// for stdout).
    #[arg(long, value_enum, value_name = "FIELD")]
    print: Option<PrintField>,
}

#[derive(Args)]
struct TargetArgs {
    /// A token from `new` (`ilp1.…`), `-` to read the token from stdin, or a
    /// bare address for backends that need no state.
    target: String,
    /// The provider, when TARGET is a bare address it cannot be inferred from.
    #[arg(long, short, value_name = "NAME")]
    provider: Option<String>,
}

#[derive(Args)]
struct WaitArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Print the one-time code instead of the message.
    #[arg(long, conflicts_with = "link")]
    otp: bool,
    /// Regex for the code; capture group 1 wins when present.
    #[arg(long, requires = "otp", value_name = "REGEX")]
    pattern: Option<String>,
    /// Print the first link, optionally only one containing this text.
    #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "TEXT")]
    link: Option<String>,
    /// Only mail whose sender contains this (case-insensitive).
    #[arg(long, value_name = "TEXT")]
    from: Option<String>,
    /// Only mail whose subject contains this (case-insensitive).
    #[arg(long, value_name = "TEXT")]
    subject: Option<String>,
    /// Give up after this long (exit 2), e.g. 90s, 5m.
    #[arg(long, short, default_value = "120s", value_parser = parse_duration, value_name = "DURATION")]
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
    /// Providers probed at once.
    #[arg(long, default_value_t = 8, value_name = "N")]
    concurrency: usize,
    /// Only these providers (default: all).
    #[arg(value_name = "PROVIDER")]
    only: Vec<String>,
}

#[derive(Subcommand)]
enum HealthCmd {
    /// Return a quarantined provider to routing.
    Clear {
        /// The provider to clear.
        provider: String,
    },
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

fn parse_kind(s: &str) -> Result<Kind> {
    s.parse::<Kind>().map_err(|_| {
        let names = Kind::ALL.iter().map(|k| k.as_str());
        let mut f = Failure::usage(
            format!("unknown --kind {s:?}"),
            format!("valid kinds: {}", Kind::ALL.map(|k| k.as_str()).join(", ")),
        );
        if let Some(g) = suggest::closest(s, names) {
            f.hint = format!("did you mean {g:?}? {}", f.hint);
            f.did_you_mean = Some(g.into());
        }
        f
    })
}

fn check_provider(il: &Interloper, name: &str) -> Result<()> {
    if il.registry().contains(name) {
        Ok(())
    } else {
        Err(Failure::unknown_provider(name, il.registry().names()))
    }
}

/// Read a token from stdin: the first non-empty line.
fn read_stdin_token() -> Result<String> {
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).map_err(|e| {
        Failure::usage(
            format!("reading TARGET from stdin: {e}"),
            "pipe a token in, e.g. `interloper new --print token | interloper wait - --otp`",
        )
    })?;
    buf.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            Failure::usage(
                "TARGET is `-` but stdin was empty",
                "pipe a token in, e.g. `interloper new --print token | interloper wait - --otp`",
            )
        })
}

/// Resolve a token or bare address to an inbox.
fn open(il: &Interloper, t: &TargetArgs) -> Result<Inbox> {
    let target = if t.target == "-" {
        read_stdin_token()?
    } else {
        t.target.trim().to_string()
    };
    if let Some(p) = &t.provider {
        check_provider(il, p)?;
    }
    if Address::looks_like_token(&target) {
        let address = Address::from_token(&target)?;
        if !il.registry().contains(&address.provider) {
            return Err(
                Failure::unknown_provider(&address.provider, il.registry().names()).with_hint(
                    format!(
                        "the token was issued by {:?}, which this build does not know; run `interloper new` for a fresh address",
                        address.provider
                    ),
                ),
            );
        }
        return Ok(il.resume(address)?);
    }
    if !target.contains('@') {
        return Err(Failure::from(interloper::Error::InvalidToken(format!(
            "{target:?} is neither an ilp1.… token nor an email address"
        ))));
    }
    let provider = match &t.provider {
        Some(p) => p.clone(),
        None => infer_provider(il, &target)?,
    };
    Ok(il.resume(Address::new(target, provider))?)
}

/// A bare address names its provider when exactly one declares its domain.
fn infer_provider(il: &Interloper, address: &str) -> Result<String> {
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
        [] => Err(Failure::usage(
            format!("no provider declares the domain {domain:?}"),
            "pass --provider NAME, or use the token printed by `interloper new`",
        )),
        many => Err(Failure::usage(
            format!("{domain} is served by {}", many.join(", ")),
            format!("pass --provider with one of: {}", many.join(", ")),
        )),
    }
}

/// The static capabilities `new`'s options demand. Each check here is a
/// necessary condition of the pool's own matching, so this never rejects a
/// request the pool would have served; it only answers "impossible" early,
/// and says which option made it so.
struct Constraints<'a> {
    kind: Option<Kind>,
    local: bool,
    domain: Option<&'a str>,
    min_ttl: Option<Duration>,
    solver: bool,
}

impl Constraints<'_> {
    fn violations(&self, s: &ProviderSpec) -> Vec<String> {
        let c = &s.caps;
        let mut v = Vec::new();
        if c.needs_solver && !self.solver {
            v.push("needs INTERLOPER_SOLVER_URL".into());
        }
        if let Some(k) = self.kind
            && !c.serves(k)
        {
            v.push(format!("--kind {k}"));
        }
        if self.local && !c.custom_local {
            v.push("--local".into());
        }
        if let Some(d) = self.domain
            && !c.domains.is_empty()
            && !c.domains.iter().any(|x| x.eq_ignore_ascii_case(d))
        {
            v.push(format!("--domain {d}"));
        }
        if let (Some(need), Some(have)) = (self.min_ttl, c.address_ttl)
            && have < need
        {
            v.push(format!("--min-ttl {}", fmt_ttl(Some(need))));
        }
        v
    }
}

fn providers_where(il: &Interloper, f: impl Fn(&ProviderSpec) -> bool) -> String {
    let names: Vec<&str> = il
        .registry()
        .specs()
        .filter(|s| f(s))
        .map(|s| s.name)
        .collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

/// Fail early, with a useful hint, when no provider could ever satisfy `new`.
fn check_feasible(il: &Interloper, req: &Request) -> Result<()> {
    let c = Constraints {
        kind: req.kind,
        local: req.local.is_some(),
        domain: req.domain.as_deref(),
        min_ttl: req.address_ttl,
        solver: il.registry().solver().is_some(),
    };
    let local_hint = || {
        format!(
            "providers that allow a custom --local: {}",
            providers_where(il, |s| s.caps.custom_local
                && (!s.caps.needs_solver || c.solver))
        )
    };
    if let Some(name) = &req.provider {
        let spec = il
            .registry()
            .specs()
            .find(|s| s.name == name)
            .expect("checked by check_provider");
        let bad = c.violations(spec);
        if bad.is_empty() {
            return Ok(());
        }
        let hint = if c.local && !spec.caps.custom_local {
            local_hint()
        } else {
            format!(
                "providers that satisfy every option: {}",
                providers_where(il, |s| c.violations(s).is_empty())
            )
        };
        return Err(Failure::not_supported(
            format!("{name} cannot serve {}", bad.join(", ")),
            hint,
        ));
    }
    if il.registry().specs().any(|s| c.violations(s).is_empty()) {
        return Ok(());
    }
    let mut asked = Vec::new();
    if let Some(k) = c.kind {
        asked.push(format!("--kind {k}"));
    }
    if c.local {
        asked.push("--local".into());
    }
    if let Some(d) = c.domain {
        asked.push(format!("--domain {d}"));
    }
    if let Some(t) = c.min_ttl {
        asked.push(format!("--min-ttl {}", fmt_ttl(Some(t))));
    }
    let mut hints = Vec::new();
    if c.local {
        hints.push(local_hint());
    }
    if let Some(k) = c.kind {
        hints.push(format!(
            "providers serving {k}: {}",
            providers_where(il, |s| s.caps.serves(k)
                && (!s.caps.needs_solver || c.solver))
        ));
    }
    if hints.is_empty() {
        hints.push("relax the options; `interloper providers --json` shows capabilities".into());
    }
    Err(Failure::not_supported(
        format!("no provider supports {}", asked.join(" with ")),
        hints.join("; "),
    ))
}

/// Make a failure from `new` more actionable using the request it came from.
fn new_hint(il: &Interloper, req: &Request, f: Failure) -> Failure {
    match f.code {
        "no_provider" => {
            let mut hint = failure::no_provider_hint(&f.tried);
            if req.local.is_some()
                || req.kind.is_some()
                || req.domain.is_some()
                || req.address_ttl.is_some()
            {
                hint.push_str("; relaxing --local/--kind/--domain/--min-ttl widens the pool");
            }
            f.with_hint(hint)
        }
        "not_supported" if req.local.is_some() => {
            let others = providers_where(il, |s| s.caps.custom_local);
            let hint = if f.message.contains("local part") {
                format!(
                    "a local part may use A-Z a-z 0-9 . _ + - (1-64 chars); providers that allow a custom --local: {others}"
                )
            } else {
                format!(
                    "choose another --local (or omit it); providers that allow a custom --local: {others}"
                )
            };
            f.with_hint(hint)
        }
        _ => f,
    }
}

async fn cmd_new(il: &Interloper, a: NewArgs, json: bool) -> Result<()> {
    let mut req = Request::new();
    if let Some(p) = &a.provider {
        check_provider(il, p)?;
    }
    req.provider = a.provider;
    req.kind = if a.gmail {
        Some(Kind::GmailAlias)
    } else {
        a.kind.as_deref().map(parse_kind).transpose()?
    };
    req.local = a.local;
    req.domain = a.domain;
    req.domain_not_in = a.not_domain;
    req.address_ttl = a.min_ttl;
    if a.count == 0 {
        return Err(Failure::usage(
            "--count must be at least 1",
            "omit -n for one address",
        ));
    }
    req.options()
        .validate()
        .map_err(|e| new_hint(il, &req, e.into()))?;
    check_feasible(il, &req)?;
    let boxes = if a.count == 1 {
        il.inbox(&req).await.map(|b| vec![b])
    } else {
        il.inboxes(a.count, &req).await
    }
    .map_err(|e| new_hint(il, &req, e.into()))?;
    for b in &boxes {
        let ttl = b.provider().caps().address_ttl;
        let expires = b.address().expires_at.map(|t| t.to_string());
        if let Some(field) = a.print {
            let v = match field {
                PrintField::Address => b.email().to_string(),
                PrintField::Token => b.token(),
                PrintField::Provider => b.provider().name().to_string(),
                PrintField::Expires => expires.unwrap_or_else(|| "never".into()),
            };
            println!("{v}");
        } else if json {
            let line = json!({
                "address": b.email(),
                "provider": b.provider().name(),
                "address_ttl": ttl.map(|d| d.as_secs()),
                "expires_at": expires,
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

fn compile_pattern(p: &str) -> Result<interloper::regex::Regex> {
    interloper::regex::Regex::new(p).map_err(|e| {
        Failure::usage(
            format!("bad --pattern: {e}"),
            "--pattern is a Rust regex; put the code in capture group 1, e.g. 'code: (\\d{6})'",
        )
    })
}

async fn cmd_wait(il: &Interloper, a: WaitArgs, json: bool) -> Result<()> {
    // Before any network: a bad regex must not cost a two-minute wait.
    let pattern = a.pattern.as_deref().map(compile_pattern).transpose()?;
    let inbox = open(il, &a.target)?;
    let filter = MailFilter {
        from: a.from,
        subject: a.subject,
    };
    if a.otp {
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
            let code = interloper::parse::extract_otp(&m.subject, &m.text, None);
            println!("{}", message_json(&m, code.as_deref()));
        } else {
            println!("{}\t{}", m.sender, m.subject);
        }
    }
    Ok(())
}

async fn cmd_watch(il: &Interloper, t: TargetArgs, json: bool) -> Result<()> {
    let inbox = open(il, &t)?;
    let mut stream = inbox.watch(None);
    while let Some(m) = stream.next().await {
        let m = m?;
        if json {
            let code = interloper::parse::extract_otp(&m.subject, &m.text, None);
            println!("{}", message_json(&m, code.as_deref()));
        } else {
            println!("{}\t{}\t{}", m.id, m.sender, m.subject);
        }
        // Each line is a separate event for whoever is reading the pipe.
        let _ = std::io::stdout().flush();
    }
    Ok(())
}

async fn cmd_read(il: &Interloper, a: ReadArgs, json: bool) -> Result<()> {
    let inbox = open(il, &a.target)?;
    match a.id {
        Some(id) => {
            let m = inbox.get(&id).await?;
            if json {
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
                if json {
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

/// Left-aligned columns sized to their widest cell, two spaces apart, so a
/// long value can never run into the next column. The last column is not
/// padded.
fn table(rows: &[Vec<String>]) -> Vec<String> {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|i| {
            rows.iter()
                .filter_map(|r| r.get(i))
                .map(|c| c.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    rows.iter()
        .map(|r| {
            let mut line = String::new();
            for (i, cell) in r.iter().enumerate() {
                if i + 1 == r.len() {
                    line.push_str(cell);
                } else {
                    let pad = widths[i] - cell.chars().count() + 2;
                    line.push_str(cell);
                    line.extend(std::iter::repeat_n(' ', pad));
                }
            }
            line
        })
        .collect()
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
    let mut cells = vec![
        ["PROVIDER", "STATUS", "P50", "TTL", "KIND", "SITES"]
            .map(String::from)
            .to_vec(),
    ];
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
        cells.push(vec![
            s.name.to_string(),
            status,
            p50,
            fmt_ttl(s.caps.address_ttl),
            kinds,
            s.caps.sites.join(","),
        ]);
    }
    for line in table(&cells) {
        println!("{line}");
    }
}

fn cmd_health(il: &Interloper, cmd: HealthCmd, json: bool) -> Result<()> {
    match cmd {
        HealthCmd::Clear { provider } => {
            check_provider(il, &provider)?;
            let was = il.health().unquarantine(&provider);
            if json {
                println!("{}", json!({"provider": provider, "cleared": was}));
            } else {
                println!(
                    "{provider}: {}",
                    if was {
                        "cleared"
                    } else {
                        "was not quarantined"
                    }
                );
            }
        }
        HealthCmd::Show => {
            let snap = il.health().snapshot();
            let sorted: std::collections::BTreeMap<_, _> = snap.into_iter().collect();
            println!("{}", serde_json::to_string_pretty(&sorted).unwrap());
        }
    }
    Ok(())
}

async fn cmd_serve(a: ServeArgs) -> Result<ExitCode> {
    let mut config = interloper_server::config::Config::from_env().map_err(Failure::config)?;
    if let Some(b) = a.bind {
        config.bind = b;
    }
    let il = Interloper::from_env()?;
    interloper_server::serve(config, il)
        .await
        .map_err(|e| Failure::internal(format!("server: {e}")))?;
    Ok(ExitCode::SUCCESS)
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let json = cli.json;
    match cli.command {
        Command::Serve(a) => return cmd_serve(a).await,
        Command::Guide => {
            let cmd = Cli::command();
            if json {
                let v = docs::guide_json(&cmd);
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                print!("{}", docs::guide_text(&cmd));
            }
            return Ok(ExitCode::SUCCESS);
        }
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "interloper", &mut std::io::stdout());
            return Ok(ExitCode::SUCCESS);
        }
        Command::Man => {
            match clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout()) {
                // `interloper man | head` is not a failure.
                Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                    return Err(Failure::internal(format!("writing the man page: {e}")));
                }
                _ => {}
            }
            return Ok(ExitCode::SUCCESS);
        }
        _ => {}
    }
    let il = Arc::new(Interloper::from_env()?);
    let ok = |r: Result<()>| r.map(|_| ExitCode::SUCCESS);
    let result = match cli.command {
        Command::New(a) => ok(cmd_new(&il, a, json).await),
        Command::Wait(a) => ok(cmd_wait(&il, a, json).await),
        Command::Watch(t) => ok(cmd_watch(&il, t, json).await),
        Command::Read(a) => ok(cmd_read(&il, a, json).await),
        Command::Providers => {
            cmd_providers(&il, json);
            Ok(ExitCode::SUCCESS)
        }
        Command::Canary(a) => match a.only.iter().find(|n| !il.registry().contains(n)) {
            Some(bad) => Err(Failure::unknown_provider(bad, il.registry().names())),
            None => canary::run(&il, a.only, a.concurrency, json)
                .await
                .map_err(Failure::from),
        },
        Command::Health(h) => ok(cmd_health(&il, h, json)),
        Command::Serve(_) | Command::Guide | Command::Completions { .. } | Command::Man => {
            unreachable!("handled above")
        }
    };
    // A read-only or full disk must not fail the user's command.
    if let Err(e) = il.save_health() {
        if json {
            eprintln!(
                "{}",
                json!({"warning": {"code": "health_not_saved", "message": e.to_string()}})
            );
        } else {
            eprintln!("warning: could not save provider health: {e}");
        }
    }
    result
}

/// Whether --json is in effect, judged from raw input. Used only when clap
/// itself rejects the command line, so the rejection can still be JSON.
fn json_requested(args: &[std::ffi::OsString], env: Option<&str>) -> bool {
    let flag = args
        .iter()
        .skip(1)
        .take_while(|a| *a != "--")
        .any(|a| a == "--json");
    let env = env.is_some_and(|v| {
        !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off" | "n" | "f"
        )
    });
    flag || env
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(e) if !e.use_stderr() => {
            // --help or --version.
            let _ = e.print();
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            let env = std::env::var("INTERLOPER_JSON").ok();
            if json_requested(&args, env.as_deref()) {
                failure::report(&Failure::from_clap(&e), true);
            } else {
                let _ = e.print();
            }
            return ExitCode::from(failure::EXIT_USAGE);
        }
    };
    let level = match cli.verbose {
        0 if matches!(cli.command, Command::Serve(_)) => "interloper=info,interloper_server=info",
        // JSON mode keeps stderr to the one error object unless asked.
        0 if cli.json => "off",
        0 => "warn",
        1 => "interloper=debug,interloper_server=debug",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_env("INTERLOPER_LOG")
        .unwrap_or_else(|_| level.into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
    let json = cli.json;
    match run(cli).await {
        Ok(code) => code,
        Err(f) => {
            failure::report(&f, json);
            ExitCode::from(f.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("interloper").chain(args.iter().copied()))
    }

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
        Cli::command().debug_assert();
    }

    #[test]
    fn every_flag_is_described() {
        fn walk(cmd: &clap::Command, path: &str) {
            for a in cmd.get_arguments() {
                if matches!(a.get_id().as_str(), "help" | "version") {
                    continue;
                }
                assert!(
                    a.get_help().is_some() || a.get_long_help().is_some(),
                    "{path} {} has no description",
                    a.get_id()
                );
            }
            for sub in cmd.get_subcommands() {
                walk(sub, &format!("{path} {}", sub.get_name()));
            }
        }
        let mut cmd = Cli::command();
        cmd.build();
        walk(&cmd, "interloper");
    }

    #[test]
    fn every_subcommand_has_examples_and_json_shape() {
        for sub in Cli::command().get_subcommands() {
            let d = docs::subdoc(sub.get_name());
            assert!(!d.examples.is_empty() && !d.json.is_empty());
            assert!(
                d.examples
                    .contains(&format!("interloper {}", sub.get_name()))
            );
        }
    }

    #[test]
    fn json_is_global_and_env_driven() {
        assert!(parse(&["providers", "--json"]).unwrap().json);
        assert!(parse(&["--json", "providers"]).unwrap().json);
        let args: Vec<std::ffi::OsString> =
            ["interloper", "new", "--json"].map(Into::into).to_vec();
        assert!(json_requested(&args, None));
        let args: Vec<std::ffi::OsString> = ["interloper", "wait", "--", "--json"]
            .map(Into::into)
            .to_vec();
        assert!(!json_requested(&args, None));
        assert!(json_requested(&args, Some("1")));
        assert!(!json_requested(&args, Some("0")));
        assert!(!json_requested(&args, Some("false")));
    }

    #[test]
    fn print_field_parses() {
        let cli = parse(&["new", "--print", "token"]).unwrap();
        let Command::New(a) = cli.command else {
            panic!()
        };
        assert!(a.print == Some(PrintField::Token));
        let e = parse(&["new", "--print", "tokn"]).err().unwrap();
        let f = Failure::from_clap(&e);
        assert_eq!(f.code, "usage");
        assert_eq!(f.exit_code(), failure::EXIT_USAGE);
        assert_eq!(f.did_you_mean.as_deref(), Some("token"));
    }

    #[test]
    fn clap_errors_become_usage_failures() {
        let e = parse(&["wiat"]).err().unwrap();
        let f = Failure::from_clap(&e);
        assert_eq!(f.code, "usage");
        assert_eq!(f.did_you_mean.as_deref(), Some("wait"));
        assert!(!f.message.starts_with("error:"), "{}", f.message);
    }

    #[test]
    fn kinds_suggest() {
        let f = parse_kind("gmial").err().unwrap();
        assert_eq!(f.code, "usage");
        assert_eq!(f.did_you_mean.as_deref(), Some("gmail-alias"));
        assert!(parse_kind("edu").is_ok());
        for k in Kind::ALL {
            assert!(docs::kind_help().contains(k.as_str()));
        }
    }

    #[test]
    fn bad_pattern_is_usage() {
        let f = compile_pattern("(").err().unwrap();
        assert_eq!(f.code, "usage");
        assert!(compile_pattern(r"code: (\d+)").is_ok());
    }

    #[test]
    fn guide_covers_every_subcommand_and_code() {
        let cmd = Cli::command();
        let text = docs::guide_text(&cmd);
        for sub in cmd.get_subcommands() {
            assert!(
                text.contains(&format!("interloper {}", sub.get_name())),
                "guide misses {}",
                sub.get_name()
            );
        }
        for c in failure::ERROR_CODES {
            assert!(text.contains(c.code), "guide misses {}", c.code);
        }
        for e in failure::tests::core_samples() {
            assert!(text.contains(e.code()), "guide misses {}", e.code());
        }
        for x in failure::EXIT_CODES {
            assert!(text.contains(&format!("  {}  {}", x.code, x.name)));
        }
        for p in interloper::providers::all() {
            assert!(text.contains(p.name), "guide misses provider {}", p.name);
        }
        for v in docs::ENV_VARS {
            assert!(text.contains(v.name));
        }
        for (v, _) in interloper_server::config::ENV {
            assert!(text.contains(v), "guide misses server setting {v}");
        }
        let json = docs::guide_json(&cmd);
        assert_eq!(
            json["commands"].as_array().unwrap().len(),
            cmd.get_subcommands().count()
        );
        assert_eq!(
            json["error_codes"].as_array().unwrap().len(),
            failure::ERROR_CODES.len()
        );
    }

    #[test]
    fn help_documents_exit_codes_and_workflow() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("wait \"$TOKEN\" --otp"));
        assert!(help.contains("ilp1."));
        for x in failure::EXIT_CODES {
            assert!(help.contains(x.name), "help misses exit {}", x.name);
        }
        // The workflow leads: it comes before the usage line.
        assert!(help.find("interloper new").unwrap() < help.find("Usage:").unwrap());
    }

    #[test]
    fn table_columns_never_touch() {
        let rows = vec![
            vec!["PROVIDER".into(), "KIND".into(), "SITES".into()],
            vec![
                "22do".into(),
                "gmail-alias,outlook-alias,own-domain".into(),
                "22.do".into(),
            ],
            vec!["a".into(), "edu".into(), "x".into()],
        ];
        let lines = table(&rows);
        assert_eq!(
            lines[1],
            "22do      gmail-alias,outlook-alias,own-domain  22.do"
        );
        let col = lines[0].find("SITES").unwrap();
        for l in &lines {
            assert_eq!(&l[col - 2..col], "  ", "{l}");
        }
    }

    #[test]
    fn man_and_completions_render() {
        let mut out = Vec::new();
        clap_mangen::Man::new(Cli::command())
            .render(&mut out)
            .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("interloper"));
        let mut out = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut Cli::command(),
            "interloper",
            &mut out,
        );
        assert!(String::from_utf8(out).unwrap().contains("wait"));
    }
}
