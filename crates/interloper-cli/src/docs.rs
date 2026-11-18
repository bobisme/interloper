//! Help text and the `guide` manual. Tables (commands and their flags, exit
//! codes, error codes, kinds, providers) are generated from the code they
//! describe; prose is written once here and shared by `--help` and `guide`.

use std::fmt::Write as _;

use clap::Command;
use interloper::Kind;
use serde_json::{Value, json};

use crate::failure::{ERROR_CODES, EXIT_CODES};

pub const ABOUT: &str = "Disposable inboxes from every backend, behind one interface.";

pub const WORKFLOW: &str = "\
Sign up somewhere with a throwaway address and read the one-time code:

  1. interloper new --json
       {\"address\":\"x7f2@mail.tm\",\"provider\":\"mailtm\",...,\"token\":\"ilp1.eyJ...\"}
     Keep the token. Type the address into the signup form.
  2. interloper wait \"$TOKEN\" --otp --timeout 180s --json
       {\"otp\":\"482913\"}
  3. Exit 2 means nothing arrived in time: resubmit the form, then wait again
     with the same token. For a verification link instead of a code, use
     `wait \"$TOKEN\" --link verify`.

Shell one-liner (plain `new` prints ADDRESS<TAB>PROVIDER<TAB>TTL<TAB>TOKEN):
  IFS=$'\\t' read -r ADDRESS _ _ TOKEN < <(interloper new)";

pub const TOKENS: &str = "\
A token (`ilp1.…`) is a portable handle that carries the address, its provider,
its expiry and the provider's session state. Keep it and pass it as TARGET to
wait, read and watch, from any process or machine; nothing else is needed to
resume the inbox. It holds credentials: treat it as a secret. TARGET `-` reads
the token from stdin. A bare address also works for providers that need no
state (the provider is inferred from the domain, or given with --provider).";

pub const OUTPUT: &str = "\
stdout carries only results. With --json (or INTERLOPER_JSON=1) every result is
JSON: one object per line unless the command says otherwise. On failure stdout
is empty (watch may already have printed earlier messages) and stderr ends
with exactly one line {\"error\":{\"code\",\"retryable\",\"message\",\"hint\",...}}.
Optional error fields: retry_after_seconds, tried, did_you_mean. Without --json
the failure is `error[CODE]: MESSAGE` and a `hint:` line on stderr.
Retry only when `retryable` is true; honor retry_after_seconds when present.";

pub struct SubDoc {
    pub name: &'static str,
    pub examples: &'static str,
    pub json: &'static str,
}

const MESSAGE_SHAPE: &str = "{\"id\":str,\"sender\":str,\"subject\":str,\"received_at\":RFC3339|null,\"text\":str,\"links\":[str],\"otp\":str|null}";

pub const SUBDOCS: &[SubDoc] = &[
    SubDoc {
        name: "new",
        examples: "  interloper new --json
  interloper new --print token > token.txt
  interloper new --kind gmail-alias --min-ttl 1h -n 3",
        json: "One line per address:
  {\"address\":str,\"provider\":str,\"address_ttl\":seconds|null,\"expires_at\":RFC3339|null,\"token\":str}
  address_ttl null means the address does not expire. --print FIELD prints one
  bare value per line instead (and takes precedence over --json for stdout).",
    },
    SubDoc {
        name: "wait",
        examples: "  interloper wait \"$TOKEN\" --otp --from github.com --json
  interloper wait \"$TOKEN\" --link verify --timeout 5m
  interloper new --print token | interloper wait - --otp --pattern 'code: (\\d+)'",
        json: "--otp: {\"otp\":str}   --link: {\"link\":str}   otherwise the message:
  {MESSAGE}
  Exit 2 (code timeout) when nothing matched in time.",
    },
    SubDoc {
        name: "watch",
        examples: "  interloper watch \"$TOKEN\" --json
  interloper watch someone@guerrillamail.com --provider guerrillamail",
        json: "One line per message as it arrives (runs until interrupted):
  {MESSAGE}",
    },
    SubDoc {
        name: "read",
        examples: "  interloper read \"$TOKEN\" --json
  interloper read \"$TOKEN\" MESSAGE_ID --json",
        json: "Without ID, one line per message (no lines: empty inbox):
  {\"id\":str,\"sender\":str,\"subject\":str,\"received_at\":RFC3339|null,\"locked\":bool}
  With ID: {MESSAGE}",
    },
    SubDoc {
        name: "providers",
        examples: "  interloper providers
  interloper providers --json",
        json: "One pretty-printed array:
  [{\"provider\":str,\"status\":\"ok|slow|down|quarantined|probation|no-solver\",\"p50\":seconds|null,
    \"kind\":[str],\"sites\":[str],\"address_ttl\":seconds|null,\"custom_local\":bool,
    \"needs_solver\":bool,\"last_failure\":str|null}]",
    },
    SubDoc {
        name: "canary",
        examples: "  interloper canary --json
  interloper canary mailtm guerrillamail",
        json: "One pretty-printed object keyed by provider:
  {\"mailtm\":{\"status\":\"ok|down|error|quarantined|skipped\",\"seconds\":float,\"detail\":str|null}}
  Exits 1 only when a provider shows schema drift.",
    },
    SubDoc {
        name: "health",
        examples: "  interloper health show
  interloper health clear mailtm --json",
        json: "show: the raw health store as one object keyed by provider.
  clear: {\"provider\":str,\"cleared\":bool}",
    },
    SubDoc {
        name: "serve",
        examples: "  INTERLOPER_API_KEYS=secret interloper serve --bind 127.0.0.1:8080",
        json: "Not applicable (runs the HTTP API until stopped).",
    },
    SubDoc {
        name: "guide",
        examples: "  interloper guide
  interloper guide --json",
        json: "One pretty-printed object: workflow, tokens, output, commands (with flags and\n  output shapes), exit_codes, error_codes, env, kinds, providers.",
    },
    SubDoc {
        name: "completions",
        examples: "  interloper completions bash > ~/.local/share/bash-completion/completions/interloper
  interloper completions fish > ~/.config/fish/completions/interloper.fish
  interloper completions zsh > \"${fpath[1]}/_interloper\"",
        json: "Not applicable (prints a completion script).",
    },
    SubDoc {
        name: "man",
        examples: "  interloper man > interloper.1 && man ./interloper.1",
        json: "Not applicable (prints roff).",
    },
];

pub fn subdoc(name: &str) -> &'static SubDoc {
    SUBDOCS
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no SubDoc for {name}"))
}

fn json_shape(d: &SubDoc) -> String {
    d.json.replace("{MESSAGE}", MESSAGE_SHAPE)
}

/// `after_help` for one subcommand.
pub fn sub_help(name: &str) -> String {
    let d = subdoc(name);
    format!(
        "Examples:\n{}\n\nOutput with --json:\n  {}\n\n{}",
        d.examples,
        json_shape(d),
        exit_line()
    )
}

fn exit_line() -> String {
    let codes: Vec<String> = EXIT_CODES
        .iter()
        .map(|e| format!("{} {}", e.code, e.name))
        .collect();
    format!(
        "Exit codes: {}. Details: `interloper guide`.",
        codes.join(", ")
    )
}

pub fn top_long_about() -> String {
    format!("{ABOUT}\n\n{WORKFLOW}")
}

pub fn top_after_help() -> String {
    let mut s = format!("Tokens:\n{}\n\nExit codes:\n", indent(TOKENS));
    for e in EXIT_CODES {
        let _ = writeln!(s, "  {}  {:<12}{}", e.code, e.name, e.meaning);
    }
    s.push_str("\nRun `interloper guide` for the full agent manual (or `guide --json`).");
    s
}

pub fn kind_help() -> String {
    let kinds: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
    format!("Kind of address: {}.", kinds.join(", "))
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("  {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct EnvVar {
    pub name: &'static str,
    pub meaning: &'static str,
}

pub const ENV_VARS: &[EnvVar] = &[
    EnvVar {
        name: "INTERLOPER_JSON",
        meaning: "1/true turns on --json for every command (0/false/off leaves it off).",
    },
    EnvVar {
        name: "INTERLOPER_PROXY",
        meaning: "Egress proxy URL for every provider and the solver.",
    },
    EnvVar {
        name: "INTERLOPER_SOLVER_URL",
        meaning: "A cloudflare-solver; solver-only providers join the pool when set.",
    },
    EnvVar {
        name: "INTERLOPER_HEALTH_PATH",
        meaning: "Health cache file (default $XDG_STATE_HOME/interloper/health.json).",
    },
    EnvVar {
        name: "INTERLOPER_LOG",
        meaning: "Tracing filter for stderr logs, e.g. interloper=debug.",
    },
];

fn subcommands(cmd: &Command) -> impl Iterator<Item = &Command> {
    cmd.get_subcommands().filter(|c| c.get_name() != "help")
}

fn flag_label(a: &clap::Arg) -> String {
    let mut s = String::new();
    if let Some(long) = a.get_long() {
        s.push_str("--");
        s.push_str(long);
        if a.get_action().takes_values() {
            let v = a
                .get_value_names()
                .and_then(|v| v.first())
                .map_or_else(|| a.get_id().as_str().to_uppercase(), |v| v.to_string());
            s.push_str(&format!(" {v}"));
        }
    } else {
        let v = a
            .get_value_names()
            .and_then(|v| v.first())
            .map_or_else(|| a.get_id().as_str().to_uppercase(), |v| v.to_string());
        s.push_str(&v);
    }
    if let Some(short) = a.get_short() {
        s.push_str(&format!(" (-{short})"));
    }
    s
}

fn args_of(cmd: &Command) -> Vec<&clap::Arg> {
    cmd.get_arguments()
        .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .collect()
}

fn usage(cmd: &mut Command) -> String {
    cmd.render_usage()
        .to_string()
        .trim_start_matches("Usage: ")
        .to_string()
}

fn sorted_specs() -> Vec<interloper::ProviderSpec> {
    let mut specs = interloper::providers::all();
    specs.sort_by_key(|s| s.name);
    specs
}

fn providers_table() -> Vec<(String, String)> {
    sorted_specs()
        .iter()
        .map(|s| {
            let kinds: Vec<&str> = s.caps.kind.iter().map(|k| k.as_str()).collect();
            let mut notes = vec![kinds.join(",")];
            if s.caps.custom_local {
                notes.push("custom-local".into());
            }
            if s.caps.needs_solver {
                notes.push("needs-solver".into());
            }
            notes.push(match s.caps.address_ttl {
                Some(d) => format!("ttl {}", crate::fmt_ttl(Some(d))),
                None => "no expiry".into(),
            });
            (s.name.to_string(), notes.join("; "))
        })
        .collect()
}

/// The manual printed by `interloper guide`.
pub fn guide_text(root: &Command) -> String {
    let mut root = root.clone();
    root.build();
    let mut s = String::new();
    let _ = writeln!(
        s,
        "INTERLOPER AGENT GUIDE (v{})\n{ABOUT}\n",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(s, "WORKFLOW\n{}\n", indent(WORKFLOW));
    let _ = writeln!(s, "TOKENS\n{}\n", indent(TOKENS));
    let _ = writeln!(s, "OUTPUT CONTRACT\n{}\n", indent(OUTPUT));
    let _ = writeln!(
        s,
        "GLOBAL FLAGS\n  --json        JSON output and JSON errors (env INTERLOPER_JSON=1)\n  -v, --verbose log routing decisions to stderr (repeat for more)\n"
    );
    s.push_str("COMMANDS\n");
    let names: Vec<String> = subcommands(&root)
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("listed");
        let about = sub.get_about().map(|a| a.to_string()).unwrap_or_default();
        let _ = writeln!(s, "\n  interloper {name} — {about}");
        let _ = writeln!(s, "    usage: {}", usage(sub));
        for a in args_of(sub) {
            let help = a.get_help().map(|h| h.to_string()).unwrap_or_default();
            let _ = writeln!(s, "      {:<24} {help}", flag_label(a));
        }
        let nested: Vec<(String, String)> = subcommands(sub)
            .map(|c| {
                (
                    c.get_name().to_string(),
                    c.get_about().map(|a| a.to_string()).unwrap_or_default(),
                )
            })
            .collect();
        for (n, about) in nested {
            let _ = writeln!(s, "      {name} {n:<17} {about}");
        }
        let d = subdoc(&name);
        let _ = writeln!(s, "    examples:\n{}", indent(&indent(d.examples)));
        let _ = writeln!(
            s,
            "    --json output:\n      {}",
            json_shape(d).replace('\n', "\n    ")
        );
    }
    s.push_str("\nEXIT CODES\n");
    for e in EXIT_CODES {
        let _ = writeln!(s, "  {}  {:<12}{}", e.code, e.name, e.meaning);
    }
    s.push_str("\nERROR CODES (JSON error.code; retry = whether retrying unchanged can work)\n");
    let _ = writeln!(s, "  {:<20}{:<6}{:<9}MEANING", "CODE", "EXIT", "RETRY");
    for c in ERROR_CODES {
        let _ = writeln!(
            s,
            "  {:<20}{:<6}{:<9}{}",
            c.code,
            c.exit,
            c.retry.as_str(),
            c.meaning
        );
    }
    s.push_str("\nENVIRONMENT\n");
    for e in ENV_VARS {
        let _ = writeln!(s, "  {}\n      {}", e.name, e.meaning);
    }
    s.push_str("\nSERVER ENVIRONMENT (`interloper serve`)\n");
    for (name, meaning) in interloper_server::config::ENV {
        let _ = writeln!(s, "  {name}\n      {meaning}");
    }
    let kinds: Vec<&str> = Kind::ALL.iter().map(|k| k.as_str()).collect();
    let _ = writeln!(s, "\nKINDS (--kind)\n  {}", kinds.join(", "));
    s.push_str("\nPROVIDERS (built in; live health: `interloper providers`)\n");
    for (name, notes) in providers_table() {
        let _ = writeln!(s, "  {name:<18}{notes}");
    }
    s
}

/// The same manual as structured data, for `guide --json`.
pub fn guide_json(root: &Command) -> Value {
    let mut root = root.clone();
    root.build();
    let names: Vec<String> = subcommands(&root)
        .map(|c| c.get_name().to_string())
        .collect();
    let commands: Vec<Value> = names
        .iter()
        .map(|name| {
            let sub = root.find_subcommand_mut(name).expect("listed");
            let args: Vec<Value> = args_of(sub)
                .iter()
                .map(|a| {
                    json!({
                        "name": a.get_id().as_str(),
                        "long": a.get_long(),
                        "short": a.get_short().map(|c| c.to_string()),
                        "positional": a.is_positional(),
                        "takes_value": a.get_action().takes_values(),
                        "required": a.is_required_set(),
                        "help": a.get_help().map(|h| h.to_string()),
                    })
                })
                .collect();
            let nested: Vec<String> = subcommands(sub).map(|c| c.get_name().to_string()).collect();
            let d = subdoc(name);
            let usage = usage(sub);
            json!({
                "name": name,
                "about": sub.get_about().map(|a| a.to_string()),
                "usage": usage,
                "args": args,
                "subcommands": nested,
                "examples": d.examples.lines().map(str::trim).collect::<Vec<_>>(),
                "json_output": json_shape(d),
            })
        })
        .collect();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "about": ABOUT,
        "workflow": WORKFLOW,
        "tokens": TOKENS,
        "output": OUTPUT,
        "error_shape": {"error": {"code": "str", "retryable": "bool", "message": "str", "hint": "str",
            "retry_after_seconds": "number (optional)", "tried": "[str] (optional)", "did_you_mean": "str (optional)"}},
        "commands": commands,
        "exit_codes": EXIT_CODES.iter().map(|e| json!({"code": e.code, "name": e.name, "meaning": e.meaning})).collect::<Vec<_>>(),
        "error_codes": ERROR_CODES.iter().map(|c| json!({"code": c.code, "exit": c.exit, "retry": c.retry.as_str(), "meaning": c.meaning})).collect::<Vec<_>>(),
        "env": ENV_VARS.iter().map(|e| json!({"name": e.name, "meaning": e.meaning})).collect::<Vec<_>>(),
        "server_env": interloper_server::config::ENV.iter().map(|(n, m)| json!({"name": n, "meaning": m})).collect::<Vec<_>>(),
        "kinds": Kind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        "providers": sorted_specs().iter().map(|s| json!({
            "name": s.name,
            "kind": s.caps.kind.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            "custom_local": s.caps.custom_local,
            "needs_solver": s.caps.needs_solver,
            "address_ttl": s.caps.address_ttl.map(|d| d.as_secs()),
        })).collect::<Vec<_>>(),
    })
}
