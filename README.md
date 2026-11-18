# interloper

Disposable-email backends behind one interface: generate an address, wait for
a message, extract an OTP or a link, done. A Rust rewrite of
[cowbird](../../repos/cowbird). Like its namesake it owns no mail
infrastructure and uses everyone else's.

## CLI

```
$ interloper new
il3f09a1c2e4@euploading.com	mailtm	forever	ilp1.eyJ2YWx1ZSI6…

$ interloper wait "$TOKEN" --otp --from github.com
482913

$ interloper wait "$TOKEN" --link verify
https://example.test/verify?t=…

$ interloper providers
PROVIDER        STATUS       P50      TTL      KIND        SITES
guerrillamail   ok           1.3s     1h       own-domain  guerrillamail.com,…
mailtm          ok           0.5s     forever  own-domain  mail.tm
```

`new` prints a **token** (`ilp1.…`): address, provider, expiry and the
provider's credentials in one copy-pasteable value. `wait`, `watch` and `read`
take it, so a second process resumes the inbox with one argument instead of
cowbird's `ADDRESS --provider P --state S`. It holds credentials; treat it as
a secret. A bare address works too for providers that need no state, and the
provider is inferred from the domain.

| command | |
|---|---|
| `new [-p P] [--kind K\|--gmail] [--local L] [--domain D] [--not-domain D]… [--min-ttl 2h] [-n N] [--json]` | acquire address(es) |
| `wait TARGET [--otp [--pattern RE]\|--link [TEXT]] [--from S] [--subject S] [-t 120s] [--json]` | first matching mail |
| `watch TARGET [--json]` | stream mail as it arrives |
| `read TARGET [ID] [--json]` | list, or show one message |
| `providers [--json]` | measured health matrix |
| `canary [--json] [PROVIDER…]` | live probe, concurrent; exits 1 only on schema drift |
| `health clear P` / `health show` | clear a quarantine / dump health |

Exit codes: 0 ok, 1 error, 2 timeout.

## Library

```rust
let il = interloper::Interloper::from_env()?;
let inbox = il.inbox(&Request::new().kind(Kind::GmailAlias)).await?;
println!("{}", inbox.email());
let code = inbox.otp(Duration::from_secs(120)).await?;
```

## What is better than cowbird

- **Providers recover.** A DOWN provider is a circuit breaker with a
  half-open probe (30s cooldown, doubling, capped at 15 min) instead of being
  out of routing for the life of the process.
- **Hedged acquire.** If the best provider hasn't answered within about twice
  its own p50, the next one starts in parallel, and the first address back
  wins.
- **Watches ride out blips.** One 502 during a two-minute `otp()` wait no
  longer throws the wait away; five consecutive transient failures do.
- **OTP extraction is scored**, not first-six-digits: announced codes beat
  order numbers, years, phone numbers, dates; `123 456` joins; announced
  alphanumeric codes count; the subject is searched too.
- **Errors are an exhaustive enum.** Whether an error reroutes or counts
  against health is a `match` with no wildcard, so a new error kind cannot
  silently opt out.
- **Drift says where.** `J` JSON accessors report the provider, the JSON path
  and what was found: `expected key "id" at messages[3]`.
- **Fixtures replace only the wire**, so retry, 429, 5xx and challenge logic
  run under test exactly as in production.
- **Concurrent CLI processes merge health** instead of overwriting each other.
- One static binary with a real Chrome TLS/HTTP2 fingerprint (BoringSSL via
  `wreq`). No Python, no curl_cffi.

## Configuration

| env | |
|---|---|
| `INTERLOPER_PROXY` | egress proxy for every provider (and the solver) |
| `INTERLOPER_SOLVER_URL` | a [cloudflare-solver](https://github.com/B00H0O/cloudflare-solver); solver-only providers join the pool when set |
| `INTERLOPER_HEALTH_PATH` | health cache (default `$XDG_STATE_HOME/interloper/health.json`) |
| `INTERLOPER_LOG` | tracing filter, e.g. `interloper=debug` |

`COWBIRD_*` equivalents are accepted.

## Testing

```bash
cargo test                                   # offline, the default gate
INTERLOPER_DELIVERY=mailtm cargo test -p interloper --features live \
  --test delivery -- --nocapture             # real mail, rationed sender
```

Every adapter runs the shared contract suite (`contract_tests!`) against
recorded fixtures. Porting guide: [docs/PORTING.md](docs/PORTING.md).
