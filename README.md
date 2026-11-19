# interloper

![A dark songbird perched on a row of nest-shaped mailboxes; one holds an envelope like a speckled egg](docs/banner.webp)

Disposable-email backends behind one interface: generate an address, wait for
a message, extract an OTP or a link, done. 32 providers, one CLI, one HTTP
API, built for scripts and AI agents.

A Rust rewrite of [cowbird](https://github.com/Pranjal-SB/cowbird). Like its
namesake it owns no mail infrastructure and uses everyone else's.

## CLI

```
$ interloper new
il3f09a1c2e4@euploading.com	mailtm	forever	ilp1.eyJ2YWx1ZSI6…

$ interloper wait "$TOKEN" --otp --from github.com
482913

$ interloper wait "$TOKEN" --link verify
https://example.test/verify?t=…

$ interloper providers
PROVIDER       STATUS  P50   TTL      KIND        SITES
guerrillamail  ok      1.3s  1h       own-domain  guerrillamail.com,…
mailtm         ok      0.5s  forever  own-domain  mail.tm
```

`new` prints a **token** (`ilp1.…`): a portable handle that carries the
address, provider, expiry and the provider's session state in one
copy-pasteable value. `wait`, `watch` and `read` take it as TARGET, so a second
process resumes the inbox with one argument instead of cowbird's
`ADDRESS --provider P --state S`. It holds credentials; treat it as a secret.
TARGET `-` reads the token from stdin. A bare address works too for providers
that need no state, and the provider is inferred from the domain.

| command | |
|---|---|
| `new [-p P] [--kind K\|--gmail] [--local L] [--domain D] [--not-domain D]… [--min-ttl 2h] [-n N] [--print address\|token\|provider\|expires]` | acquire address(es) |
| `wait TARGET [--otp [--pattern RE]\|--link [TEXT]] [--from S] [--subject S] [-t 120s]` | first matching mail |
| `watch TARGET` | stream mail as it arrives |
| `read TARGET [ID]` | list, or show one message |
| `providers` | measured health matrix |
| `canary [--concurrency N] [PROVIDER…]` | live probe, concurrent; exits 1 only on schema drift |
| `health clear P` / `health show` | clear a quarantine / dump health |
| `guide` | the agent manual: workflow, JSON shapes, exit and error codes (`--json` for structured) |
| `completions SHELL` / `man` | shell completions (bash, zsh, fish, …) / roff man page |

Every command takes `--json` (or set `INTERLOPER_JSON=1`). Results are then
JSON on stdout, one object per line. On failure stdout is empty and stderr
ends with one line:

```json
{"error":{"code":"rate_limited","retryable":true,"message":"…","hint":"…","retry_after_seconds":30}}
```

`code` is stable (`provider_down`, `challenge`, `solver_unavailable`,
`rate_limited`, `schema_drift`, `message_locked`, `message_gone`,
`not_supported`, `address_expired`, `no_provider`, `timeout`, `invalid_token`,
`usage`, `unknown_provider`, `config`, `internal`). Retry only when
`retryable` is true. Misspelled providers and kinds get a `did_you_mean`.

| exit | meaning |
|---|---|
| 0 | ok |
| 1 | anything else, including schema drift |
| 2 | timeout: nothing arrived; retry, maybe with a longer `--timeout` |
| 3 | usage: bad flag, unknown provider or kind, bad `--pattern`, unsupported option combination; fix the command |
| 4 | unavailable: provider down, rate limited, challenged, no provider available; usually retryable |
| 5 | address expired or invalid token; run `new` again |
| 6 | message gone or locked |

`interloper guide` prints these tables from the code itself, plus every
command's flags and JSON output shape, so it cannot drift.

## Library

```rust
let il = interloper::Interloper::from_env()?;
let inbox = il.inbox(&Request::new().kind(Kind::GmailAlias)).await?;
println!("{}", inbox.email());
let code = inbox.otp(Duration::from_secs(120)).await?;
```

## Server

`interloper serve` runs the HTTP API (`crates/interloper-server`): issue
inboxes, list and read mail, long-poll `wait`, Server-Sent Events, one-shot
webhooks, and the provider health matrix. Every response is
`{"success", "data", "error"}`; auth is `X-API-Key`. Provider state stays on
the server, so clients only ever handle the address.

```bash
INTERLOPER_API_KEYS=secret interloper serve --bind 127.0.0.1:8080
curl -s -H 'X-API-Key: secret' -X POST localhost:8080/v1/inboxes
curl -s -H 'X-API-Key: secret' 'localhost:8080/v1/inboxes/ADDR/wait?otp=true'
```

| env | |
|---|---|
| `INTERLOPER_API_KEYS` | comma-separated; the server refuses to start without one |
| `INTERLOPER_BIND` | listen address (default `127.0.0.1:8080`) |
| `INTERLOPER_DATABASE` | SQLite file for issued addresses (default: memory) |
| `INTERLOPER_DATABASE_URL` | Postgres URL: turns on fleet mode (below); not with `INTERLOPER_DATABASE` |
| `INTERLOPER_INSTANCE_ID` | this instance's name in fleet mode (default `$HOSTNAME`); unique per instance |
| `INTERLOPER_HEALTH_SYNC_SECONDS` | fleet health sync interval (default 5) |
| `INTERLOPER_RATE_LIMIT` | per key and IP, e.g. `30/minute` |
| `INTERLOPER_WAIT_MAX`, `INTERLOPER_WAIT_DEFAULT`, `INTERLOPER_WEBHOOK_MAX` | seconds |
| `INTERLOPER_WEBHOOK_SECRET`, `INTERLOPER_WEBHOOK_ALLOW_PRIVATE` | webhook signing; SSRF guard off (local only) |
| `INTERLOPER_ALLOWED_ORIGINS` | CORS allow-list |

### Fleet mode

Point several instances at one Postgres (`INTERLOPER_DATABASE_URL`) and put
any load balancer in front; no sticky sessions are needed. The schema is
created on startup. `compose.yaml` runs Postgres and two servers.

- **Addresses are shared.** Any instance serves an address another one
  issued, with the provider state it was issued with.
- **Quarantine is global.** Schema drift seen by one instance quarantines the
  provider on all of them; `DELETE /v1/providers/{name}/quarantine` on any
  instance clears it on all of them within one sync.
- **Peers' failures steer routing.** Each instance publishes its health
  every sync and reads its peers' fresh rows (rows older than three sync
  intervals, by the database clock, are ignored). A provider leaves routing
  when a strict majority of the instances with recent evidence see it DOWN
  inside its cooldown; ties keep it in. Peers can only take a provider out,
  never put back one this instance saw fail, and their verdicts lapse with
  the voters' own cooldowns. Challenge-driven failures do not vote: they
  are about one instance's IP. `GET /v1/providers` shows `fleet_down` when
  peers, not local measurements, are what keeps a provider out.

cowbird shared quarantine but not DOWN, so each instance paid its own failed
calls to learn a provider had died.

TLS follows the URL's `sslmode` like libpq: `prefer` (default) uses TLS when
offered, `require` refuses plaintext, `disable` never tries. Certificates are
verified against Mozilla's roots, so managed Postgres (Neon, Supabase, RDS)
works with its connection string as given.

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
- **Built for agents.** `--json` everywhere, one JSON error object with a
  stable code, a `retryable` flag and a hint; distinct exit codes;
  `interloper guide` prints a manual generated from the code itself.
- **Fleet mode.** Several servers share issued addresses, health and
  quarantine through Postgres.
- One static binary with a real Chrome TLS/HTTP2 fingerprint (BoringSSL via
  `wreq`). No Python, no curl_cffi.

## Configuration

| env | |
|---|---|
| `INTERLOPER_PROXY` | egress proxy for every provider (and the solver) |
| `INTERLOPER_SOLVER_URL` | a [cloudflare-solver](https://github.com/B00H0O/cloudflare-solver); solver-only providers join the pool when set. Build it with `podman build -t il-solver deploy/solver` (pins Chrome 148; upstream's Dockerfile now installs a Chrome that breaks Turnstile) |
| `INTERLOPER_HEALTH_PATH` | health cache (default `$XDG_STATE_HOME/interloper/health.json`) |
| `INTERLOPER_LOG` | tracing filter, e.g. `interloper=debug` |
| `INTERLOPER_JSON` | `1` turns on `--json` for every command |

`COWBIRD_*` equivalents are accepted.

## Testing

```bash
cargo test                                   # offline, the default gate
interloper canary                            # live: can each provider issue and list?
INTERLOPER_DELIVERY=all cargo test -p interloper --features live \
  --test delivery -- --nocapture             # live: does real mail arrive and parse?
```

Every adapter runs the shared contract suite (`contract_tests!`) against
recorded fixtures. Porting guide: [docs/PORTING.md](docs/PORTING.md).

The delivery test sends each inbox its own random code and link and checks
both come back exactly. With `INTERLOPER_RESEND_KEY` and
`INTERLOPER_SENDER_FROM` (an address at a domain verified in
[Resend](https://resend.com)) it sends through Resend, six providers at a
time; otherwise it falls back to the keyless, rationed JoltMx test sender.
`INTERLOPER_DELIVERY` takes a comma list, `provider:domain` to pin a domain,
or `all`.

## License

AGPL-3.0-or-later, the same as [cowbird](https://github.com/Pranjal-SB/cowbird),
which interloper ports: provider behavior and many test fixtures come from it.
See [LICENSE](LICENSE). The optional solver image in `deploy/solver` builds
[cloudflare-solver](https://github.com/B00H0O/cloudflare-solver) (MIT) from a
pinned commit.
