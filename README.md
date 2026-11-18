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
calls to learn a provider had died. Plain TCP only: keep Postgres on a
private network.

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
