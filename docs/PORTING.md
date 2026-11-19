# Porting a cowbird adapter

Source of truth for behavior: [cowbird](https://github.com/Pranjal-SB/cowbird)'s `packages/providers/<name>/`
(`src/cowbird_<name>/__init__.py`, `tests/test_contract.py`,
`tests/fixtures/`). Templates here: `src/providers/mailtm.rs` (account +
token state), `guerrillamail.rs` (session id in state, `fresh_session`),
`inboxes.rs` (catch-all, no-request generate, delete), `maildrop.rs`
(GraphQL).

## Steps

1. Copy fixtures: `crates/interloper/fixtures/<name>/` ← cowbird's
   `tests/fixtures/`. They were recorded through cowbird's `Transport` (Chrome
   impersonation + `Accept: application/json` on JSON calls), which is what
   interloper sends too, so they replay as-is.
2. Write `crates/interloper/src/providers/<name>.rs`:
   - `pub const CAPS: Capabilities = Capabilities { ..Capabilities::DEFAULT }`
     with every field cowbird declared (`timedelta` → `hours()/days()/minutes()`,
     `poll_interval=3.0` → `Duration::from_secs(3)`).
   - `pub const SPEC: ProviderSpec = ProviderSpec { name, caps: CAPS, build: |t| Arc::new(X { http: t }) }`.
     Name = cowbird's `name` exactly (it keys persisted health).
   - `impl Provider` with `#[async_trait]`.
3. Register: `pub mod <name>;` and `<name>::SPEC` in `providers/mod.rs`
   (alphabetical). **Only touch your own lines** in that file.
4. Tests in the same file: `crate::contract_tests!(SPEC, build(&wire()));`
   plus a port of every adapter-specific test in cowbird's `test_contract.py`
   (the generic `ProviderContract` ones are covered by the macro).
5. `cargo test -p interloper providers::<name>` and `cargo clippy --all-targets`
   must be clean.

## Mapping

| cowbird | interloper |
|---|---|
| `self.http.json("GET", url, params=..., headers=...)` | `self.http.get(url).query(k, v).header(k, v).json().await?` |
| `self.http.json("POST", url, json=body)` | `.post(url).json_body(&json!(..)).json().await?` |
| `data=` form body | `.form([("k", v)])` |
| `self.http.text(...)` | `.text().await?` |
| `self.http.send(...)` → `resp.status_code`, `resp.text`, `resp.cookies` | `.send_json().await?` (pins JSON Accept) or `.send().await?` → `resp.status`, `resp.text`, `resp.cookie("n")`, `resp.json(name)?` |
| `cookies={...}` | `.cookie(k, v)` |
| `raise SchemaDrift(name, expected=..., got=...)` | `J::new(name, &v, "where")` accessors (`at`, `opt`, `items`, `str`, `id`, `req_id`, `s`, `time`) produce drift with a JSON path; or `Error::drift(name, expected, got)` |
| `raise ProviderDown(...)` | `Error::down(name, detail)` |
| `raise MessageGone(...)` | `Error::gone(name, id)` |
| `raise NotSupported(...)` | `Error::unsupported(msg)` |
| `MessageLocked` | `Error::MessageLocked { provider, id }` |
| `AddressExpired` | `Error::AddressExpired(msg)` |
| `html_to_text`, `extract_links` | `Message::from_bodies(id, sender, subject, at, html, text_opt)` derives both |
| `datetime.fromisoformat` / epoch | `j.time("field")` or `shape::parse_time` |
| `secrets.token_hex(5)` local part | `util::random_local()` / `util::local_or_random(opts)` |
| domain choice + NotSupported | `util::pick_domain(name, opts, DOMAINS)?` |
| `opts.local` refused | `util::no_custom_local(name, opts)?` |
| solver turnstile | `self.http.turnstile_solver()?.turnstile(url, sitekey, action, cdata).await?` |
| `FakeTransport(routes)` | `Fixtures::new().route(key, Reply::json(..))` / `.route_seq(key, [..])`; same substring matching on `"METHOD url?query body cookies headers"`, longest key first |
| `Reply(status=404, payload=...)` | `Reply::json(v).with_status(404)`, `Reply::status(500)`, `Reply::text(s)`, `.set_cookie(n, v)` |
| `Responses(a, b)` | `.route_seq(key, [a, b])` (last repeats) |
| `http.seen` | `w.seen()`, `w.methods()`, `req.full_url()`, `req.header(..)`, `req.body` |

Transport behavior to rely on, not re-implement: 429 → `RateLimited`,
5xx → retried then `ProviderDown`, Cloudflare interstitial → `Challenge`
(and a solve + replay when a solver is configured), wire errors → `ProviderDown`.
`json()` on a non-JSON 4xx is `ProviderDown`, on a non-JSON 2xx is drift.

## Rules

- Protocol knowledge only. No retries, sleeps, clients, or HTML parsing.
- A caller error (unserved domain, bad local) is `NotSupported`, never drift:
  drift quarantines the provider until a human clears it.
- An answer about one message (gone, locked) is never an outage.
- Keep cowbird's doc comments that explain *why* a backend behaves oddly;
  they are hard-won. American English.
- Do not change core (`src/*.rs` outside `providers/`). If core is missing
  something, say so in your report instead.
