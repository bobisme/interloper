//! Where the server keeps the addresses it issued.
//!
//! An address carries provider state (mail.tm's JWT, for one) that later calls
//! need. Handing that blob to clients would make `GET /v1/inboxes/{addr}/messages`
//! impossible to call from plain curl, so the server holds it. cowbird kept it
//! in a dict by default, so a restart lost every live inbox; here a SQLite file
//! keeps them when `INTERLOPER_DATABASE` is set, and Postgres
//! (`INTERLOPER_DATABASE_URL`) lets a fleet of servers share them, so any
//! instance serves an address another one issued.
//!
//! All three backends key by the lowercased address, store the address as
//! JSON, evict an expired row when it is read, and reap the rest in `sweep`.

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use interloper::Address;
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};
use tokio_postgres::NoTls;

#[derive(Debug)]
pub struct StoreUnavailable(pub String);

impl std::fmt::Display for StoreUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Any database failure, pool timeouts included, is an outage to the caller:
/// a 503 to retry, not a 500.
pub(crate) fn unavailable(e: impl std::error::Error) -> StoreUnavailable {
    // tokio-postgres prints a server error as just "db error"; the server's
    // message is in the source chain.
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg = format!("{msg}: {s}");
        src = s.source();
    }
    StoreUnavailable(msg)
}

/// How long a request waits for a pooled connection before answering 503.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// Tables for fleet mode. `addresses` mirrors the SQLite schema. The two
/// health tables are described in [`crate::fleet`].
const PG_SCHEMA: &str = "
    create table if not exists addresses (
        value      text primary key,
        body       text not null,
        expires_at bigint
    );
    create index if not exists addresses_expiry on addresses (expires_at);
    create table if not exists instance_health (
        instance_id text primary key,
        snapshot    jsonb not null,
        updated_at  timestamptz not null default now()
    );
    create table if not exists provider_quarantine (
        provider    text primary key,
        reason      text not null,
        instance_id text not null,
        at          timestamptz not null default now()
    );
";

pub enum Store {
    Memory(Mutex<HashMap<String, Address>>),
    Sqlite(Mutex<Connection>),
    Postgres(Pool),
}

impl Store {
    pub fn memory() -> Self {
        Store::Memory(Mutex::new(HashMap::new()))
    }

    pub fn sqlite(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "pragma journal_mode = wal;
             create table if not exists addresses (
                 value text primary key,
                 body text not null,
                 expires_at integer
             );
             create index if not exists addresses_expiry on addresses(expires_at);",
        )
        .map_err(|e| e.to_string())?;
        Ok(Store::Sqlite(Mutex::new(conn)))
    }

    /// Connect, and create the schema if it is missing. Fails rather than
    /// starting a server whose every request would 503. Plain TCP only: run
    /// Postgres on a private network or behind a TLS-terminating proxy.
    pub async fn postgres(url: &str) -> Result<Self, String> {
        let mut cfg = tokio_postgres::Config::from_str(url).map_err(|e| e.to_string())?;
        if cfg.get_connect_timeout().is_none() {
            cfg.connect_timeout(Duration::from_secs(5));
        }
        let mgr = Manager::from_config(
            cfg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(mgr)
            .max_size(16)
            .runtime(Runtime::Tokio1)
            .wait_timeout(Some(ACQUIRE_TIMEOUT))
            .create_timeout(Some(ACQUIRE_TIMEOUT))
            .build()
            .map_err(|e| e.to_string())?;
        let client = pool.get().await.map_err(|e| e.to_string())?;
        // Two instances booting at once may both run this, and `if not
        // exists` still races on the catalog. Separate statements, so the
        // schema commits before the lock is released.
        client
            .execute("select pg_advisory_lock(7280431)", &[])
            .await
            .map_err(|e| unavailable(e).0)?;
        let migrated = client
            .batch_execute(PG_SCHEMA)
            .await
            .map_err(|e| unavailable(e).0);
        let _ = client
            .execute("select pg_advisory_unlock(7280431)", &[])
            .await;
        migrated?;
        drop(client);
        Ok(Store::Postgres(pool))
    }

    /// The connection pool, when this store is Postgres; fleet health sync
    /// shares it.
    pub fn pg_pool(&self) -> Option<&Pool> {
        match self {
            Store::Postgres(p) => Some(p),
            _ => None,
        }
    }

    pub async fn put(&self, a: &Address) -> Result<(), StoreUnavailable> {
        let key = a.value.to_lowercase();
        let body = serde_json::to_string(a).expect("address serializes");
        let expires = a.expires_at.map(|t| t.as_second());
        match self {
            Store::Memory(m) => {
                m.lock().unwrap().insert(key, a.clone());
                Ok(())
            }
            Store::Sqlite(c) => c
                .lock()
                .unwrap()
                .execute(
                    "insert or replace into addresses (value, body, expires_at) values (?1, ?2, ?3)",
                    params![key, body, expires],
                )
                .map(|_| ())
                .map_err(unavailable),
            // Upsert: one instance issuing and another refreshing the same
            // address is ordinary, not a conflict.
            Store::Postgres(p) => p
                .get()
                .await
                .map_err(unavailable)?
                .execute(
                    "insert into addresses (value, body, expires_at) values ($1, $2, $3)
                     on conflict (value) do update
                     set body = excluded.body, expires_at = excluded.expires_at",
                    &[&key, &body, &expires],
                )
                .await
                .map(|_| ())
                .map_err(unavailable),
        }
    }

    /// The address, unless unknown or expired (expired rows are evicted on read).
    pub async fn get(&self, value: &str) -> Result<Option<Address>, StoreUnavailable> {
        let key = value.to_lowercase();
        let now = Timestamp::now();
        let body: Option<String> = match self {
            Store::Memory(m) => {
                let found = m.lock().unwrap().get(&key).cloned();
                return match found {
                    Some(a) if a.is_expired(now) => {
                        self.remove(&key).await?;
                        Ok(None)
                    }
                    other => Ok(other),
                };
            }
            Store::Sqlite(c) => c
                .lock()
                .unwrap()
                .query_row(
                    "select body from addresses where value = ?1",
                    params![key],
                    |r| r.get(0),
                )
                .optional()
                .map_err(unavailable)?,
            Store::Postgres(p) => p
                .get()
                .await
                .map_err(unavailable)?
                .query_opt("select body from addresses where value = $1", &[&key])
                .await
                .map_err(unavailable)?
                .map(|r| r.get(0)),
        };
        match body.and_then(|b| serde_json::from_str::<Address>(&b).ok()) {
            Some(a) if a.is_expired(now) => {
                self.remove(&key).await?;
                Ok(None)
            }
            other => Ok(other),
        }
    }

    async fn remove(&self, key: &str) -> Result<(), StoreUnavailable> {
        match self {
            Store::Memory(m) => {
                m.lock().unwrap().remove(key);
                Ok(())
            }
            Store::Sqlite(c) => c
                .lock()
                .unwrap()
                .execute("delete from addresses where value = ?1", params![key])
                .map(|_| ())
                .map_err(unavailable),
            Store::Postgres(p) => p
                .get()
                .await
                .map_err(unavailable)?
                .execute("delete from addresses where value = $1", &[&key])
                .await
                .map(|_| ())
                .map_err(unavailable),
        }
    }

    /// Reap expired rows. `get` only evicts rows somebody asks for, and nobody
    /// asks for an address after it expired; without this they pile up.
    pub async fn sweep(&self) -> Result<usize, StoreUnavailable> {
        let now = Timestamp::now();
        match self {
            Store::Memory(m) => {
                let mut m = m.lock().unwrap();
                let before = m.len();
                m.retain(|_, a| !a.is_expired(now));
                Ok(before - m.len())
            }
            Store::Sqlite(c) => c
                .lock()
                .unwrap()
                .execute(
                    "delete from addresses where expires_at is not null and expires_at <= ?1",
                    params![now.as_second()],
                )
                .map_err(unavailable),
            Store::Postgres(p) => p
                .get()
                .await
                .map_err(unavailable)?
                .execute(
                    "delete from addresses where expires_at is not null and expires_at <= $1",
                    &[&now.as_second()],
                )
                .await
                .map(|n| n as usize)
                .map_err(unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn past(value: &str) -> Address {
        let mut a = Address::new(value, "p");
        a.expires_at = Some(Timestamp::from_second(1).unwrap());
        a
    }

    /// The shared contract. `tag` keeps rows from concurrent runs against
    /// one Postgres apart.
    async fn check(store: Store, tag: &str) {
        let me = format!("Me-{tag}@X.test");
        let old = format!("old-{tag}@x.test");
        let a = Address::new(&me, "p").with_state("secret");
        store.put(&a).await.unwrap();
        assert_eq!(store.get(&me.to_lowercase()).await.unwrap(), Some(a));
        // Upsert, not a duplicate-key error.
        let b = Address::new(&me, "p").with_state("refreshed");
        store.put(&b).await.unwrap();
        assert_eq!(store.get(&me).await.unwrap(), Some(b));
        store.put(&past(&old)).await.unwrap();
        assert_eq!(store.get(&old).await.unwrap(), None);
        store.put(&past(&old)).await.unwrap();
        assert!(store.sweep().await.unwrap() >= 1);
        assert_eq!(store.get(&old).await.unwrap(), None);
        assert_eq!(
            store.get(&format!("nobody-{tag}@x.test")).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn memory_store() {
        check(Store::memory(), "m").await;
    }

    #[tokio::test]
    async fn sqlite_store_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("ilp-store-{}", std::process::id()));
        let path = dir.join("a.db");
        check(Store::sqlite(&path).unwrap(), "s").await;
        let a = Address::new("keep@x.test", "p").with_state("s");
        Store::sqlite(&path).unwrap().put(&a).await.unwrap();
        assert_eq!(
            Store::sqlite(&path)
                .unwrap()
                .get("keep@x.test")
                .await
                .unwrap(),
            Some(a)
        );
        std::fs::remove_dir_all(dir).ok();
    }

    /// Runs only with `INTERLOPER_TEST_DATABASE_URL` set.
    #[tokio::test]
    async fn postgres_store() {
        let Some(url) = crate::fleet::test_database_url() else {
            eprintln!("skipped: INTERLOPER_TEST_DATABASE_URL is unset");
            return;
        };
        let tag = format!("{:x}", rand::random::<u64>());
        check(Store::postgres(&url).await.unwrap(), &tag).await;
        // A second connection (another instance) sees what the first wrote.
        let a = Address::new(format!("shared-{tag}@x.test"), "p").with_state("s");
        Store::postgres(&url).await.unwrap().put(&a).await.unwrap();
        assert_eq!(
            Store::postgres(&url)
                .await
                .unwrap()
                .get(&a.value)
                .await
                .unwrap(),
            Some(a)
        );
    }

    #[tokio::test]
    async fn unreachable_postgres_fails_fast() {
        let r = Store::postgres("postgres://u:p@127.0.0.1:1/db").await;
        assert!(r.is_err());
    }
}
