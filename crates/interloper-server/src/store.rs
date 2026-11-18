//! Where the server keeps the addresses it issued.
//!
//! An address carries provider state (mail.tm's JWT, for one) that later calls
//! need. Handing that blob to clients would make `GET /v1/inboxes/{addr}/messages`
//! impossible to call from plain curl, so the server holds it. cowbird kept it
//! in a dict by default, so a restart lost every live inbox; here a SQLite file
//! keeps them when `INTERLOPER_DATABASE` is set.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use interloper::Address;
use jiff::Timestamp;
use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug)]
pub struct StoreUnavailable(pub String);

pub enum Store {
    Memory(Mutex<HashMap<String, Address>>),
    Sqlite(Mutex<Connection>),
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

    pub fn put(&self, a: &Address) -> Result<(), StoreUnavailable> {
        match self {
            Store::Memory(m) => {
                m.lock().unwrap().insert(a.value.to_lowercase(), a.clone());
                Ok(())
            }
            Store::Sqlite(c) => {
                let body = serde_json::to_string(a).expect("address serializes");
                c.lock()
                    .unwrap()
                    .execute(
                        "insert or replace into addresses (value, body, expires_at) values (?1, ?2, ?3)",
                        params![a.value.to_lowercase(), body, a.expires_at.map(|t| t.as_second())],
                    )
                    .map(|_| ())
                    .map_err(|e| StoreUnavailable(e.to_string()))
            }
        }
    }

    /// The address, unless unknown or expired (expired rows are evicted on read).
    pub fn get(&self, value: &str) -> Result<Option<Address>, StoreUnavailable> {
        let key = value.to_lowercase();
        let now = Timestamp::now();
        let found = match self {
            Store::Memory(m) => m.lock().unwrap().get(&key).cloned(),
            Store::Sqlite(c) => {
                let body: Option<String> = c
                    .lock()
                    .unwrap()
                    .query_row(
                        "select body from addresses where value = ?1",
                        params![key],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(|e| StoreUnavailable(e.to_string()))?;
                body.and_then(|b| serde_json::from_str(&b).ok())
            }
        };
        match found {
            Some(a) if a.is_expired(now) => {
                self.remove(&key)?;
                Ok(None)
            }
            other => Ok(other),
        }
    }

    fn remove(&self, key: &str) -> Result<(), StoreUnavailable> {
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
                .map_err(|e| StoreUnavailable(e.to_string())),
        }
    }

    /// Reap expired rows. `get` only evicts rows somebody asks for, and nobody
    /// asks for an address after it expired; without this they pile up.
    pub fn sweep(&self) -> Result<usize, StoreUnavailable> {
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
                .map_err(|e| StoreUnavailable(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn past() -> Address {
        let mut a = Address::new("old@x.test", "p");
        a.expires_at = Some(Timestamp::from_second(1).unwrap());
        a
    }

    fn check(store: Store) {
        let a = Address::new("Me@X.test", "p").with_state("secret");
        store.put(&a).unwrap();
        assert_eq!(store.get("me@x.test").unwrap(), Some(a));
        store.put(&past()).unwrap();
        assert_eq!(store.get("old@x.test").unwrap(), None);
        store.put(&past()).unwrap();
        assert_eq!(store.sweep().unwrap(), 1);
        assert_eq!(store.get("nobody@x.test").unwrap(), None);
    }

    #[test]
    fn memory_store() {
        check(Store::memory());
    }

    #[test]
    fn sqlite_store_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("ilp-store-{}", std::process::id()));
        let path = dir.join("a.db");
        check(Store::sqlite(&path).unwrap());
        let a = Address::new("keep@x.test", "p").with_state("s");
        Store::sqlite(&path).unwrap().put(&a).unwrap();
        assert_eq!(
            Store::sqlite(&path).unwrap().get("keep@x.test").unwrap(),
            Some(a)
        );
        std::fs::remove_dir_all(dir).ok();
    }
}
