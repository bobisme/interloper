//! Disposable-email backends behind one interface: generate an address, wait
//! for a message, extract an OTP or a link.
//!
//! ```no_run
//! # async fn demo() -> interloper::Result<()> {
//! use std::time::Duration;
//! let il = interloper::Interloper::from_env()?;
//! let inbox = il.inbox(&interloper::Request::new()).await?;
//! println!("sign up with {}", inbox.email());
//! let code = inbox.otp(Duration::from_secs(120)).await?;
//! # Ok(()) }
//! ```

pub mod contract;
pub mod error;
pub mod hash;
pub mod health;
pub mod inbox;
pub mod mime;
pub mod model;
pub mod parse;
pub mod pool;
pub mod provider;
pub mod providers;
pub mod registry;
pub mod shape;
pub mod solver;
pub mod testing;
pub mod transport;

use std::path::PathBuf;
use std::sync::Arc;

pub use error::{Error, Result};
pub use health::{HealthStore, Status};
pub use inbox::{Inbox, MailFilter};
pub use model::{Address, Capabilities, Kind, Message, MessageRow};
pub use pool::{Hedge, Pool, Request};
pub use provider::{GenerateOptions, Provider};
pub use regex;
pub use registry::{ProviderSpec, Registry};
pub use solver::Solver;

/// The front door: a registry of every built-in provider, a health store, and
/// a pool that routes between them.
pub struct Interloper {
    pool: Pool,
    health_path: Option<PathBuf>,
}

impl Interloper {
    /// Every built-in provider, the solver from `INTERLOPER_SOLVER_URL`, the
    /// proxy from `INTERLOPER_PROXY`, and health persisted at
    /// [`health::default_health_path`].
    pub fn from_env() -> Result<Self> {
        let health = Arc::new(HealthStore::new());
        let path = health::default_health_path();
        health.load(&path);
        let registry = Registry::new(providers::all(), health).with_solver(Solver::from_env()?);
        Ok(Interloper {
            pool: Pool::new(Arc::new(registry)),
            health_path: Some(path),
        })
    }

    /// Build from parts, with no persistence.
    pub fn with_registry(registry: Registry) -> Self {
        Interloper {
            pool: Pool::new(Arc::new(registry)),
            health_path: None,
        }
    }

    pub fn with_hedge(mut self, hedge: Option<Hedge>) -> Self {
        self.pool = Pool::new(self.pool.registry().clone()).with_hedge(hedge);
        self
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub fn registry(&self) -> &Arc<Registry> {
        self.pool.registry()
    }

    pub fn health(&self) -> &Arc<HealthStore> {
        self.registry().health()
    }

    /// A fresh inbox from the best provider that satisfies `req`.
    pub async fn inbox(&self, req: &Request) -> Result<Inbox> {
        let (provider, address) = self.pool.acquire(req).await?;
        Ok(Inbox::new(provider, address))
    }

    /// `n` inboxes spread across distinct providers rather than hammering the
    /// top-ranked one: it respects each backend's budget and means one dying
    /// backend costs 1/n of the batch. Wraps when `n` exceeds the candidates.
    /// All-or-nothing: on any failure the ones acquired are closed.
    pub async fn inboxes(&self, n: usize, req: &Request) -> Result<Vec<Inbox>> {
        let names: Vec<String> = self
            .pool
            .candidates(req)?
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        let jobs = (0..n).map(|i| {
            let mut r = req.clone();
            if req.provider.is_none() && !names.is_empty() {
                r.provider = Some(names[i % names.len()].clone());
            }
            async move { self.pool.acquire(&r).await }
        });
        let results = futures::future::join_all(jobs).await;
        let mut boxes = Vec::new();
        let mut first_err = None;
        for r in results {
            match r {
                Ok((p, a)) => boxes.push(Inbox::new(p, a)),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if let Some(e) = first_err {
            futures::future::join_all(boxes.into_iter().map(Inbox::close)).await;
            return Err(e);
        }
        Ok(boxes)
    }

    /// Re-open an inbox issued earlier, possibly by another process.
    pub fn resume(&self, address: Address) -> Result<Inbox> {
        let provider = self.registry().get(&address.provider)?;
        if provider.caps().needs_state && address.state.is_none() {
            return Err(Error::unsupported(format!(
                "{} needs the state issued at generate time; resume from the token instead",
                address.provider
            )));
        }
        Ok(Inbox::new(provider, address))
    }

    /// Re-open an inbox from [`Inbox::token`].
    pub fn resume_token(&self, token: &str) -> Result<Inbox> {
        self.resume(Address::from_token(token)?)
    }

    /// Persist health, merging with concurrent writers. Errors are returned
    /// for the caller to ignore: a read-only disk must not fail real work.
    pub fn save_health(&self) -> std::io::Result<()> {
        match &self.health_path {
            Some(p) => self.health().save(p),
            None => Ok(()),
        }
    }
}
