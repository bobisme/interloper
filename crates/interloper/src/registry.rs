//! Finds providers and builds them. Does not choose between them; that is
//! the pool's job.
//!
//! cowbird discovered adapters through Python entry points so each could ship
//! as its own package. In Rust the natural unit is a compiled-in table of
//! [`ProviderSpec`]s: no load-time failures to swallow, and a provider that
//! does not compile cannot ship. Library users can still add their own specs.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::error::{Error, Result};
use crate::health::HealthStore;
use crate::model::{Address, Capabilities, Message, MessageRow};
use crate::provider::{GenerateOptions, Provider, poll_watch};
use crate::solver::Solver;
use crate::transport::{Backend, NetConfig, Transport, WreqBackend};

/// How to build one provider.
#[derive(Clone, Copy)]
pub struct ProviderSpec {
    pub name: &'static str,
    pub caps: Capabilities,
    pub build: fn(Transport) -> Arc<dyn Provider>,
}

impl std::fmt::Debug for ProviderSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderSpec")
            .field("name", &self.name)
            .finish()
    }
}

/// Builds the wire for one provider.
pub type WireFactory = Arc<dyn Fn(&ProviderSpec) -> Result<Arc<dyn Backend>> + Send + Sync>;

pub struct Registry {
    specs: BTreeMap<&'static str, ProviderSpec>,
    instances: Mutex<HashMap<&'static str, Arc<dyn Provider>>>,
    health: Arc<HealthStore>,
    solver: Option<Solver>,
    net: NetConfig,
    wire: WireFactory,
    transport_tweak: Option<Arc<dyn Fn(Transport) -> Transport + Send + Sync>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("specs", &self.specs.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Registry {
    /// A registry over `specs`, with real network wires.
    pub fn new(specs: impl IntoIterator<Item = ProviderSpec>, health: Arc<HealthStore>) -> Self {
        let net = NetConfig::from_env();
        let wire_net = net.clone();
        Registry {
            specs: specs.into_iter().map(|s| (s.name, s)).collect(),
            instances: Mutex::new(HashMap::new()),
            health,
            solver: None,
            net,
            // One wire per provider: separate cookie jars, as each backend
            // had its own session in cowbird.
            wire: Arc::new(move |_| {
                Ok(Arc::new(WreqBackend::new(wire_net.clone())?) as Arc<dyn Backend>)
            }),
            transport_tweak: None,
        }
    }

    pub fn with_solver(mut self, solver: Option<Solver>) -> Self {
        // A clearance is bound to the egress, so the solver must leave
        // through the same proxy as the providers.
        self.solver = solver.map(|s| s.with_proxy(self.net.proxy.clone()));
        self
    }

    pub fn with_wire(mut self, wire: WireFactory) -> Self {
        self.wire = wire;
        self
    }

    /// Adjust every transport after it is built (tests turn retries off).
    pub fn with_transport_tweak(
        mut self,
        f: impl Fn(Transport) -> Transport + Send + Sync + 'static,
    ) -> Self {
        self.transport_tweak = Some(Arc::new(f));
        self
    }

    pub fn register(&mut self, spec: ProviderSpec) {
        self.instances.lock().unwrap().remove(spec.name);
        self.specs.insert(spec.name, spec);
    }

    pub fn health(&self) -> &Arc<HealthStore> {
        &self.health
    }

    pub fn solver(&self) -> Option<&Solver> {
        self.solver.as_ref()
    }

    pub fn specs(&self) -> impl Iterator<Item = &ProviderSpec> {
        self.specs.values()
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.specs.keys().copied().collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.specs.contains_key(name)
    }

    /// The provider, wrapped so every call it makes feeds health.
    pub fn get(&self, name: &str) -> Result<Arc<dyn Provider>> {
        let spec = self
            .specs
            .get(name)
            .ok_or_else(|| Error::NoProviderAvailable {
                tried: vec![name.to_string()],
                last: Some(Box::new(Error::unsupported(format!(
                    "unknown provider {name:?}"
                )))),
            })?;
        let mut instances = self.instances.lock().unwrap();
        if let Some(p) = instances.get(spec.name) {
            return Ok(p.clone());
        }
        let wire = (self.wire)(spec)?;
        let mut transport = Transport::new(spec.name, wire)
            .max_concurrency(spec.caps.max_concurrency)
            .fresh_session(spec.caps.fresh_session)
            .solver(self.solver.clone());
        if let Some(tweak) = &self.transport_tweak {
            transport = tweak(transport);
        }
        let inner = (spec.build)(transport);
        let tracked: Arc<dyn Provider> = Arc::new(Tracked {
            inner,
            health: self.health.clone(),
        });
        instances.insert(spec.name, tracked.clone());
        Ok(tracked)
    }

    /// Insert an already-built provider (tests, or a caller-owned adapter).
    pub fn insert(&mut self, provider: Arc<dyn Provider>) {
        let name: &'static str = Box::leak(provider.name().to_string().into_boxed_str());
        let caps = *provider.caps();
        self.specs.insert(
            name,
            ProviderSpec {
                name,
                caps,
                build: |_| unreachable!("inserted providers are prebuilt"),
            },
        );
        let tracked: Arc<dyn Provider> = Arc::new(Tracked {
            inner: provider,
            health: self.health.clone(),
        });
        self.instances.lock().unwrap().insert(name, tracked);
    }

    /// Every provider, by name.
    pub fn all(&self) -> Vec<Arc<dyn Provider>> {
        self.specs.keys().filter_map(|n| self.get(n).ok()).collect()
    }
}

/// Times and records every call a provider makes.
///
/// Without this, health is only observed at `generate()` — the one call a
/// rotted provider is least likely to fail. A backend whose `list()` changed
/// shape would keep issuing addresses and stay green forever, and rot
/// detection is the point of the project.
struct Tracked {
    inner: Arc<dyn Provider>,
    health: Arc<HealthStore>,
}

impl Tracked {
    async fn tracked<T>(&self, fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        let started = Instant::now();
        let result = fut.await;
        match &result {
            Ok(_) => self
                .health
                .record_success(self.inner.name(), started.elapsed()),
            Err(e) => self.health.record_error(self.inner.name(), e),
        }
        result
    }
}

#[async_trait]
impl Provider for Tracked {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn caps(&self) -> &Capabilities {
        self.inner.caps()
    }

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address> {
        self.tracked(self.inner.generate(opts)).await
    }

    async fn list(&self, address: &Address) -> Result<Vec<MessageRow>> {
        self.tracked(self.inner.list(address)).await
    }

    async fn get(&self, address: &Address, id: &str) -> Result<Message> {
        self.tracked(self.inner.get(address, id)).await
    }

    async fn delete(&self, address: &Address, id: &str) -> Result<()> {
        self.tracked(self.inner.delete(address, id)).await
    }

    fn watch<'a>(
        &'a self,
        address: &'a Address,
        poll: Option<Duration>,
    ) -> BoxStream<'a, Result<Message>> {
        // A watch is the longest-running call in the system; polling through
        // this wrapper means its list()/get() calls feed health too. A push
        // provider keeps its own implementation.
        if self.inner.caps().push {
            self.inner.watch(address, poll)
        } else {
            poll_watch(self, address, poll)
        }
    }
}
