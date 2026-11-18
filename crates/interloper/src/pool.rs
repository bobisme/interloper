//! Choosing a provider: pure policy over the registry and health store.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::error::{Error, Result};
use crate::health::Tier;
use crate::model::{Address, Kind};
use crate::provider::{GenerateOptions, Provider};
use crate::registry::Registry;

/// What the caller needs from an address. Every field narrows the candidates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Request {
    pub provider: Option<String>,
    pub kind: Option<Kind>,
    pub local: Option<String>,
    pub domain: Option<String>,
    pub domain_not_in: Vec<String>,
    pub address_ttl: Option<Duration>,
    pub message_ttl: Option<Duration>,
    pub push: Option<bool>,
    pub delete: Option<bool>,
    pub self_hosted: Option<bool>,
}

impl Request {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn provider(mut self, name: impl Into<String>) -> Self {
        self.provider = Some(name.into());
        self
    }

    pub fn kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    pub fn local(mut self, local: impl Into<String>) -> Self {
        self.local = Some(local.into());
        self
    }

    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn domain_not_in(mut self, domains: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.domain_not_in = domains.into_iter().map(Into::into).collect();
        self
    }

    pub fn address_ttl(mut self, at_least: Duration) -> Self {
        self.address_ttl = Some(at_least);
        self
    }

    pub fn message_ttl(mut self, at_least: Duration) -> Self {
        self.message_ttl = Some(at_least);
        self
    }

    pub fn options(&self) -> GenerateOptions {
        GenerateOptions {
            kind: self.kind,
            local: self.local.clone(),
            domain: self.domain.clone(),
        }
    }

    fn domain_blocked(&self, address: &Address) -> bool {
        let d = address.domain().to_ascii_lowercase();
        self.domain_not_in
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&d))
    }
}

/// Hedging: when the leading candidate has not answered within this long,
/// start the next one too and take whichever answers first.
#[derive(Debug, Clone, Copy)]
pub struct Hedge {
    /// Delay before a hedge when the provider has no latency history.
    pub default: Duration,
    /// Floor and ceiling for the delay derived from a provider's p50.
    pub min: Duration,
    pub max: Duration,
    /// Most generates in flight at once for one acquire.
    pub fan_out: usize,
}

impl Default for Hedge {
    fn default() -> Self {
        Hedge {
            default: Duration::from_secs(3),
            min: Duration::from_millis(1500),
            max: Duration::from_secs(8),
            fan_out: 3,
        }
    }
}

pub struct Pool {
    registry: Arc<Registry>,
    hedge: Option<Hedge>,
}

impl Pool {
    pub fn new(registry: Arc<Registry>) -> Self {
        Pool {
            registry,
            hedge: Some(Hedge::default()),
        }
    }

    /// `None` disables hedging: candidates are tried strictly one at a time,
    /// as cowbird did.
    pub fn with_hedge(mut self, hedge: Option<Hedge>) -> Self {
        self.hedge = hedge;
        self
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Eligible providers, best first.
    pub fn candidates(&self, req: &Request) -> Result<Vec<Arc<dyn Provider>>> {
        req.options().validate()?;
        if let Some(name) = &req.provider {
            return Ok(vec![self.registry.get(name)?]);
        }
        let health = self.registry.health();
        // (tier, p50, -domain_count, name): healthier, faster, wider, then stable.
        type Ranked = (Tier, f64, i64, String, Arc<dyn Provider>);
        let mut ranked: Vec<Ranked> = self
            .registry
            .all()
            .into_iter()
            .filter(|p| self.matches(p.as_ref(), req))
            .filter_map(|p| {
                let tier = health.tier(p.name())?;
                // Unmeasured ranks as 0.0: new providers get explored.
                let p50 = health.p50(p.name()).unwrap_or(0.0);
                Some((
                    tier,
                    p50,
                    -(p.caps().domain_count as i64),
                    p.name().to_string(),
                    p,
                ))
            })
            .collect();
        ranked.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(a.1.total_cmp(&b.1))
                .then(a.2.cmp(&b.2))
                .then(a.3.cmp(&b.3))
        });
        Ok(ranked.into_iter().map(|r| r.4).collect())
    }

    fn matches(&self, p: &dyn Provider, req: &Request) -> bool {
        let caps = p.caps();
        if caps.needs_solver && self.registry.solver().is_none() {
            return false;
        }
        if req.kind.is_some_and(|k| !caps.serves(k)) {
            return false;
        }
        if req.push.is_some_and(|v| v != caps.push)
            || req.delete.is_some_and(|v| v != caps.delete)
            || req.self_hosted.is_some_and(|v| v != caps.self_hosted)
        {
            return false;
        }
        if req.local.is_some() && !caps.custom_local {
            return false;
        }
        if let Some(d) = &req.domain
            && !caps.domains.is_empty()
            && !caps.domains.iter().any(|x| x.eq_ignore_ascii_case(d))
        {
            return false;
        }
        if !req.domain_not_in.is_empty()
            && !caps.domains.is_empty()
            && caps
                .domains
                .iter()
                .all(|d| req.domain_not_in.iter().any(|b| b.eq_ignore_ascii_case(d)))
        {
            return false;
        }
        outlives(caps.address_ttl, req.address_ttl) && outlives(caps.message_ttl, req.message_ttl)
    }

    fn hedge_delay(&self, hedge: &Hedge, p: &dyn Provider) -> Duration {
        match self.registry.health().p50(p.name()) {
            Some(p50) => Duration::from_secs_f64(p50 * 2.0).clamp(hedge.min, hedge.max),
            None => hedge.default,
        }
    }

    /// An address from the best provider that will issue one.
    ///
    /// Reroutable failures move on to the next candidate; anything else is an
    /// answer for the caller and is returned at once. With hedging on, a slow
    /// leader does not hold the caller hostage: after a delay derived from its
    /// own p50, the next candidate starts in parallel and the first address
    /// back wins. Losers are cancelled; an address one of them may already
    /// have created upstream is simply abandoned, which is what disposable
    /// addresses are for.
    pub async fn acquire(&self, req: &Request) -> Result<(Arc<dyn Provider>, Address)> {
        let opts = Arc::new(req.options());
        let mut queue = self.candidates(req)?.into_iter();
        let mut tried: Vec<String> = Vec::new();
        let mut last: Option<Error> = None;
        type Attempt = BoxFuture<'static, (Arc<dyn Provider>, Result<Address>)>;
        let mut inflight: FuturesUnordered<Attempt> = FuturesUnordered::new();
        let launch = |p: Arc<dyn Provider>, tried: &mut Vec<String>| -> Attempt {
            tried.push(p.name().to_string());
            let opts = opts.clone();
            Box::pin(async move {
                let r = p.generate(&opts).await;
                (p, r)
            })
        };
        let mut leader: Option<Arc<dyn Provider>> = None;
        loop {
            if inflight.is_empty() {
                match queue.next() {
                    Some(p) => {
                        leader = Some(p.clone());
                        inflight.push(launch(p, &mut tried));
                    }
                    None => break,
                }
            }
            let hedge_wait = match (&self.hedge, &leader) {
                (Some(h), Some(l)) if inflight.len() < h.fan_out && queue.len() > 0 => {
                    Some(self.hedge_delay(h, l.as_ref()))
                }
                _ => None,
            };
            let timer = async {
                match hedge_wait {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                Some((p, result)) = inflight.next() => match result {
                    Ok(address) if req.domain_not_in.is_empty() || !req.domain_blocked(&address) => {
                        return Ok((p, address));
                    }
                    Ok(_) => {}
                    Err(e) if !e.reroutable() => return Err(e),
                    Err(e) => {
                        tracing::debug!(provider = p.name(), error = %e, "rerouting");
                        last = Some(e);
                    }
                },
                () = timer => {
                    if let Some(p) = queue.next() {
                        tracing::debug!(provider = p.name(), "hedging a slow leader");
                        leader = Some(p.clone());
                        inflight.push(launch(p, &mut tried));
                    }
                }
            }
        }
        Err(Error::NoProviderAvailable {
            tried,
            last: last.map(Box::new),
        })
    }
}

fn outlives(have: Option<Duration>, need: Option<Duration>) -> bool {
    match (have, need) {
        (_, None) | (None, Some(_)) => true,
        (Some(h), Some(n)) => h >= n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthStore;
    use crate::model::{Capabilities, hours};
    use crate::testing::{FAKE_CAPS, FakeProvider};

    fn pool(providers: Vec<FakeProvider>) -> Pool {
        let mut reg = Registry::new([], Arc::new(HealthStore::new()));
        for p in providers {
            reg.insert(Arc::new(p));
        }
        Pool::new(Arc::new(reg)).with_hedge(None)
    }

    #[tokio::test]
    async fn reroutes_past_a_down_provider() {
        let p = pool(vec![
            FakeProvider::new("a").failing(Error::down("a", "x")),
            FakeProvider::new("b"),
        ]);
        let (prov, addr) = p.acquire(&Request::new()).await.unwrap();
        assert_eq!(prov.name(), "b");
        assert_eq!(addr.provider, "b");
        assert_eq!(
            p.registry().health().status("a"),
            crate::health::Status::Down
        );
    }

    #[tokio::test]
    async fn non_reroutable_errors_surface_immediately() {
        let p = pool(vec![
            FakeProvider::new("a").failing(Error::unsupported("nope")),
            FakeProvider::new("b"),
        ]);
        assert!(matches!(
            p.acquire(&Request::new()).await,
            Err(Error::NotSupported(_))
        ));
    }

    #[tokio::test]
    async fn exhausted_pool_names_every_attempt() {
        let p = pool(vec![
            FakeProvider::new("a").failing(Error::down("a", "x")),
            FakeProvider::new("b").failing(Error::RateLimited {
                provider: "b".into(),
                retry_after: None,
            }),
        ]);
        match p.acquire(&Request::new()).await {
            Err(Error::NoProviderAvailable { tried, last }) => {
                assert_eq!(tried, ["a", "b"]);
                assert!(matches!(last.as_deref(), Some(Error::RateLimited { .. })));
            }
            other => panic!("{:?}", other.err()),
        }
    }

    #[test]
    fn filters_by_capability() {
        const GMAIL: Capabilities = Capabilities {
            kind: &[Kind::GmailAlias],
            address_ttl: Some(hours(1)),
            ..FAKE_CAPS
        };
        let p = pool(vec![
            FakeProvider::new("own"),
            FakeProvider::new("gm").caps(GMAIL),
        ]);
        let names = |r: Request| {
            p.candidates(&r)
                .unwrap()
                .iter()
                .map(|p| p.name().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(Request::new().kind(Kind::GmailAlias)), ["gm"]);
        assert_eq!(names(Request::new().address_ttl(hours(2))), ["own"]);
        assert_eq!(
            names(Request::new().domain_not_in(["fake.test"])),
            Vec::<String>::new()
        );
        assert!(
            names(Request::new().local("x")).is_empty(),
            "fakes do not take a custom local"
        );
    }

    #[test]
    fn bad_local_part_is_refused_before_routing() {
        let p = pool(vec![FakeProvider::new("a")]);
        assert!(matches!(
            p.candidates(&Request::new().local("a/../b")),
            Err(Error::NotSupported(_))
        ));
    }

    #[test]
    fn ranking_prefers_healthy_then_fast_then_wide() {
        const WIDE: Capabilities = Capabilities {
            domain_count: 9,
            ..FAKE_CAPS
        };
        let p = pool(vec![
            FakeProvider::new("a"),
            FakeProvider::new("b").caps(WIDE),
            FakeProvider::new("c"),
        ]);
        let h = p.registry().health();
        h.record_success("a", Duration::from_secs(2));
        h.record_success("c", Duration::from_secs(1));
        h.record_success("b", Duration::from_secs(1));
        let names: Vec<_> = p
            .candidates(&Request::new())
            .unwrap()
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        assert_eq!(names, ["b", "c", "a"]);
    }

    #[tokio::test(start_paused = true)]
    async fn hedge_beats_a_slow_leader() {
        let reg = {
            let mut r = Registry::new([], Arc::new(HealthStore::new()));
            r.insert(Arc::new(
                FakeProvider::new("a").slow(Duration::from_secs(30)),
            ));
            r.insert(Arc::new(
                FakeProvider::new("b").slow(Duration::from_millis(100)),
            ));
            Arc::new(r)
        };
        let p = Pool::new(reg).with_hedge(Some(Hedge::default()));
        let started = tokio::time::Instant::now();
        let (prov, _) = p.acquire(&Request::new()).await.unwrap();
        assert_eq!(prov.name(), "b");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn blocked_domain_moves_on() {
        let p = pool(vec![
            FakeProvider::new("a").generate_with(|_| Ok(Address::new("x@blocked.test", "a"))),
            FakeProvider::new("b"),
        ]);
        let (prov, _) = p
            .acquire(&Request::new().domain_not_in(["BLOCKED.test"]))
            .await
            .unwrap();
        assert_eq!(prov.name(), "b");
    }
}
