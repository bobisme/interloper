//! Fleet mode: several servers sharing one Postgres.
//!
//! The address store is the easy half (see [`crate::store`]). This is the
//! other half: health. Two tables, because health holds two kinds of fact.
//!
//! * `instance_health`: one row per instance, its whole [`HealthStore`]
//!   snapshot plus `updated_at` (stamped by the database clock, so instance
//!   clock skew cannot make a dead peer look alive). Each row has exactly one
//!   writer, so no locking is needed. Rows older than `stale_after` are
//!   ignored: a crashed or scaled-down instance stops voting by itself.
//! * `provider_quarantine`: global. Schema drift means the adapter is wrong
//!   everywhere it runs, so the first instance to see it inserts a row (later
//!   inserts are no-ops), every instance adopts it, and deleting the row
//!   (`DELETE /v1/providers/{name}/quarantine` on any instance) clears it
//!   fleet-wide.
//!
//! # The routing rule
//!
//! cowbird wrote per-instance rows but never read peers' back, so every
//! instance paid its own failed requests (and timeouts) to learn that a
//! provider had died. Here peers' fresh rows feed routing through a
//! [`TierOverlay`], under a rule chosen so a peer can save us a failed call
//! but can never cost us much:
//!
//! 1. **Peers only demote.** If this instance excludes a provider, it stays
//!    excluded; no peer can route us to something we saw fail.
//! 2. **Each informed instance votes, this one included.** An entry votes
//!    *down* while it is DOWN inside its cooldown (`retry_at` in the future),
//!    and *up* when it is OK or SLOW. Everything else abstains: no entry,
//!    probation (cooldown over, outcome unknown), quarantine (the global
//!    table handles that), and evidence older than [`EVIDENCE_HORIZON`].
//! 3. **Egress-specific failures abstain.** A DOWN caused by a challenge
//!    (`needs_residential_ip`) is about that instance's IP; fan-out exists to
//!    have several, so it must not take the provider away from the others.
//! 4. **Strict majority demotes; ties route.** The provider leaves routing
//!    while down votes outnumber up votes. A peer that just saw a failure
//!    keeps an uninformed instance from repeating it; a single peer cannot
//!    overrule an instance that saw a success. Being wrong toward "up" costs
//!    one failed call (the local breaker then trips); being wrong toward
//!    "down" is bounded by the voters' own cooldowns (at most 15 minutes).
//!    Down votes are re-checked against their `retry_at` at routing time,
//!    so a peer's verdict lapses on schedule even between syncs.
//!
//! Peers' votes never enter this instance's snapshot, so a verdict cannot
//! echo around the fleet and outlive the measurement behind it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadpool_postgres::Pool;
use interloper::HealthStore;
use interloper::health::{COOLDOWN_MAX, ProviderHealth, Status, Tier, TierOverlay};
use jiff::{SignedDuration, Timestamp};

use crate::store::StoreUnavailable;

/// Evidence older than this abstains. The longest a DOWN can last, so an old
/// success cannot outvote a failure that is still inside its cooldown for
/// longer than that failure could have lasted anyway.
pub const EVIDENCE_HORIZON: Duration = COOLDOWN_MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote {
    Up,
    /// Down until the voter's own cooldown ends.
    Down {
        until: Timestamp,
    },
}

/// What one instance's entry says about a provider; `None` abstains.
pub fn vote(e: &ProviderHealth, now: Timestamp) -> Option<Vote> {
    let checked = e.last_checked?;
    let horizon = SignedDuration::try_from(EVIDENCE_HORIZON).unwrap_or(SignedDuration::MAX);
    if now.duration_since(checked) > horizon {
        return None;
    }
    match e.status {
        Status::Ok | Status::Slow => Some(Vote::Up),
        Status::Down if e.needs_residential_ip => None,
        Status::Down => match e.retry_at {
            Some(until) if until > now => Some(Vote::Down { until }),
            _ => None,
        },
        Status::Quarantined => None,
    }
}

/// Every fresh peer's votes, by provider.
pub fn peer_votes(
    peers: &[HashMap<String, ProviderHealth>],
    now: Timestamp,
) -> HashMap<String, Vec<Vote>> {
    let mut out: HashMap<String, Vec<Vote>> = HashMap::new();
    for snapshot in peers {
        for (provider, e) in snapshot {
            if let Some(v) = vote(e, now) {
                out.entry(provider.clone()).or_default().push(v);
            }
        }
    }
    out
}

/// The rule in the module docs: the tier to route at, given the local entry,
/// the local verdict and the peers' votes.
pub fn decide(
    local: Option<&ProviderHealth>,
    tier: Option<Tier>,
    peers: &[Vote],
    now: Timestamp,
) -> Option<Tier> {
    let tier = tier?;
    let mut up = 0usize;
    let mut down = 0usize;
    let own = local.and_then(|e| vote(e, now));
    for v in own.iter().chain(peers) {
        match v {
            Vote::Up => up += 1,
            Vote::Down { until } if *until > now => down += 1,
            Vote::Down { .. } => {}
        }
    }
    if down > up { None } else { Some(tier) }
}

/// Peers' votes as of the last sync, consulted by [`HealthStore::tier`].
#[derive(Default)]
pub struct PeerView {
    votes: Mutex<HashMap<String, Vec<Vote>>>,
}

impl PeerView {
    pub fn set(&self, votes: HashMap<String, Vec<Vote>>) {
        *self.votes.lock().unwrap() = votes;
    }

    /// Whether the peers alone take a locally routable provider out.
    pub fn vetoes(&self, provider: &str, local: Option<&ProviderHealth>, now: Timestamp) -> bool {
        let votes = self.votes.lock().unwrap();
        let peers = votes.get(provider).map_or(&[][..], Vec::as_slice);
        // Only what the peers change: a provider our own vote already holds
        // down is not theirs to report.
        decide(local, Some(Tier::Healthy), &[], now).is_some()
            && decide(local, Some(Tier::Healthy), peers, now).is_none()
    }
}

impl TierOverlay for PeerView {
    fn adjust(
        &self,
        provider: &str,
        local: Option<&ProviderHealth>,
        tier: Option<Tier>,
        now: Timestamp,
    ) -> Option<Tier> {
        let votes = self.votes.lock().unwrap();
        match votes.get(provider) {
            Some(peers) => decide(local, tier, peers, now),
            None => tier,
        }
    }
}

use crate::store::unavailable as db;

/// Publishes this instance's health, reads its peers', and keeps quarantine
/// in step with the global table.
pub struct HealthSync {
    pool: Pool,
    health: Arc<HealthStore>,
    instance: String,
    stale_after: Duration,
    view: Arc<PeerView>,
    /// Quarantines already accounted for against the table: inserted by us,
    /// or adopted from it. These are never re-inserted, or an instance that
    /// adopted a quarantine would resurrect the row an operator just deleted.
    published: Mutex<HashSet<String>>,
    /// Serializes `sync` and `clear_quarantine`, so a clear cannot interleave
    /// with a sync that snapshotted the quarantine before it.
    lock: tokio::sync::Mutex<()>,
}

impl HealthSync {
    /// Installs the peer overlay on `health`. `stale_after` is how old a
    /// peer's row may be and still vote.
    pub fn new(
        pool: Pool,
        health: Arc<HealthStore>,
        instance: impl Into<String>,
        stale_after: Duration,
    ) -> Arc<Self> {
        let view = Arc::new(PeerView::default());
        health.set_overlay(Some(view.clone()));
        Arc::new(HealthSync {
            pool,
            health,
            instance: instance.into(),
            stale_after,
            view,
            published: Mutex::new(HashSet::new()),
            lock: tokio::sync::Mutex::new(()),
        })
    }

    pub fn instance(&self) -> &str {
        &self.instance
    }

    pub fn view(&self) -> &PeerView {
        &self.view
    }

    /// At startup: seed from this instance's own row, then adopt the table's
    /// quarantines. The table is the authority here: a local quarantine it
    /// lacks was cleared while this instance was away.
    pub async fn load(&self) -> Result<(), StoreUnavailable> {
        let _g = self.lock.lock().await;
        let client = self.pool.get().await.map_err(db)?;
        let row = client
            .query_opt(
                "select snapshot from instance_health where instance_id = $1",
                &[&self.instance],
            )
            .await
            .map_err(db)?;
        if let Some(row) = row {
            let v: serde_json::Value = row.get(0);
            if let Ok(snap) = serde_json::from_value::<HashMap<String, ProviderHealth>>(v) {
                self.health.seed(snap);
            }
        }
        let accounted: HashSet<String> = self
            .health
            .snapshot()
            .into_iter()
            .filter(|(_, e)| e.status == Status::Quarantined)
            .map(|(k, _)| k)
            .collect();
        self.reconcile(&client, accounted).await
    }

    /// One round: publish our row and new quarantines, refresh the peer view,
    /// reconcile quarantines.
    pub async fn sync(&self) -> Result<(), StoreUnavailable> {
        let _g = self.lock.lock().await;
        let client = self.pool.get().await.map_err(db)?;
        let snapshot = self.health.snapshot();
        let body = serde_json::to_value(&snapshot).expect("health serializes");
        client
            .execute(
                "insert into instance_health (instance_id, snapshot, updated_at)
                 values ($1, $2, now())
                 on conflict (instance_id) do update
                 set snapshot = excluded.snapshot, updated_at = now()",
                &[&self.instance, &body],
            )
            .await
            .map_err(db)?;
        let mut accounted = self.published.lock().unwrap().clone();
        for (provider, e) in &snapshot {
            if e.status == Status::Quarantined && !accounted.contains(provider) {
                // First writer wins: a later instance noticing the same drift
                // must not overwrite who saw it first, or when.
                client
                    .execute(
                        "insert into provider_quarantine (provider, reason, instance_id)
                         values ($1, $2, $3) on conflict (provider) do nothing",
                        &[
                            provider,
                            &e.last_failure.as_deref().unwrap_or("quarantined"),
                            &self.instance,
                        ],
                    )
                    .await
                    .map_err(db)?;
                accounted.insert(provider.clone());
            }
        }
        let rows = client
            .query(
                "select snapshot from instance_health
                 where instance_id <> $1
                   and updated_at > now() - make_interval(secs => $2)",
                &[&self.instance, &self.stale_after.as_secs_f64()],
            )
            .await
            .map_err(db)?;
        let peers: Vec<HashMap<String, ProviderHealth>> = rows
            .into_iter()
            .filter_map(|r| serde_json::from_value(r.get::<_, serde_json::Value>(0)).ok())
            .collect();
        self.view.set(peer_votes(&peers, Timestamp::now()));
        self.reconcile(&client, accounted).await
    }

    /// Match local quarantines to the table in both directions. Only a
    /// quarantine in `accounted` is lifted when the table lacks it; one that
    /// appeared locally after this round's snapshot has not been published
    /// yet, and lifting it would lose a fresh drift (cowbird lifted it).
    async fn reconcile(
        &self,
        client: &deadpool_postgres::Client,
        accounted: HashSet<String>,
    ) -> Result<(), StoreUnavailable> {
        let rows = client
            .query("select provider, reason from provider_quarantine", &[])
            .await
            .map_err(db)?;
        let mut table = HashSet::new();
        for r in rows {
            let provider: String = r.get(0);
            let reason: String = r.get(1);
            if self.health.status(&provider) != Status::Quarantined {
                self.health.quarantine(&provider, &reason);
            }
            table.insert(provider);
        }
        for (provider, e) in self.health.snapshot() {
            if e.status == Status::Quarantined
                && !table.contains(&provider)
                && accounted.contains(&provider)
            {
                self.health.unquarantine(&provider);
            }
        }
        *self.published.lock().unwrap() = table;
        Ok(())
    }

    /// Clear a quarantine fleet-wide. Returns whether anything was cleared,
    /// here or in the table. Peers lift theirs on their next sync.
    pub async fn clear_quarantine(&self, provider: &str) -> Result<bool, StoreUnavailable> {
        let _g = self.lock.lock().await;
        let client = self.pool.get().await.map_err(db)?;
        let n = client
            .execute(
                "delete from provider_quarantine where provider = $1",
                &[&provider],
            )
            .await
            .map_err(db)?;
        self.published.lock().unwrap().remove(provider);
        let local = self.health.unquarantine(provider);
        Ok(n > 0 || local)
    }
}

#[cfg(test)]
pub(crate) fn test_database_url() -> Option<String> {
    std::env::var("INTERLOPER_TEST_DATABASE_URL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: i64) -> Timestamp {
        Timestamp::from_second(1_800_000_000 + s).unwrap()
    }

    fn ok_at(s: i64) -> ProviderHealth {
        ProviderHealth {
            status: Status::Ok,
            last_checked: Some(t(s)),
            ..Default::default()
        }
    }

    fn down_at(s: i64, until: i64) -> ProviderHealth {
        ProviderHealth {
            status: Status::Down,
            last_checked: Some(t(s)),
            failures: 1,
            retry_at: Some(t(until)),
            ..Default::default()
        }
    }

    #[test]
    fn votes() {
        let now = t(0);
        assert_eq!(vote(&ok_at(-5), now), Some(Vote::Up));
        assert_eq!(
            vote(&down_at(-5, 25), now),
            Some(Vote::Down { until: t(25) })
        );
        // Probation, quarantine, never checked, and stale evidence abstain.
        assert_eq!(vote(&down_at(-60, -30), now), None);
        let q = ProviderHealth {
            status: Status::Quarantined,
            ..ok_at(-1)
        };
        assert_eq!(vote(&q, now), None);
        assert_eq!(vote(&ProviderHealth::default(), now), None);
        assert_eq!(vote(&ok_at(-(15 * 60) - 1), now), None);
        // A challenge is about the voter's egress IP, not the provider.
        let challenged = ProviderHealth {
            needs_residential_ip: true,
            ..down_at(-5, 25)
        };
        assert_eq!(vote(&challenged, now), None);
    }

    #[test]
    fn uninformed_instance_follows_a_peer_that_saw_failure() {
        let now = t(0);
        let peers = [Vote::Down { until: t(25) }];
        assert_eq!(decide(None, Some(Tier::Healthy), &peers, now), None);
        // ...until the peer's own cooldown lapses, without another sync.
        assert_eq!(
            decide(None, Some(Tier::Healthy), &peers, t(26)),
            Some(Tier::Healthy)
        );
    }

    #[test]
    fn ties_route_and_majorities_demote() {
        let now = t(0);
        let local = ok_at(-10);
        let one = [Vote::Down { until: t(25) }];
        assert_eq!(
            decide(Some(&local), Some(Tier::Healthy), &one, now),
            Some(Tier::Healthy),
            "one peer cannot overrule our own success"
        );
        let two = [Vote::Down { until: t(25) }, Vote::Down { until: t(40) }];
        assert_eq!(decide(Some(&local), Some(Tier::Slow), &two, now), None);
        let mixed = [
            Vote::Down { until: t(25) },
            Vote::Down { until: t(40) },
            Vote::Up,
        ];
        assert_eq!(
            decide(Some(&local), Some(Tier::Healthy), &mixed, now),
            Some(Tier::Healthy)
        );
    }

    #[test]
    fn peers_never_promote() {
        let local = down_at(-1, 30);
        let peers = [Vote::Up, Vote::Up, Vote::Up];
        assert_eq!(decide(Some(&local), None, &peers, t(0)), None);
    }

    #[test]
    fn probation_keeps_its_tier_unless_outvoted() {
        let local = down_at(-60, -30);
        assert_eq!(
            decide(Some(&local), Some(Tier::Probation), &[Vote::Up], t(0)),
            Some(Tier::Probation)
        );
        assert_eq!(
            decide(
                Some(&local),
                Some(Tier::Probation),
                &[Vote::Down { until: t(9) }],
                t(0)
            ),
            None
        );
    }

    #[test]
    fn peer_votes_group_by_provider() {
        let now = t(0);
        let a = HashMap::from([
            ("p".to_string(), down_at(-1, 30)),
            ("q".to_string(), ok_at(-1)),
        ]);
        let b = HashMap::from([
            ("p".to_string(), down_at(-2, 20)),
            ("r".to_string(), ProviderHealth::default()),
        ]);
        let v = peer_votes(&[a, b], now);
        assert_eq!(v["p"].len(), 2);
        assert_eq!(v["q"], vec![Vote::Up]);
        assert!(!v.contains_key("r"));
    }

    #[test]
    fn overlay_reaches_routing() {
        let h = Arc::new(HealthStore::new());
        let view = Arc::new(PeerView::default());
        h.set_overlay(Some(view.clone()));
        assert!(h.tier("p").is_some());
        let until = Timestamp::now()
            .checked_add(SignedDuration::from_secs(60))
            .unwrap();
        view.set(HashMap::from([("p".into(), vec![Vote::Down { until }])]));
        assert_eq!(h.tier("p"), None);
        assert!(view.vetoes("p", None, Timestamp::now()));
        // Our own fresh success ties the vote, and ties route.
        h.record_success("p", Duration::from_millis(10));
        assert_eq!(h.tier("p"), Some(Tier::Healthy));
        // The overlay is never part of the snapshot we publish.
        assert_eq!(h.snapshot()["p"].status, Status::Ok);
    }
}
