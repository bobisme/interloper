//! Two instances, one Postgres. Runs only with `INTERLOPER_TEST_DATABASE_URL`
//! set; each test uses its own provider and address names, so runs against a
//! shared database cannot see each other.

use std::sync::Arc;
use std::time::Duration;

use interloper::health::{Status, Tier};
use interloper::model::Capabilities;
use interloper::testing::{FAKE_CAPS, FakeProvider};
use interloper::{Address, Error, HealthStore, Interloper, MessageRow, Registry, Request};

use crate::fleet::{HealthSync, test_database_url};
use crate::service::Service;
use crate::store::Store;

const STALE: Duration = Duration::from_secs(15);

fn tag() -> String {
    format!("{:x}", rand::random::<u64>())
}

/// A provider name unique to this run. Leaked: `FakeProvider` wants a
/// `&'static str`, and a test process is short-lived.
fn unique(prefix: &str, tag: &str) -> &'static str {
    Box::leak(format!("{prefix}-{tag}").into_boxed_str())
}

struct Instance {
    service: Arc<Service>,
    sync: Arc<HealthSync>,
    health: Arc<HealthStore>,
}

async fn instance(url: &str, id: String, provider: FakeProvider) -> Instance {
    let health = Arc::new(HealthStore::new());
    let mut reg = Registry::new([], health.clone());
    reg.insert(Arc::new(provider));
    let il = Interloper::with_registry(reg).with_hedge(None);
    let store = Store::postgres(url).await.expect("postgres");
    let sync = HealthSync::new(store.pg_pool().unwrap().clone(), health.clone(), id, STALE);
    sync.load().await.unwrap();
    let service = Service::with_fleet(il, store, Some(sync.clone()));
    Instance {
        service,
        sync,
        health,
    }
}

const STATEFUL: Capabilities = Capabilities {
    needs_state: true,
    poll_interval: Duration::from_millis(5),
    ..FAKE_CAPS
};

#[tokio::test]
async fn b_serves_an_address_a_issued() {
    let Some(url) = test_database_url() else {
        eprintln!("skipped: INTERLOPER_TEST_DATABASE_URL is unset");
        return;
    };
    let t = tag();
    let name = unique("fleet", &t);
    let value = format!("Inbox-{t}@fake.test");
    let issued = value.clone();
    // A issues; it holds no mail. B's copy of the same provider has the
    // mailbox, and needs the state A was issued to open it.
    let a_provider = FakeProvider::new(name)
        .caps(STATEFUL)
        .generate_with(move |_| Ok(Address::new(&issued, name).with_state("jwt-from-a")));
    let b_provider = FakeProvider::new(name)
        .caps(STATEFUL)
        .pages([vec![MessageRow::new("m1", "s", "Code")]])
        .bodies([FakeProvider::message(
            "m1",
            "Your code",
            "Your verification code is 771204",
        )]);
    let a = instance(&url, format!("a-{t}"), a_provider).await;
    let b = instance(&url, format!("b-{t}"), b_provider).await;

    let addr = a.service.create(&Request::default()).await.unwrap();
    assert_eq!(addr.value, value);

    // Any case: the key is the lowercased address.
    let inbox = b.service.inbox(&value.to_uppercase()).await.unwrap();
    assert_eq!(inbox.address().state.as_deref(), Some("jwt-from-a"));
    let rows = inbox.messages().await.unwrap();
    assert_eq!(rows.len(), 1);
    let (m, code) = b.service.get_message(&value, "m1").await.unwrap();
    assert_eq!(m.id, "m1");
    assert_eq!(code.as_deref(), Some("771204"));
    assert!(matches!(
        b.service.inbox(&format!("nobody-{t}@fake.test")).await,
        Err(crate::error::ApiError::UnknownAddress)
    ));
}

#[tokio::test]
async fn quarantine_is_fleet_wide_both_ways() {
    let Some(url) = test_database_url() else {
        eprintln!("skipped: INTERLOPER_TEST_DATABASE_URL is unset");
        return;
    };
    let t = tag();
    let name = unique("quar", &t);
    let a = instance(&url, format!("a-{t}"), FakeProvider::new(name)).await;
    let b = instance(&url, format!("b-{t}"), FakeProvider::new(name)).await;

    a.health
        .record_error(name, &Error::drift(name, "messages[0].id", "null"));
    assert_eq!(a.health.status(name), Status::Quarantined);
    a.sync.sync().await.unwrap();
    b.sync.sync().await.unwrap();
    assert_eq!(b.health.status(name), Status::Quarantined);
    assert_eq!(b.health.tier(name), None);
    assert!(
        b.service.create(&Request::default()).await.is_err(),
        "B must not route to a provider A quarantined"
    );

    // Cleared on B: A follows on its next sync and does not resurrect it.
    assert!(b.service.clear_quarantine(name).await.unwrap());
    assert_eq!(b.health.tier(name), Some(Tier::Healthy));
    a.sync.sync().await.unwrap();
    assert_eq!(a.health.status(name), Status::Ok);
    a.sync.sync().await.unwrap();
    b.sync.sync().await.unwrap();
    assert_eq!(b.health.status(name), Status::Ok);
    assert!(!b.service.clear_quarantine(name).await.unwrap());

    // A restarted instance adopts the table, not its own stale quarantine.
    a.health.quarantine(name, "drift");
    a.sync.sync().await.unwrap();
    b.sync.clear_quarantine(name).await.unwrap();
    let a2 = instance(&url, format!("a-{t}"), FakeProvider::new(name)).await;
    assert_eq!(a2.health.status(name), Status::Ok);
}

#[tokio::test]
async fn a_fresh_peer_failure_keeps_b_from_repeating_it() {
    let Some(url) = test_database_url() else {
        eprintln!("skipped: INTERLOPER_TEST_DATABASE_URL is unset");
        return;
    };
    let t = tag();
    let name = unique("down", &t);
    let a = instance(&url, format!("a-{t}"), FakeProvider::new(name)).await;
    let b = instance(&url, format!("b-{t}"), FakeProvider::new(name)).await;

    a.health.record_error(name, &Error::down(name, "502"));
    a.sync.sync().await.unwrap();
    b.sync.sync().await.unwrap();
    assert_eq!(b.health.tier(name), None, "B has no evidence; A's counts");
    assert!(b.sync.view().vetoes(name, None, jiff::Timestamp::now()));
    // B's own snapshot is untouched: the verdict is A's, not B's.
    assert!(b.health.get(name).is_none());

    // B's own success ties the vote, and ties route.
    b.health.record_success(name, Duration::from_millis(5));
    assert_eq!(b.health.tier(name), Some(Tier::Healthy));

    // A goes quiet: its row ages past the staleness window and stops voting.
    let c = instance(&url, format!("c-{t}"), FakeProvider::new(name)).await;
    c.sync.sync().await.unwrap();
    assert_eq!(c.health.tier(name), None);
    let pool = c.service.store.pg_pool().unwrap().get().await.unwrap();
    pool.execute(
        "update instance_health set updated_at = now() - interval '1 hour'
         where instance_id = $1",
        &[&format!("a-{t}")],
    )
    .await
    .unwrap();
    c.sync.sync().await.unwrap();
    assert_eq!(c.health.tier(name), Some(Tier::Healthy));
}
