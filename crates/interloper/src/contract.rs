//! The contract every provider must satisfy, run against replayed fixtures.
//!
//! An adapter's test module invokes [`contract_tests!`] with a constructor
//! that builds the provider over a `testing::Fixtures` wire, and inherits the
//! whole suite. Fixtures must hold at least one message so the body-read path
//! is exercised.
//!
//! Record fixtures through interloper's own transport (`interloper record`,
//! or `Transport` in a scratch test), never with curl: the two send different
//! `Accept` headers and some backends answer them with different shapes.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use crate::error::Error;
use crate::model::Address;
use crate::provider::{GenerateOptions, Provider};
use crate::registry::ProviderSpec;

pub async fn declares_capabilities(spec: ProviderSpec, p: Arc<dyn Provider>) {
    let caps = p.caps();
    assert_eq!(p.name(), spec.name, "spec name and provider name disagree");
    assert!(!p.name().is_empty());
    assert!(
        p.name()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "provider names are lowercase ascii: {}",
        p.name()
    );
    assert!(
        !caps.kind.is_empty(),
        "a provider must serve at least one kind"
    );
    assert!(
        !caps.sites.is_empty(),
        "a provider must declare its front doors"
    );
    assert!(
        caps.domain_count >= caps.domains.len(),
        "domain_count must cover the declared domains"
    );
    assert!(caps.max_concurrency >= 1);
    // A backend needing a throwaway session per request keys its inbox on
    // something the session used to carry, so that identity must travel in
    // Address::state; without it list() quietly returns an empty inbox.
    if caps.fresh_session {
        assert!(
            caps.needs_state,
            "{}: fresh_session without needs_state",
            p.name()
        );
    }
    assert!(
        !caps.push,
        "{}: no push provider exists yet; write its contract first",
        p.name()
    );
}

pub async fn generate_returns_an_owned_address(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    assert!(a.value.contains('@'), "{}", a.value);
    assert_eq!(a.provider, p.name());
    if p.caps().needs_state {
        assert!(
            a.state.is_some(),
            "{} declares needs_state but issued none",
            p.name()
        );
    }
    if !p.caps().domains.is_empty() {
        assert!(
            p.caps()
                .domains
                .iter()
                .any(|d| d.eq_ignore_ascii_case(a.domain())),
            "{} issued {} outside its declared domains",
            p.name(),
            a.value
        );
    }
}

pub async fn two_generates_are_distinct(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let b = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    assert_ne!(
        a.value,
        b.value,
        "{} issued {} twice. If the fixture returns one recorded generate for every call, \
         route a sequence; if the backend keys inboxes on a session cookie, set fresh_session \
         and replay identity from Address::state.",
        p.name(),
        a.value
    );
}

pub async fn listing_is_a_list_and_monotonic(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let first: Vec<String> = p
        .list(&a)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.id)
        .collect();
    let second: Vec<String> = p
        .list(&a)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.id)
        .collect();
    for id in &first {
        assert!(
            second.contains(id),
            "older id {id} vanished from a later listing"
        );
    }
}

pub async fn get_reads_a_listed_message(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let rows = p.list(&a).await.expect("list");
    assert!(
        !rows.is_empty(),
        "{}: fixtures must list at least one message so get() is exercised",
        p.name()
    );
    let m = p.get(&a, &rows[0].id).await.expect("get");
    assert_eq!(m.id, rows[0].id);
    assert!(
        !m.text.trim().is_empty() || !m.html.trim().is_empty(),
        "{}: message has neither text nor html",
        p.name()
    );
}

/// The inbox survives a trip through the portable token, as it must when a
/// second process resumes it.
pub async fn token_round_trip_keeps_the_inbox(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let resumed = Address::from_token(&a.to_token()).expect("token");
    assert_eq!(resumed, a);
    p.list(&resumed).await.expect("list from a resumed address");
}

pub async fn delete_agrees_with_caps(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let rows = p.list(&a).await.expect("list");
    let id = rows.first().map_or("missing", |r| r.id.as_str());
    let result = p.delete(&a, id).await;
    if p.caps().delete {
        assert!(
            !matches!(result, Err(Error::NotSupported(_))),
            "{} declares delete but refuses it",
            p.name()
        );
    } else {
        assert!(
            matches!(result, Err(Error::NotSupported(_))),
            "{} implements delete but does not declare it",
            p.name()
        );
    }
}

pub async fn watch_yields_listed_mail(p: Arc<dyn Provider>) {
    let a = p
        .generate(&GenerateOptions::default())
        .await
        .expect("generate");
    let mut s = p.watch(&a, Some(Duration::ZERO));
    let first = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .expect("watch produced nothing")
        .expect("stream ended")
        .expect("watch error");
    assert!(!first.id.is_empty());
}

pub async fn options_are_honoured_or_refused(p: Arc<dyn Provider>) {
    let opts = GenerateOptions {
        local: Some("interlopertest".into()),
        ..Default::default()
    };
    let result = p.generate(&opts).await;
    if p.caps().custom_local {
        // The fixture may answer with a recorded address; only the backends
        // that build the address locally can be held to the local part.
        assert!(
            result.is_ok(),
            "{} declares custom_local but refused one: {result:?}",
            p.name()
        );
    }
    let unserved = GenerateOptions {
        domain: Some("not-a-domain-anyone-serves.test".into()),
        ..Default::default()
    };
    if !p.caps().domains.is_empty() {
        assert!(
            matches!(p.generate(&unserved).await, Err(Error::NotSupported(_))),
            "{} accepted a domain it does not declare",
            p.name()
        );
    }
}

/// Expand the contract suite for one provider. `$spec` is its `ProviderSpec`;
/// `$build` is an expression of type `Arc<dyn Provider>` built over fixtures,
/// evaluated fresh for every test.
#[macro_export]
macro_rules! contract_tests {
    ($spec:expr, $build:expr) => {
        mod contract {
            #[allow(unused_imports)]
            use super::*;
            use $crate::contract as c;

            fn provider() -> ::std::sync::Arc<dyn $crate::Provider> {
                $build
            }

            #[tokio::test]
            async fn declares_capabilities() {
                c::declares_capabilities($spec, provider()).await
            }
            #[tokio::test]
            async fn generate_returns_an_owned_address() {
                c::generate_returns_an_owned_address(provider()).await
            }
            #[tokio::test]
            async fn two_generates_are_distinct() {
                c::two_generates_are_distinct(provider()).await
            }
            #[tokio::test]
            async fn listing_is_a_list_and_monotonic() {
                c::listing_is_a_list_and_monotonic(provider()).await
            }
            #[tokio::test]
            async fn get_reads_a_listed_message() {
                c::get_reads_a_listed_message(provider()).await
            }
            #[tokio::test]
            async fn token_round_trip_keeps_the_inbox() {
                c::token_round_trip_keeps_the_inbox(provider()).await
            }
            #[tokio::test]
            async fn delete_agrees_with_caps() {
                c::delete_agrees_with_caps(provider()).await
            }
            #[tokio::test]
            async fn watch_yields_listed_mail() {
                c::watch_yields_listed_mail(provider()).await
            }
            #[tokio::test]
            async fn options_are_honoured_or_refused() {
                c::options_are_honoured_or_refused(provider()).await
            }
        }
    };
}
