//! The provider protocol: one disposable-mail backend.

use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::BoxStream;
use regex::Regex;

use crate::error::{Error, Result};
use crate::model::{Address, Capabilities, Kind, Message, MessageRow};

// RFC 5321 allows more, but no backend here needs it.
static LOCAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._+-]{1,64}$").unwrap());
static DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$").unwrap());

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerateOptions {
    pub kind: Option<Kind>,
    pub local: Option<String>,
    pub domain: Option<String>,
}

impl GenerateOptions {
    /// Adapters build URL paths and queries from the address, so a chosen
    /// local part or domain must not be able to add a path segment, a query
    /// or a header line. Checked once, here, for every adapter.
    pub fn validate(&self) -> Result<()> {
        if let Some(l) = &self.local
            && !LOCAL.is_match(l)
        {
            return Err(Error::unsupported(format!(
                "not a usable local part: {l:?}"
            )));
        }
        if let Some(d) = &self.domain
            && !DOMAIN.is_match(d)
        {
            return Err(Error::unsupported(format!("not a usable domain: {d:?}")));
        }
        Ok(())
    }
}

/// One disposable-mail backend.
///
/// Implementations hold protocol knowledge and nothing else: no client, no
/// retry logic, no HTML parsing. If one needs more than about forty lines of
/// non-domain code, core is missing something.
#[async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;
    fn caps(&self) -> &Capabilities;

    async fn generate(&self, opts: &GenerateOptions) -> Result<Address>;

    /// Inbox headers. An empty inbox is `Ok(vec![])`, never an error.
    async fn list(&self, address: &Address) -> Result<Vec<MessageRow>>;

    async fn get(&self, address: &Address, id: &str) -> Result<Message>;

    async fn delete(&self, _address: &Address, _id: &str) -> Result<()> {
        Err(Error::unsupported(format!(
            "{} cannot delete messages",
            self.name()
        )))
    }

    /// New mail as it arrives. This default polls; a push backend overrides
    /// it, and callers cannot tell which they got.
    fn watch<'a>(
        &'a self,
        address: &'a Address,
        poll: Option<Duration>,
    ) -> BoxStream<'a, Result<Message>> {
        poll_watch(self, address, poll)
    }
}

/// How many consecutive transient failures a watch rides out before giving
/// up. cowbird ended the stream on the first one, so a single 502 during a
/// two-minute `otp()` wait threw the whole wait away.
pub const WATCH_TOLERANCE: u32 = 5;

/// The polling implementation of [`Provider::watch`], usable by wrappers so
/// their own `list`/`get` are what get called.
pub fn poll_watch<'a, P: Provider + ?Sized>(
    p: &'a P,
    address: &'a Address,
    poll: Option<Duration>,
) -> BoxStream<'a, Result<Message>> {
    let interval = poll.unwrap_or(p.caps().poll_interval);
    Box::pin(async_stream::stream! {
        let mut seen: HashSet<String> = HashSet::new();
        let mut strikes = 0u32;
        loop {
            let mut failed: Option<Error> = None;
            match p.list(address).await {
                Ok(rows) => {
                    for row in rows {
                        if seen.contains(&row.id) {
                            continue;
                        }
                        if row.locked {
                            seen.insert(row.id);
                            continue;
                        }
                        match p.get(address, &row.id).await {
                            Ok(m) => {
                                seen.insert(row.id);
                                yield Ok(m);
                            }
                            // Listed, then expired before we read it. One gone
                            // message must not end the stream.
                            Err(Error::MessageGone { .. } | Error::MessageLocked { .. }) => {
                                seen.insert(row.id);
                            }
                            // Not marked seen: retried next round.
                            Err(e) if e.reroutable() => failed = Some(e),
                            Err(e) => {
                                yield Err(e);
                                return;
                            }
                        }
                    }
                }
                Err(e) if e.reroutable() => failed = Some(e),
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
            match failed {
                Some(e) => {
                    strikes += 1;
                    if strikes >= WATCH_TOLERANCE {
                        yield Err(e);
                        return;
                    }
                    tracing::debug!(provider = p.name(), strikes, error = %e, "watch riding out a transient failure");
                }
                None => strikes = 0,
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeProvider;
    use futures::StreamExt;

    #[test]
    fn options_refuse_injection() {
        for bad in ["a/b", "a?b", "a\r\nb", "", &"x".repeat(65)] {
            let o = GenerateOptions {
                local: Some(bad.into()),
                ..Default::default()
            };
            assert!(o.validate().is_err(), "{bad:?}");
        }
        let o = GenerateOptions {
            domain: Some("evil.test/x".into()),
            ..Default::default()
        };
        assert!(o.validate().is_err());
        let o = GenerateOptions {
            local: Some("a.b+c".into()),
            domain: Some("x.y.test".into()),
            ..Default::default()
        };
        assert!(o.validate().is_ok());
    }

    #[tokio::test]
    async fn watch_survives_transient_list_failures() {
        let p = FakeProvider::new("f").list_with(|n| match n {
            0 | 1 => Err(Error::down("f", "502")),
            _ => Ok(vec![MessageRow::new("m1", "s", "hi")]),
        });
        let a = Address::new("a@fake.test", "f");
        let mut s = p.watch(&a, Some(Duration::ZERO));
        let m = s.next().await.unwrap().unwrap();
        assert_eq!(m.id, "m1");
    }

    #[tokio::test]
    async fn watch_gives_up_after_tolerance() {
        let p = FakeProvider::new("f").list_with(|_| Err(Error::down("f", "502")));
        let a = Address::new("a@fake.test", "f");
        let mut s = p.watch(&a, Some(Duration::ZERO));
        assert!(matches!(
            s.next().await,
            Some(Err(Error::ProviderDown { .. }))
        ));
        assert!(s.next().await.is_none());
    }

    #[tokio::test]
    async fn watch_yields_each_message_once_and_skips_locked() {
        let mut locked = MessageRow::new("m0", "s", "paywalled");
        locked.locked = true;
        let p = FakeProvider::new("f").pages([
            vec![locked.clone(), MessageRow::new("m1", "s", "a")],
            vec![
                locked,
                MessageRow::new("m1", "s", "a"),
                MessageRow::new("m2", "s", "b"),
            ],
        ]);
        let a = Address::new("a@fake.test", "f");
        let ids: Vec<String> = p
            .watch(&a, Some(Duration::ZERO))
            .take(2)
            .map(|m| m.unwrap().id)
            .collect()
            .await;
        assert_eq!(ids, ["m1", "m2"]);
    }
}
