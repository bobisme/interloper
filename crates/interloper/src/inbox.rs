//! One address bound to its provider, and the wait-and-extract loops nearly
//! every caller actually wants.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;
use futures::stream::BoxStream;
use regex::Regex;

use crate::error::{Error, Result};
use crate::model::{Address, Message, MessageRow};
use crate::parse::extract_otp;
use crate::provider::Provider;

/// Which messages a wait should consider. Case-insensitive substrings.
#[derive(Debug, Clone, Default)]
pub struct MailFilter {
    pub from: Option<String>,
    pub subject: Option<String>,
}

impl MailFilter {
    pub fn from(mut self, sender: impl Into<String>) -> Self {
        self.from = Some(sender.into());
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn accepts(&self, m: &Message) -> bool {
        let has = |hay: &str, needle: &Option<String>| {
            needle
                .as_ref()
                .is_none_or(|n| hay.to_lowercase().contains(&n.to_lowercase()))
        };
        has(&m.sender, &self.from) && has(&m.subject, &self.subject)
    }
}

pub struct Inbox {
    provider: Arc<dyn Provider>,
    address: Address,
    issued: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox")
            .field("address", &self.address)
            .finish()
    }
}

impl Inbox {
    pub fn new(provider: Arc<dyn Provider>, address: Address) -> Self {
        Inbox {
            provider,
            address,
            issued: Mutex::new(Vec::new()),
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The email address itself.
    pub fn email(&self) -> &str {
        &self.address.value
    }

    /// A portable handle to resume this inbox in another process. Contains
    /// provider credentials.
    pub fn token(&self) -> String {
        self.address.to_token()
    }

    pub fn provider(&self) -> &Arc<dyn Provider> {
        &self.provider
    }

    pub async fn messages(&self) -> Result<Vec<MessageRow>> {
        self.provider.list(&self.address).await
    }

    pub async fn get(&self, id: &str) -> Result<Message> {
        self.provider.get(&self.address, id).await
    }

    pub async fn delete(&self, id: &str) -> Result<()> {
        self.provider.delete(&self.address, id).await
    }

    /// New mail as it arrives, each message once.
    pub fn watch(&self, poll: Option<Duration>) -> BoxStream<'_, Result<Message>> {
        Box::pin(self.provider.watch(&self.address, poll).inspect(|m| {
            if let Ok(m) = m {
                self.issued.lock().unwrap().push(m.id.clone());
            }
        }))
    }

    /// The first `extract(message)` that returns `Some`, among messages the
    /// filter accepts, or [`Error::Timeout`].
    pub async fn first<T>(
        &self,
        timeout: Duration,
        filter: &MailFilter,
        mut extract: impl FnMut(&Message) -> Option<T>,
    ) -> Result<T> {
        let search = async {
            let mut stream = self.watch(None);
            while let Some(m) = stream.next().await {
                let m = m?;
                if filter.accepts(&m)
                    && let Some(found) = extract(&m)
                {
                    return Ok(found);
                }
            }
            Err(Error::Timeout(format!(
                "mail stream for {} ended before a match",
                self.address.value
            )))
        };
        match tokio::time::timeout(timeout, search).await {
            Ok(r) => r,
            Err(_) => Err(Error::Timeout(format!(
                "no matching mail for {} within {}s",
                self.address.value,
                timeout.as_secs()
            ))),
        }
    }

    /// The first message the filter accepts.
    pub async fn wait(&self, timeout: Duration, filter: &MailFilter) -> Result<Message> {
        self.first(timeout, filter, |m| Some(m.clone())).await
    }

    /// The first one-time code. See [`crate::parse::extract_otp`].
    pub async fn otp(&self, timeout: Duration) -> Result<String> {
        self.otp_matching(timeout, &MailFilter::default(), None)
            .await
    }

    pub async fn otp_matching(
        &self,
        timeout: Duration,
        filter: &MailFilter,
        pattern: Option<&Regex>,
    ) -> Result<String> {
        self.first(timeout, filter, |m| {
            extract_otp(&m.subject, &m.text, pattern)
        })
        .await
    }

    /// The first link, optionally containing `needle`.
    pub async fn link(&self, timeout: Duration, needle: Option<&str>) -> Result<String> {
        self.link_matching(timeout, &MailFilter::default(), needle)
            .await
    }

    pub async fn link_matching(
        &self,
        timeout: Duration,
        filter: &MailFilter,
        needle: Option<&str>,
    ) -> Result<String> {
        self.first(timeout, filter, |m| {
            m.links
                .iter()
                .find(|h| needle.is_none_or(|n| h.contains(n)))
                .cloned()
        })
        .await
    }

    /// Best-effort cleanup of messages this inbox handed out. The address
    /// expires on its own anyway; failing to tidy up never fails the caller.
    pub async fn close(self) {
        if !self.provider.caps().delete {
            return;
        }
        let ids = std::mem::take(&mut *self.issued.lock().unwrap());
        for id in ids {
            let _ = self.provider.delete(&self.address, &id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Capabilities, MessageRow};
    use crate::testing::{FAKE_CAPS, FakeProvider};

    const FAST: Capabilities = Capabilities {
        poll_interval: Duration::from_millis(1),
        delete: true,
        ..FAKE_CAPS
    };

    fn inbox(p: FakeProvider) -> Inbox {
        Inbox::new(Arc::new(p.caps(FAST)), Address::new("a@fake.test", "fake"))
    }

    #[tokio::test]
    async fn otp_skips_mail_without_a_code() {
        let p = FakeProvider::new("fake")
            .pages([
                vec![MessageRow::new("1", "s", "welcome")],
                vec![
                    MessageRow::new("1", "s", "welcome"),
                    MessageRow::new("2", "s", "code"),
                ],
            ])
            .bodies([
                FakeProvider::message("1", "Welcome", "Thanks for joining"),
                FakeProvider::message("2", "Verify", "Your code is 551203"),
            ]);
        assert_eq!(
            inbox(p).otp(Duration::from_secs(5)).await.unwrap(),
            "551203"
        );
    }

    #[tokio::test]
    async fn filter_by_sender() {
        let mut a = FakeProvider::message("1", "Code", "code 111111");
        a.sender = "spam@other.test".into();
        let mut b = FakeProvider::message("2", "Code", "code 222222");
        b.sender = "noreply@github.com".into();
        let p = FakeProvider::new("fake")
            .pages([vec![
                MessageRow::new("1", "", ""),
                MessageRow::new("2", "", ""),
            ]])
            .bodies([a, b]);
        let f = MailFilter::default().from("GitHub.com");
        assert_eq!(
            inbox(p)
                .otp_matching(Duration::from_secs(5), &f, None)
                .await
                .unwrap(),
            "222222"
        );
    }

    #[tokio::test]
    async fn link_with_needle() {
        let m = Message::from_bodies(
            "1",
            "s",
            "x",
            None,
            r#"<a href="https://a.test/unsub">u</a><a href="https://a.test/verify?t=9">v</a>"#,
            None,
        );
        let p = FakeProvider::new("fake")
            .pages([vec![MessageRow::new("1", "", "")]])
            .bodies([m]);
        assert_eq!(
            inbox(p)
                .link(Duration::from_secs(5), Some("verify"))
                .await
                .unwrap(),
            "https://a.test/verify?t=9"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_cleanly() {
        let p = FakeProvider::new("fake");
        let err = inbox(p).otp(Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, Error::Timeout(_)), "{err}");
    }

    #[tokio::test]
    async fn close_deletes_what_was_handed_out() {
        let p = FakeProvider::new("fake")
            .pages([vec![MessageRow::new("1", "", "")]])
            .caps(FAST);
        let deleted = p.deleted.clone();
        let b = Inbox::new(Arc::new(p), Address::new("a@fake.test", "fake"));
        b.wait(Duration::from_secs(5), &MailFilter::default())
            .await
            .unwrap();
        b.close().await;
        assert_eq!(*deleted.lock().unwrap(), ["1"]);
    }
}
