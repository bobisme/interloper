//! The logic the routes call. Routes own HTTP; this owns everything else.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use interloper::parse::extract_otp;
use interloper::regex::Regex;
use interloper::{Address, Inbox, Interloper, MailFilter, Message, Request};

use crate::error::ApiError;
use crate::store::Store;

pub struct Service {
    pub il: Interloper,
    pub store: Store,
}

impl Service {
    pub fn new(il: Interloper, store: Store) -> Arc<Self> {
        Arc::new(Service { il, store })
    }

    pub async fn create(&self, req: &Request) -> Result<Address, ApiError> {
        let inbox = self.il.inbox(req).await?;
        let address = inbox.address().clone();
        self.store.put(&address)?;
        Ok(address)
    }

    /// A live inbox for a stored address. The provider is looked up by name,
    /// so the object serving a request is not the one that issued the address.
    pub fn inbox(&self, value: &str) -> Result<Inbox, ApiError> {
        let address = self.store.get(value)?.ok_or(ApiError::UnknownAddress)?;
        Ok(self.il.resume(address)?)
    }

    pub async fn get_message(
        &self,
        value: &str,
        id: &str,
    ) -> Result<(Message, Option<String>), ApiError> {
        let m = self.inbox(value)?.get(id).await?;
        let code = extract_otp(&m.subject, &m.text, None);
        Ok((m, code))
    }

    /// Hold until matching mail arrives or `timeout` passes. `Ok(None)` means
    /// nothing arrived in time: a normal answer, not an error. With
    /// `want_otp`, mail without a code is skipped: a caller waiting for a code
    /// does not want the newsletter that arrived first.
    pub async fn wait(
        &self,
        value: &str,
        timeout: Duration,
        pattern: Option<&Regex>,
        want_otp: bool,
        filter: &MailFilter,
    ) -> Result<Option<(Message, Option<String>)>, ApiError> {
        let inbox = self.inbox(value)?;
        let search = async {
            let mut stream = inbox.watch(None);
            while let Some(m) = stream.next().await {
                let m = m?;
                if !filter.accepts(&m) {
                    continue;
                }
                let code = extract_otp(&m.subject, &m.text, pattern);
                if want_otp && code.is_none() {
                    continue;
                }
                return Ok(Some((m, code)));
            }
            Ok(None)
        };
        // Dropping the stream on timeout cancels its polling; nothing leaks.
        match tokio::time::timeout(timeout, search).await {
            Ok(r) => r,
            Err(_) => Ok(None),
        }
    }
}
