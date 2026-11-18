//! Small helpers every adapter wants.

use rand::Rng;
use rand::seq::IndexedRandom;

use crate::error::{Error, Result};
use crate::provider::GenerateOptions;

/// A random local part: `il` plus ten hex digits. Unguessable enough for the
/// backends whose inboxes are public by address.
pub fn random_local() -> String {
    let n: u64 = rand::rng().random();
    format!("il{:010x}", n & 0xff_ffff_ffff)
}

/// The caller's local part, or a random one.
pub fn local_or_random(opts: &GenerateOptions) -> String {
    opts.local.clone().unwrap_or_else(random_local)
}

/// The caller's domain when it is one of `domains`, a random one of them when
/// none was asked for, and `NotSupported` (a caller error, never drift)
/// otherwise.
pub fn pick_domain<S: AsRef<str>>(
    provider: &str,
    opts: &GenerateOptions,
    domains: &[S],
) -> Result<String> {
    if let Some(want) = &opts.domain {
        return domains
            .iter()
            .find(|d| d.as_ref().eq_ignore_ascii_case(want))
            .map(|d| d.as_ref().to_string())
            .ok_or_else(|| Error::unsupported(format!("{provider} does not serve {want}")));
    }
    domains
        .choose(&mut rand::rng())
        .map(|d| d.as_ref().to_string())
        .ok_or_else(|| Error::drift(provider, "at least one domain", "none"))
}

/// Refuse a custom local part on a backend that assigns its own.
pub fn no_custom_local(provider: &str, opts: &GenerateOptions) -> Result<()> {
    match &opts.local {
        Some(_) => Err(Error::unsupported(format!(
            "{provider} assigns its own local part"
        ))),
        None => Ok(()),
    }
}
