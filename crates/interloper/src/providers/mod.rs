//! Every built-in backend. One module per backend; add its `SPEC` to [`all`].

pub mod guerrillamail;
pub mod inboxes;
pub mod maildrop;
pub mod mailtm;
pub mod util;

use crate::registry::ProviderSpec;

/// The compiled-in provider table.
pub fn all() -> Vec<ProviderSpec> {
    vec![
        guerrillamail::SPEC,
        inboxes::SPEC,
        maildrop::SPEC,
        mailtm::SPEC,
    ]
}
