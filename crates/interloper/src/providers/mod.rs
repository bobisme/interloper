//! Every built-in backend. One module per backend; add its `SPEC` to [`all`].

pub mod guerrillamail;
pub mod inboxes;
pub mod inboxkitten;
pub mod mailcx;
pub mod maildrop;
pub mod mailtm;
pub mod tempmailio;
pub mod tempmailplus;
pub mod temporarymail;
pub mod tenminutemail;
pub mod util;

use crate::registry::ProviderSpec;

/// The compiled-in provider table.
pub fn all() -> Vec<ProviderSpec> {
    vec![
        guerrillamail::SPEC,
        inboxes::SPEC,
        inboxkitten::SPEC,
        mailcx::SPEC,
        maildrop::SPEC,
        mailtm::SPEC,
        tempmailio::SPEC,
        tempmailplus::SPEC,
        temporarymail::SPEC,
        tenminutemail::SPEC,
    ]
}
