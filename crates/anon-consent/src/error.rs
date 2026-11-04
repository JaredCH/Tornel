use thiserror::Error;

/// Consent-gate failures.
#[derive(Debug, Error)]
pub enum ConsentError {
    #[error("core error: {0}")]
    Core(#[from] anon_core::CoreError),

    #[error("storage error: {0}")]
    Storage(#[from] anon_storage::StorageError),

    #[error("no proposal exists with id {0}")]
    UnknownProposal(String),

    #[error("proposal {0} has already been decided; a second decision is a replay")]
    AlreadyDecided(String),

    #[error("proposal {0} expired before a decision was made (not auto-approved)")]
    ProposalExpired(String),

    /// The frontend supplied fields that do not match what the backend signed.
    /// §5.2: the UI cannot approve a rotation it invented.
    #[error("the submitted proposal does not match the signed proposal held by the backend")]
    ProposalMismatch,

    #[error("proposal signature is invalid")]
    BadSignature,

    #[error("group {0} is unknown")]
    UnknownGroup(String),

    #[error("rotation would not advance the epoch ({0} -> {1})")]
    EpochNotAdvanced(u64, u64),

    #[error("group security state is not forward-secret; sending must be blocked or flagged")]
    NotForwardSecret,
}

pub type Result<T> = std::result::Result<T, ConsentError>;
