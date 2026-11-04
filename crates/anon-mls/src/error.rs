use thiserror::Error;

/// MLS group failures.
///
/// Deliberately coarse where the distinction would help an attacker: a message
/// that fails to decrypt because the sender was removed and one that fails
/// because the ciphertext was tampered with both surface as
/// [`MlsError::Decrypt`], matching the reasoning in `anon-storage`'s
/// `OpenFailed`.
#[derive(Debug, Error)]
pub enum MlsError {
    #[error("storage error: {0}")]
    Storage(#[from] anon_storage::StorageError),

    #[error("MLS storage backend error: {0}")]
    Backend(String),

    #[error("group not found in local storage")]
    GroupNotFound,

    #[error("a group with this id already exists")]
    GroupExists,

    #[error("this member is not part of the group")]
    NotAMember,

    #[error("the group has a pending commit; merge or clear it first")]
    PendingCommit,

    #[error("message could not be decrypted (wrong epoch, removed member, or tampering)")]
    Decrypt,

    #[error("message was not an application message")]
    NotApplicationMessage,

    #[error("malformed MLS message: {0}")]
    Malformed(&'static str),

    #[error("key package is invalid: {0}")]
    InvalidKeyPackage(String),

    #[error("welcome message could not be processed: {0}")]
    InvalidWelcome(String),

    #[error("refusing to remove the last remaining member")]
    WouldEmptyGroup,

    #[error("member index {0} is not in the group")]
    UnknownMember(u32),

    #[error("identity is not valid for MLS: {0}")]
    InvalidIdentity(&'static str),
}

pub type Result<T> = std::result::Result<T, MlsError>;
