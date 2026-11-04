use thiserror::Error;

/// Messaging failures.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("frame encoding error: {0}")]
    Frame(#[from] FrameError),

    #[error("transport refused delivery: {0}")]
    Transport(#[from] anon_transport::TransportError),

    #[error("storage error: {0}")]
    Storage(#[from] anon_storage::StorageError),

    #[error("a message must not be sent to a local-only route (no clearnet fallback)")]
    LocalRouteNotDeliverable,

    #[error("payload exceeds the largest padding bucket ({max} bytes before padding)")]
    PayloadTooLarge { max: usize },

    #[error("duplicate message id rejected (replay)")]
    Replay,

    #[error("frame carries unsupported protocol version {found} (this build speaks {supported})")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("frame decryption failed (wrong key or tampered ciphertext)")]
    Decrypt,

    #[error("outbox is full")]
    OutboxFull,

    /// A group-layer failure. Kept as a string rather than wrapping
    /// `anon_mls::MlsError` so this crate's error type does not force every
    /// caller to depend on the MLS crate just to match on delivery errors.
    #[error("group messaging error: {0}")]
    Group(String),

    /// A mailbox host declined to store a blob (`plan.md` §4.4 "Abuse").
    ///
    /// Distinct from [`MessageError::Storage`] because this is a *policy* answer,
    /// not a failure: the sender must surface "not accepted" rather than retry
    /// blindly or claim delivery.
    #[error("mailbox host refused the message: {0}")]
    MailboxRefused(String),
}

pub type Result<T> = std::result::Result<T, MessageError>;

/// Frame-level errors, kept separate so framing can be tested without a store.
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame is too short to be valid")]
    Truncated,

    #[error("frame declares length {declared} but carries {actual} bytes")]
    LengthMismatch { declared: usize, actual: usize },

    #[error("frame padding is malformed")]
    BadPadding,

    #[error("frame carries unsupported protocol version {found} (this build speaks {supported})")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("payload is larger than the largest padding bucket")]
    TooLarge,

    #[error("frame failed authentication")]
    AuthFailed,
}
