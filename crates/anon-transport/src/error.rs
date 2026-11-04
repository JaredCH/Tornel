use thiserror::Error;

/// Transport failures.
///
/// Note the deliberate absence of any variant that means "fell back to
/// clearnet". There is no such outcome in this design (`plan.md` §1.2).
#[derive(Debug, Error)]
pub enum TransportError {
    /// The transport is bootstrapping or idle; sending is refused.
    #[error("transport is not ready; refusing to send (fail-closed)")]
    NotReady,

    /// The transport does not provide Tor-grade anonymity.
    #[error("transport does not provide Tor-grade anonymity; refusing to send")]
    AnonymityUnavailable,

    /// The transport failed or was shut down.
    #[error("transport failed: {0}")]
    Failed(String),

    /// The peer route is not usable.
    #[error("invalid peer route: {0}")]
    InvalidRoute(String),

    /// The peer reported failure.
    #[error("peer rejected the payload: {0}")]
    PeerRejected(String),

    /// Payload exceeded the configured maximum.
    #[error("payload exceeds the maximum transportable size ({max} bytes)")]
    PayloadTooLarge { max: usize },
}

pub type Result<T> = std::result::Result<T, TransportError>;
