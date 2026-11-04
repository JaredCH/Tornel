use thiserror::Error;

/// Boundary-level errors.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("core error: {0}")]
    Core(#[from] anon_core::CoreError),

    #[error("storage error: {0}")]
    Storage(#[from] anon_storage::StorageError),

    #[error("messaging error: {0}")]
    Messaging(#[from] anon_messaging::MessageError),

    #[error("consent error: {0}")]
    Consent(#[from] anon_consent::ConsentError),

    #[error("transport error: {0}")]
    Transport(#[from] anon_transport::TransportError),

    #[error("group error: {0}")]
    Group(#[from] anon_mls::MlsError),

    #[error("a required field was empty: {0}")]
    EmptyField(&'static str),

    #[error("a field exceeded its maximum length: {0}")]
    FieldTooLong(&'static str),

    #[error("the contact code could not be parsed: {0}")]
    BadContactCode(String),

    #[error("the recipient onion address could not be parsed: {0}")]
    BadOnion(String),

    #[error("the group id could not be parsed: {0}")]
    BadGroupId(String),

    #[error("no group with that id is stored on this device")]
    UnknownGroup,

    #[error("the group's MLS state is missing; the group cannot be used")]
    GroupStateMissing,

    #[error("an opaque handle did not resolve to a live value")]
    UnknownHandle,

    #[error("the backend is not initialised")]
    NotInitialised,

    #[error("sending is unavailable: {0}")]
    SendUnavailable(String),

    #[error("the group's keys are not forward-secret; rotation must be resolved first")]
    NotForwardSecret,
}

pub type Result<T> = std::result::Result<T, IpcError>;

/// Command-level errors, carrying a message safe to display in the UI.
///
/// Deliberately flat: the webview should not receive internal error structure,
/// which could leak filesystem paths or key state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandError {
    /// A short, user-facing message.
    pub message: String,
    /// A stable code the frontend can branch on.
    pub code: &'static str,
}

impl CommandError {
    /// Build an error with a display message and a code.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Every wrapped error becomes a `CommandError`, so backend methods can use `?`
/// and still hand the UI a display-safe value.
macro_rules! command_error_from {
    ($($ty:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$ty> for CommandError {
                fn from(e: $ty) -> Self {
                    CommandError::from(IpcError::$variant(e))
                }
            }
        )*
    };
}

command_error_from! {
    anon_core::CoreError => Core,
    anon_storage::StorageError => Storage,
    anon_messaging::MessageError => Messaging,
    anon_consent::ConsentError => Consent,
    anon_transport::TransportError => Transport,
    anon_mls::MlsError => Group,
}

impl From<IpcError> for CommandError {
    fn from(e: IpcError) -> Self {
        // Map to a code without echoing internals. The message is the human
        // explanation; the code is what the frontend switches on.
        let code = match &e {
            IpcError::EmptyField(_) | IpcError::FieldTooLong(_) => "invalid_input",
            IpcError::BadContactCode(_) | IpcError::BadOnion(_) => "invalid_address",
            IpcError::BadGroupId(_) => "invalid_group_id",
            IpcError::UnknownGroup => "unknown_group",
            IpcError::GroupStateMissing => "group_state_missing",
            IpcError::UnknownHandle => "stale_handle",
            IpcError::NotInitialised => "not_initialised",
            IpcError::SendUnavailable(_) => "send_unavailable",
            IpcError::NotForwardSecret => "not_forward_secret",
            _ => "internal",
        };
        Self::new(code, e.to_string())
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}
