use thiserror::Error;

/// Storage failures.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// The database could not be opened or decrypted. Deliberately opaque: we do
    /// not distinguish a wrong passphrase from a corrupt file, because that
    /// distinction helps an attacker and no legitimate caller needs it.
    #[error("could not open the encrypted database (wrong passphrase or corrupt file)")]
    OpenFailed,

    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: i32, supported: i32 },

    #[error("this build requires schema version {required}, but the file has {found}; migration is needed")]
    SchemaMigrationRequired { required: i32, found: i32 },

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("a data key for bucket {0} is missing; its contents have been crypto-shredded")]
    KeyShredded(String),

    #[error("stored record could not be decrypted (wrong key or tampered ciphertext)")]
    Decrypt,

    #[error("record failed integrity validation: {0}")]
    InvalidRecord(&'static str),

    #[error(
        "refused to insert a record that is already expired (expires_at {expires_at} <= now {now})"
    )]
    AlreadyExpired { expires_at: i64, now: i64 },

    #[error("argon2 parameters are invalid: {0}")]
    InvalidParams(&'static str),
}

pub type Result<T> = std::result::Result<T, StorageError>;
