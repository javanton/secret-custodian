#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("wrong key or corrupted vault")]
    WrongKey,
    #[error("the vault was created with a different key source")]
    KeySourceMismatch,
    #[error(
        "database schema version {found} is not supported by this build (supports {supported})"
    )]
    UnsupportedSchema { found: i64, supported: i64 },
    #[error("invalid key material")]
    InvalidKey,
    #[error("invalid secret value: {0}")]
    InvalidSecretValue(&'static str),
    #[error("invalid name: {0}")]
    InvalidName(&'static str),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("still referenced")]
    InUse,
    #[error("crypto failure")]
    Crypto,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
