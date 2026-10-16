pub mod crypto;
pub mod error;
pub mod paths;
mod schema;
mod secrets;
mod vault;

pub use error::CoreError;
pub use secrets::{validate_secret_value, SecretMeta};
pub use vault::{KeyInput, Vault};

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
