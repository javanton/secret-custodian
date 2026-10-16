use crate::crypto::{self, Key32};
use crate::error::CoreError;
use crate::schema::{SCHEMA, SCHEMA_VERSION};
use rusqlite::{params, Connection, OptionalExtension};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

const DEK_AAD: &[u8] = b"sg:dek";

fn meta_get(conn: &Connection, key: &str) -> Result<Vec<u8>, CoreError> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()?
        .ok_or(CoreError::WrongKey)
}

pub enum KeyInput {
    Raw(Key32),
    Passphrase(String),
}

pub struct Vault {
    conn: Mutex<Connection>,
    dek: Key32,
}

impl Vault {
    pub fn init(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        // Create the file with mode 0600 BEFORE sqlite opens it.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let (kdf, salt, kek) = match key {
            KeyInput::Raw(k) => ("raw", Vec::new(), k),
            KeyInput::Passphrase(p) => {
                let salt: [u8; 16] = crypto::random_bytes();
                (
                    "argon2id",
                    salt.to_vec(),
                    crypto::kek_from_passphrase(&p, &salt)?,
                )
            }
        };
        let dek = crypto::random_key();
        let wrapped = crypto::seal(&kek, DEK_AAD, &*dek);
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        let mut put = conn.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
        put.execute(params![
            "schema_version",
            SCHEMA_VERSION.to_string().into_bytes()
        ])?;
        put.execute(params!["kdf", kdf.as_bytes()])?;
        put.execute(params!["salt", salt])?;
        put.execute(params!["dek_wrapped", wrapped])?;
        drop(put);
        Ok(Self {
            conn: Mutex::new(conn),
            dek,
        })
    }

    pub fn open(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let kdf = meta_get(&conn, "kdf")?;
        let kek = match (kdf.as_slice(), key) {
            (b"raw", KeyInput::Raw(k)) => k,
            (b"argon2id", KeyInput::Passphrase(p)) => {
                let salt: [u8; 16] = meta_get(&conn, "salt")?
                    .try_into()
                    .map_err(|_| CoreError::WrongKey)?;
                crypto::kek_from_passphrase(&p, &salt)?
            }
            _ => return Err(CoreError::KeySourceMismatch),
        };
        let wrapped = meta_get(&conn, "dek_wrapped")?;
        let dek_bytes = crypto::open(&kek, DEK_AAD, &wrapped).map_err(|_| CoreError::WrongKey)?;
        let dek: [u8; 32] = dek_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::WrongKey)?;
        Ok(Self {
            conn: Mutex::new(conn),
            dek: Zeroizing::new(dek),
        })
    }

    pub fn open_or_init(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        if path.exists() {
            Self::open(path, key)
        } else {
            Self::init(path, key)
        }
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("vault mutex poisoned")
    }

    pub fn seal_value(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        crypto::seal(&self.dek, aad, plaintext)
    }

    pub fn open_value(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        crypto::open(&self.dek, aad, blob)
    }
}
