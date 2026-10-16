use crate::crypto::{self, Key32};
use crate::error::CoreError;
use crate::schema::{SCHEMA, SCHEMA_VERSION};
use rusqlite::{params, Connection, OptionalExtension};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

const DEK_AAD: &[u8] = b"sg:dek";

fn remove_db_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut p = path.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(p);
    }
}

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
        Self::init_with(path, key, |_| Ok(()))
    }

    /// `before_commit` runs inside the init transaction; tests use it to inject a failure.
    fn init_with(
        path: &Path,
        key: KeyInput,
        before_commit: impl FnOnce(&Connection) -> Result<(), CoreError>,
    ) -> Result<Self, CoreError> {
        // Create the file with mode 0600 BEFORE sqlite opens it.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Self::init_created(path, key, before_commit).inspect_err(|_| remove_db_files(path))
    }

    fn init_created(
        path: &Path,
        key: KeyInput,
        before_commit: impl FnOnce(&Connection) -> Result<(), CoreError>,
    ) -> Result<Self, CoreError> {
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
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Schema and meta rows land atomically: a half-initialised vault is never visible.
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        {
            let mut put = tx.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
            put.execute(params![
                "schema_version",
                SCHEMA_VERSION.to_string().into_bytes()
            ])?;
            put.execute(params!["kdf", kdf.as_bytes()])?;
            put.execute(params!["salt", salt])?;
            put.execute(params!["dek_wrapped", wrapped])?;
        }
        before_commit(&tx)?;
        tx.commit()?;
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
        // Recover from poisoning instead of panicking: a panic while holding the guard cannot
        // leave a half-applied write behind, because rusqlite rolls back any open transaction
        // when it is dropped during unwinding.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn seal_value(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        crypto::seal(&self.dek, aad, plaintext)
    }

    pub fn open_value(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        crypto::open(&self.dek, aad, blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_init_leaves_no_files_and_retry_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let key = crypto::random_key();
        let err = Vault::init_with(&path, KeyInput::Raw(Zeroizing::new(*key)), |_| {
            Err(CoreError::Crypto)
        })
        .err()
        .unwrap();
        assert!(matches!(err, CoreError::Crypto));
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        Vault::init(&path, KeyInput::Raw(Zeroizing::new(*key))).unwrap();
        Vault::open(&path, KeyInput::Raw(Zeroizing::new(*key))).unwrap();
    }
}
