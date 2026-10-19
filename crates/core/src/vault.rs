use crate::crypto::{self, Key32};
use crate::error::CoreError;
use crate::schema::{SCHEMA, SCHEMA_VERSION};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
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
        if !path.try_exists()? {
            return Err(CoreError::Io(std::io::ErrorKind::NotFound.into()));
        }
        // No CREATE flag: opening must never create a file.
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
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
        // Checked only after the key is verified, so a wrong key never learns the version.
        let found: i64 = std::str::from_utf8(&meta_get(&conn, "schema_version")?)
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or(CoreError::UnsupportedSchema {
                found: -1,
                supported: SCHEMA_VERSION,
            })?;
        if found != SCHEMA_VERSION {
            return Err(CoreError::UnsupportedSchema {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(Self {
            conn: Mutex::new(conn),
            dek: Zeroizing::new(dek),
        })
    }

    /// True when there is no usable vault at `path` and `init` is the right call: the file is
    /// missing, empty, or a SQLite database with no tables (what a crashed `init` leaves behind).
    /// A database that has tables but no `meta` row is NOT uninitialized: it is corrupt.
    pub fn needs_init(path: &Path) -> bool {
        match std::fs::metadata(path) {
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            Ok(m) if m.len() == 0 => true,
            Ok(m) if !m.is_file() => false,
            Ok(_) => Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .and_then(|c| {
                    c.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                        r.get::<_, i64>(0)
                    })
                })
                .is_ok_and(|n| n == 0),
        }
    }

    /// Opens the vault, creating it first when [`Vault::needs_init`]. Leftovers of an interrupted
    /// `init` (empty or table-less file, `-wal`, `-shm`) are removed before initialising again.
    pub fn open_or_init(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        if !path.try_exists()? {
            return Self::init(path, key);
        }
        if Self::needs_init(path) {
            remove_db_files(path);
            return Self::init(path, key);
        }
        Self::open(path, key)
    }

    /// Runs `f` in one transaction: committed when it returns `Ok`, rolled back on `Err`. The
    /// connection stays locked for the whole call, so concurrent writers are serialized.
    ///
    /// Reentrancy: the closure receives the already-locked connection and must only use it: it must not call `Vault` methods or wrappers that lock the connection (the mutex is not reentrant, that would deadlock).
    pub fn in_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection) -> Result<T, E>,
    {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(CoreError::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(CoreError::from)?;
        Ok(out)
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
