use crate::{error::CoreError, now, vault::Vault};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SecretMeta {
    pub id: i64,
    pub name: String,
    pub created_at: i64,
    pub rotated_at: Option<i64>,
}

const MAX_VALUE: usize = 8192;

pub fn validate_secret_value(v: &str) -> Result<(), CoreError> {
    if v.is_empty() {
        return Err(CoreError::InvalidSecretValue("empty"));
    }
    if v.len() > MAX_VALUE {
        return Err(CoreError::InvalidSecretValue("too long"));
    }
    if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(CoreError::InvalidSecretValue("contains CR, LF or NUL"));
    }
    Ok(())
}

fn validate_name(n: &str) -> Result<(), CoreError> {
    let ok = !n.is_empty()
        && n.len() <= 64
        && n.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        });
    if ok {
        Ok(())
    } else {
        Err(CoreError::InvalidName("use [a-z0-9._-], max 64 chars"))
    }
}

fn aad(id: i64) -> Vec<u8> {
    format!("secret:{id}").into_bytes()
}

fn row_meta(r: &rusqlite::Row) -> rusqlite::Result<SecretMeta> {
    Ok(SecretMeta {
        id: r.get(0)?,
        name: r.get(1)?,
        created_at: r.get(2)?,
        rotated_at: r.get(3)?,
    })
}

fn lookup(conn: &Connection, name: &str) -> Result<SecretMeta, CoreError> {
    conn.query_row(
        "SELECT id, name, created_at, rotated_at FROM secrets WHERE name = ?1",
        [name],
        row_meta,
    )
    .optional()?
    .ok_or(CoreError::NotFound)
}

fn update_value(conn: &Connection, id: i64, blob: &[u8], ts: i64) -> Result<(), CoreError> {
    let n = conn.execute(
        "UPDATE secrets SET value_enc = ?1, rotated_at = ?2 WHERE id = ?3",
        params![blob, ts, id],
    )?;
    if n == 0 {
        return Err(CoreError::NotFound);
    }
    Ok(())
}

fn delete_by_id(conn: &Connection, id: i64) -> Result<(), CoreError> {
    let n = conn.execute("DELETE FROM secrets WHERE id = ?1", [id])?;
    if n == 0 {
        return Err(CoreError::NotFound);
    }
    Ok(())
}

impl Vault {
    pub fn add_secret(&self, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
        validate_name(name)?;
        validate_secret_value(value)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT COUNT(*) FROM secrets WHERE name = ?1",
            [name],
            |r| r.get::<_, i64>(0),
        )? > 0;
        if exists {
            return Err(CoreError::AlreadyExists);
        }
        let ts = now();
        tx.execute(
            "INSERT INTO secrets (name, value_enc, created_at) VALUES (?1, x'', ?2)",
            params![name, ts],
        )?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE secrets SET value_enc = ?1 WHERE id = ?2",
            params![self.seal_value(&aad(id), value.as_bytes()), id],
        )?;
        tx.commit()?;
        Ok(SecretMeta {
            id,
            name: name.into(),
            created_at: ts,
            rotated_at: None,
        })
    }

    pub fn rotate_secret(&self, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
        validate_secret_value(value)?;
        // One guard for lookup and write so the row cannot vanish in between.
        let conn = self.conn();
        let meta = lookup(&conn, name)?;
        let ts = now();
        update_value(
            &conn,
            meta.id,
            &self.seal_value(&aad(meta.id), value.as_bytes()),
            ts,
        )?;
        Ok(SecretMeta {
            rotated_at: Some(ts),
            ..meta
        })
    }

    pub fn remove_secret(&self, name: &str) -> Result<(), CoreError> {
        let conn = self.conn();
        let meta = lookup(&conn, name)?;
        let used: i64 = conn.query_row(
            "SELECT COUNT(*) FROM rules WHERE secret_id = ?1",
            [meta.id],
            |r| r.get(0),
        )?;
        if used > 0 {
            return Err(CoreError::InUse);
        }
        delete_by_id(&conn, meta.id)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>, CoreError> {
        let conn = self.conn();
        let mut st =
            conn.prepare("SELECT id, name, created_at, rotated_at FROM secrets ORDER BY name")?;
        let rows = st.query_map([], row_meta)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_secret_meta(&self, name: &str) -> Result<SecretMeta, CoreError> {
        lookup(&self.conn(), name)
    }

    /// Decrypts a secret for injection. ONLY the proxy may call this; no admin API, CLI or web path may.
    pub fn reveal_for_injection(&self, id: i64) -> Result<Zeroizing<String>, CoreError> {
        let blob: Vec<u8> = self
            .conn()
            .query_row("SELECT value_enc FROM secrets WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?
            .ok_or(CoreError::NotFound)?;
        let bytes = self.open_value(&aad(id), &blob)?;
        let s = String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::Crypto)?;
        Ok(Zeroizing::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, vault::KeyInput};

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let key = crypto::random_key();
        let v = Vault::init(&dir.path().join("v.db"), KeyInput::Raw(key)).unwrap();
        (dir, v)
    }

    #[test]
    fn update_and_delete_by_id_report_not_found_when_row_vanished() {
        let (_d, v) = vault();
        let meta = v.add_secret("a", "x").unwrap();
        let conn = v.conn();
        conn.execute("DELETE FROM secrets WHERE id = ?1", [meta.id])
            .unwrap();
        assert!(matches!(
            update_value(&conn, meta.id, b"blob", 1),
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            delete_by_id(&conn, meta.id),
            Err(CoreError::NotFound)
        ));
    }
}
