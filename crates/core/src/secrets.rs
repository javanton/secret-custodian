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
    // Exactly what `http::HeaderValue::from_str` refuses (C0 controls except TAB, and DEL), so a
    // stored value can always be injected as a header. Non-ASCII UTF-8 is accepted by it too.
    if v.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(CoreError::InvalidSecretValue("contains control characters"));
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

fn insert_secret(
    vault: &Vault,
    conn: &Connection,
    name: &str,
    value: &str,
) -> Result<SecretMeta, CoreError> {
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM secrets WHERE name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )? > 0;
    if exists {
        return Err(CoreError::AlreadyExists);
    }
    let ts = now();
    conn.execute(
        "INSERT INTO secrets (name, value_enc, created_at) VALUES (?1, x'', ?2)",
        params![name, ts],
    )?;
    let id = conn.last_insert_rowid();
    conn.execute(
        "UPDATE secrets SET value_enc = ?1 WHERE id = ?2",
        params![vault.seal_value(&aad(id), value.as_bytes()), id],
    )?;
    Ok(SecretMeta {
        id,
        name: name.into(),
        created_at: ts,
        rotated_at: None,
    })
}

impl Vault {
    pub fn add_secret(&self, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
        self.add_secret_with(name, value, |_, _| Ok::<(), CoreError>(()))
    }

    /// Inserts the secret and runs `extra` in the same transaction; an `Err` from it rolls everything back.
    pub fn add_secret_with<E, F>(&self, name: &str, value: &str, extra: F) -> Result<SecretMeta, E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection, &SecretMeta) -> Result<(), E>,
    {
        validate_name(name)?;
        validate_secret_value(value)?;
        self.in_transaction(|tx| {
            let meta = insert_secret(self, tx, name, value)?;
            extra(tx, &meta)?;
            Ok(meta)
        })
    }

    /// Deletes the secret together with its rules, then runs `after`, all in one transaction.
    pub fn remove_secret_cascade_with<E, F>(&self, name: &str, after: F) -> Result<(), E>
    where
        E: From<CoreError>,
        F: FnOnce(&Connection) -> Result<(), E>,
    {
        self.in_transaction(|tx| {
            let meta = lookup(tx, name)?;
            tx.execute("DELETE FROM rules WHERE secret_id = ?1", [meta.id])
                .map_err(CoreError::from)?;
            delete_by_id(tx, meta.id)?;
            after(tx)
        })
    }

    pub fn list_secrets_with_rule_counts(&self) -> Result<Vec<(SecretMeta, i64)>, CoreError> {
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT s.id, s.name, s.created_at, s.rotated_at,
                    (SELECT COUNT(*) FROM rules r WHERE r.secret_id = s.id)
             FROM secrets s ORDER BY s.name",
        )?;
        let rows = st
            .query_map([], |r| Ok((row_meta(r)?, r.get::<_, i64>(4)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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

    fn seed_rule(v: &Vault, secret_id: i64) {
        let c = v.conn();
        c.execute(
            "INSERT OR IGNORE INTO roles (name, unmatched_policy) VALUES ('r','deny')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id)
             VALUES ('r','h.com','*','','header','X-K','{secret}',?1)",
            [secret_id],
        )
        .unwrap();
    }

    #[test]
    fn add_secret_with_rolls_the_secret_back_when_the_hook_fails() {
        let (_d, v) = vault();
        let r: Result<SecretMeta, CoreError> =
            v.add_secret_with("a", "x", |_, _| Err(CoreError::InUse));
        assert!(matches!(r, Err(CoreError::InUse)));
        assert!(v.list_secrets().unwrap().is_empty());
    }

    #[test]
    fn add_secret_with_runs_the_hook_in_the_same_transaction() {
        let (_d, v) = vault();
        let meta = v
            .add_secret_with("a", "x", |conn, m| {
                conn.execute(
                    "INSERT INTO roles (name, unmatched_policy) VALUES ('r','deny')",
                    [],
                )?;
                assert!(m.id > 0);
                Ok::<(), CoreError>(())
            })
            .unwrap();
        assert_eq!(meta.name, "a");
        assert_eq!(
            v.conn()
                .query_row("SELECT COUNT(*) FROM roles", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }

    #[test]
    fn cascade_removal_deletes_rules_and_runs_the_hook_atomically() {
        let (_d, v) = vault();
        let meta = v.add_secret("a", "x").unwrap();
        seed_rule(&v, meta.id);
        assert!(matches!(v.remove_secret("a"), Err(CoreError::InUse)));
        // a failing hook leaves both the secret and its rule in place
        let r: Result<(), CoreError> =
            v.remove_secret_cascade_with("a", |_| Err(CoreError::Crypto));
        assert!(matches!(r, Err(CoreError::Crypto)));
        assert_eq!(v.list_secrets().unwrap().len(), 1);
        assert_eq!(
            v.conn()
                .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        // success removes both
        v.remove_secret_cascade_with("a", |_| Ok::<(), CoreError>(()))
            .unwrap();
        assert!(v.list_secrets().unwrap().is_empty());
        assert_eq!(
            v.conn()
                .query_row("SELECT COUNT(*) FROM rules", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn rule_counts_are_reported_per_secret() {
        let (_d, v) = vault();
        let a = v.add_secret("a", "x").unwrap();
        v.add_secret("b", "x").unwrap();
        seed_rule(&v, a.id);
        let counts: Vec<(String, i64)> = v
            .list_secrets_with_rule_counts()
            .unwrap()
            .into_iter()
            .map(|(m, n)| (m.name, n))
            .collect();
        assert_eq!(counts, vec![("a".to_string(), 1), ("b".to_string(), 0)]);
    }

    #[test]
    fn in_transaction_commits_on_ok_and_rolls_back_on_err() {
        let (_d, v) = vault();
        let ok: Result<(), CoreError> = v.in_transaction(|c| {
            c.execute(
                "INSERT INTO roles (name, unmatched_policy) VALUES ('keep','deny')",
                [],
            )?;
            Ok(())
        });
        ok.unwrap();
        let err: Result<(), CoreError> = v.in_transaction(|c| {
            c.execute(
                "INSERT INTO roles (name, unmatched_policy) VALUES ('drop','deny')",
                [],
            )?;
            Err(CoreError::Crypto)
        });
        assert!(err.is_err());
        let names: Vec<String> = {
            let c = v.conn();
            let mut st = c.prepare("SELECT name FROM roles").unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        assert_eq!(names, vec!["keep".to_string()]);
    }
}
