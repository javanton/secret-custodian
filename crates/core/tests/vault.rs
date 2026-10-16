use sg_core::{crypto, CoreError, KeyInput, Vault};
use tempfile::tempdir;

fn raw(k: &sg_core::crypto::Key32) -> KeyInput {
    KeyInput::Raw(zeroize::Zeroizing::new(**k))
}

#[test]
fn init_then_open_with_same_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let key = crypto::random_key();
    Vault::init(&path, raw(&key)).unwrap();
    Vault::open(&path, raw(&key)).unwrap();
}

#[test]
fn open_with_wrong_key_fails_without_detail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    Vault::init(&path, raw(&crypto::random_key())).unwrap();
    let err = Vault::open(&path, raw(&crypto::random_key()))
        .err()
        .unwrap();
    assert!(matches!(err, CoreError::WrongKey));
}

#[test]
fn passphrase_vault_rejects_raw_key_and_vice_versa() {
    let dir = tempdir().unwrap();
    let p1 = dir.path().join("a.db");
    Vault::init(&p1, KeyInput::Passphrase("pw".into())).unwrap();
    Vault::open(&p1, KeyInput::Passphrase("pw".into())).unwrap();
    assert!(matches!(
        Vault::open(&p1, raw(&crypto::random_key())).err().unwrap(),
        CoreError::KeySourceMismatch
    ));
    assert!(matches!(
        Vault::open(&p1, KeyInput::Passphrase("bad".into()))
            .err()
            .unwrap(),
        CoreError::WrongKey
    ));
}

#[test]
fn secret_lifecycle_and_metadata_only_listing() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    let meta = v.add_secret("github-pat", "ghp_SUPERSECRET").unwrap();
    assert_eq!(v.list_secrets().unwrap().len(), 1);
    assert_eq!(
        &**v.reveal_for_injection(meta.id).unwrap(),
        "ghp_SUPERSECRET"
    );
    let rotated = v.rotate_secret("github-pat", "ghp_NEW").unwrap();
    assert!(rotated.rotated_at.is_some());
    assert_eq!(&**v.reveal_for_injection(meta.id).unwrap(), "ghp_NEW");
    v.remove_secret("github-pat").unwrap();
    assert!(v.list_secrets().unwrap().is_empty());
    assert!(matches!(
        v.remove_secret("github-pat"),
        Err(CoreError::NotFound)
    ));
}

#[test]
fn duplicate_name_is_rejected() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    v.add_secret("a", "x").unwrap();
    assert!(matches!(
        v.add_secret("a", "y"),
        Err(CoreError::AlreadyExists)
    ));
}

#[test]
fn values_with_crlf_or_nul_or_empty_are_rejected() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    for bad in ["a\r\nX-Evil: 1", "a\nb", "a\0b", ""] {
        assert!(
            matches!(
                v.add_secret("s", bad),
                Err(CoreError::InvalidSecretValue(_))
            ),
            "{bad:?}"
        );
    }
    assert!(matches!(
        v.add_secret("Bad Name!", "x"),
        Err(CoreError::InvalidName(_))
    ));
}

#[test]
fn database_file_never_contains_plaintext_secret() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.db");
    let v = Vault::init(&path, raw(&crypto::random_key())).unwrap();
    v.add_secret("tok", "PLAINTEXT-MARKER-12345").unwrap();
    drop(v);
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(22).any(|w| w == b"PLAINTEXT-MARKER-12345"));
    }
}

#[test]
fn database_file_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.db");
    Vault::init(&path, raw(&crypto::random_key())).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn removing_secret_referenced_by_a_rule_is_in_use() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    let meta = v.add_secret("tok", "x").unwrap();
    {
        let c = v.conn();
        c.execute(
            "INSERT INTO roles (name, unmatched_policy) VALUES ('r', 'deny')",
            [],
        )
        .unwrap();
        c.execute(
            "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id) \
             VALUES ('r', 'h.com', '/*', '*', 'header', 'Authorization', '{secret}', ?1)",
            [meta.id],
        )
        .unwrap();
    }
    assert!(matches!(v.remove_secret("tok"), Err(CoreError::InUse)));
    assert_eq!(v.list_secrets().unwrap().len(), 1);
}

#[test]
fn too_long_value_is_rejected_and_secret_cannot_move_between_rows() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    assert!(matches!(
        v.add_secret("big", &"a".repeat(8193)),
        Err(CoreError::InvalidSecretValue(_))
    ));
    let a = v.add_secret("a", "AAA").unwrap();
    let b = v.add_secret("b", "BBB").unwrap();
    {
        let c = v.conn();
        let blob: Vec<u8> = c
            .query_row("SELECT value_enc FROM secrets WHERE id = ?1", [a.id], |r| {
                r.get(0)
            })
            .unwrap();
        c.execute(
            "UPDATE secrets SET value_enc = ?1 WHERE id = ?2",
            rusqlite::params![blob, b.id],
        )
        .unwrap();
    }
    assert!(v.reveal_for_injection(b.id).is_err());
}

#[test]
fn rotate_rejects_bad_values() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    v.add_secret("s", "ok").unwrap();
    for bad in ["a\r\nX-Evil: 1", "a\nb", "a\rb", "a\0b", ""] {
        assert!(
            matches!(
                v.rotate_secret("s", bad),
                Err(CoreError::InvalidSecretValue(_))
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn raw_key_vault_rejects_passphrase() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("r.db");
    Vault::init(&path, raw(&crypto::random_key())).unwrap();
    assert!(matches!(
        Vault::open(&path, KeyInput::Passphrase("pw".into()))
            .err()
            .unwrap(),
        CoreError::KeySourceMismatch
    ));
}

#[test]
fn value_length_boundary_is_8192() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    v.add_secret("ok", &"a".repeat(8192)).unwrap();
    assert!(matches!(
        v.add_secret("big", &"a".repeat(8193)),
        Err(CoreError::InvalidSecretValue(_))
    ));
    v.rotate_secret("ok", &"b".repeat(8192)).unwrap();
    assert!(matches!(
        v.rotate_secret("ok", &"b".repeat(8193)),
        Err(CoreError::InvalidSecretValue(_))
    ));
}

#[test]
fn wal_and_shm_files_are_private_while_open() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    let path = dir.path().join("v.db");
    let v = Vault::init(&path, raw(&crypto::random_key())).unwrap();
    v.add_secret("tok", "x").unwrap();
    let mut seen = 0;
    for suffix in ["-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        if let Ok(m) = std::fs::metadata(&name) {
            seen += 1;
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "{suffix}");
        }
    }
    assert!(seen > 0, "expected WAL side files while vault is open");
    drop(v);
}

#[test]
fn open_missing_path_errors_and_creates_nothing() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("missing.db");
    let err = Vault::open(&path, raw(&crypto::random_key()))
        .err()
        .unwrap();
    match err {
        CoreError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected Io(NotFound), got {other:?}"),
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn open_or_init_still_creates_missing_vault() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("new.db");
    let key = crypto::random_key();
    Vault::open_or_init(&path, raw(&key)).unwrap();
    Vault::open_or_init(&path, raw(&key)).unwrap();
}

fn set_schema_version(path: &std::path::Path, value: &str) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
        [value.as_bytes()],
    )
    .unwrap();
}

#[test]
fn unsupported_schema_version_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let key = crypto::random_key();
    Vault::init(&path, raw(&key)).unwrap();
    set_schema_version(&path, "2");
    let err = Vault::open(&path, raw(&key)).err().unwrap();
    assert!(matches!(
        err,
        CoreError::UnsupportedSchema {
            found: 2,
            supported: 1
        }
    ));
    assert_eq!(
        err.to_string(),
        "database schema version 2 is not supported by this build (supports 1)"
    );
}

#[test]
fn non_numeric_schema_version_is_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let key = crypto::random_key();
    Vault::init(&path, raw(&key)).unwrap();
    set_schema_version(&path, "abc");
    assert!(Vault::open(&path, raw(&key)).is_err());
}

#[test]
fn wrong_key_on_unsupported_schema_still_reports_wrong_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.db");
    Vault::init(&path, raw(&crypto::random_key())).unwrap();
    set_schema_version(&path, "2");
    let err = Vault::open(&path, raw(&crypto::random_key()))
        .err()
        .unwrap();
    assert!(matches!(err, CoreError::WrongKey));
}
