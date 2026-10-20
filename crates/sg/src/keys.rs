use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use sg_core::{crypto, KeyInput};
use std::{
    io::{IsTerminal, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Where the master key comes from. Exactly one source must be chosen.
pub struct KeySource {
    pub key_file: Option<PathBuf>,
    /// Base64 of 32 bytes, from the `SC_MASTER_KEY` environment variable.
    pub master_key: Option<String>,
    pub passphrase: bool,
}

/// Writes a fresh random key (base64 of 32 bytes) to a new file with mode 0600.
/// Refuses to overwrite anything.
pub fn write_new_key_file(path: &Path) -> anyhow::Result<()> {
    let key = crypto::random_key();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {} (it must not exist yet)", path.display()))?;
    f.write_all(STANDARD.encode(*key).as_bytes())?;
    Ok(())
}

/// Resolves the key source. `confirm_passphrase` asks twice (first creation of a vault).
/// Errors never contain key material.
pub fn resolve_key(src: &KeySource, confirm_passphrase: bool) -> anyhow::Result<KeyInput> {
    let chosen = [
        src.key_file.is_some(),
        src.master_key.is_some(),
        src.passphrase,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    match chosen {
        0 => bail!("no key source: use --key-file, SC_MASTER_KEY or --passphrase"),
        1 => {}
        _ => bail!(
            "ambiguous key source: use exactly one of --key-file, SC_MASTER_KEY, --passphrase"
        ),
    }
    if let Some(p) = &src.key_file {
        let meta = std::fs::metadata(p)
            .with_context(|| format!("cannot read key file {}", p.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!(
                "key file {} is accessible to group/others (mode {:o}); run `chmod 600 {}`",
                p.display(),
                meta.permissions().mode() & 0o777,
                p.display()
            );
        }
        let text = std::fs::read_to_string(p)
            .with_context(|| format!("cannot read key file {}", p.display()))?;
        return Ok(KeyInput::Raw(
            crypto::kek_from_base64(&text).map_err(|_| bad_key())?,
        ));
    }
    if let Some(v) = &src.master_key {
        return Ok(KeyInput::Raw(
            crypto::kek_from_base64(v).map_err(|_| bad_key())?,
        ));
    }
    if !std::io::stdin().is_terminal() {
        bail!("--passphrase needs a terminal to prompt on; use --key-file or SC_MASTER_KEY when running unattended");
    }
    let pw = rpassword::prompt_password("Vault passphrase: ")?;
    if pw.is_empty() {
        bail!("the passphrase must not be empty");
    }
    if confirm_passphrase && rpassword::prompt_password("Repeat passphrase: ")? != pw {
        bail!("passphrases do not match");
    }
    Ok(KeyInput::Passphrase(pw))
}

fn bad_key() -> anyhow::Error {
    anyhow::anyhow!(
        "the key is not valid: expected base64 of exactly 32 bytes (generate one with `sc keygen`)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::os::unix::fs::PermissionsExt;

    fn file_src(p: &std::path::Path) -> KeySource {
        KeySource {
            key_file: Some(p.to_path_buf()),
            master_key: None,
            passphrase: false,
        }
    }

    #[test]
    fn key_file_must_hold_32_bytes_base64_and_be_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.key");
        write_new_key_file(&p).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(matches!(
            resolve_key(&file_src(&p), false).unwrap(),
            sg_core::KeyInput::Raw(_)
        ));
        assert!(
            write_new_key_file(&p).is_err(),
            "must not overwrite an existing key"
        );
    }

    #[test]
    fn master_key_env_value_is_decoded() {
        let src = KeySource {
            key_file: None,
            master_key: Some(STANDARD.encode([9u8; 32])),
            passphrase: false,
        };
        assert!(matches!(
            resolve_key(&src, false).unwrap(),
            sg_core::KeyInput::Raw(_)
        ));
    }

    #[test]
    fn no_key_source_is_an_error_and_two_sources_are_ambiguous() {
        let none = KeySource {
            key_file: None,
            master_key: None,
            passphrase: false,
        };
        assert!(resolve_key(&none, false).is_err());
        let both = KeySource {
            key_file: Some("/x".into()),
            master_key: Some("y".into()),
            passphrase: false,
        };
        assert!(resolve_key(&both, false).is_err());
        let pass_and_file = KeySource {
            key_file: Some("/x".into()),
            master_key: None,
            passphrase: true,
        };
        assert!(resolve_key(&pass_and_file, false).is_err());
    }

    #[test]
    fn group_or_other_readable_key_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.key");
        write_new_key_file(&p).unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            let e = resolve_key(&file_src(&p), false)
                .err()
                .expect("must refuse");
            assert!(e.to_string().contains("chmod 600"), "{mode:o}: {e}");
        }
    }

    #[test]
    fn malformed_keys_are_rejected_without_echoing_them() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.key");
        std::fs::write(&p, "SUPER-SECRET-NOT-A-KEY").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = format!("{:#}", resolve_key(&file_src(&p), false).err().unwrap());
        assert!(!e.contains("SUPER-SECRET"), "{e}");
        let src = KeySource {
            key_file: None,
            master_key: Some(STANDARD.encode([1u8; 16])),
            passphrase: false,
        };
        let e = format!("{:#}", resolve_key(&src, false).err().unwrap());
        assert!(!e.contains(&STANDARD.encode([1u8; 16])), "{e}");
    }

    #[test]
    fn missing_key_file_is_reported_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let e = resolve_key(&file_src(&dir.path().join("nope")), false)
            .err()
            .unwrap();
        assert!(e.to_string().contains("cannot read key file"), "{e}");
    }
}
