# Secret Guardian (fase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un vault de secretos en Rust, binario único y imagen Docker, cuyo proxy MITM inyecta credenciales en las peticiones de agentes de IA según el rol de su token, sin que el agente vea nunca el secreto.

**Architecture:** Workspace de crates (`core`, `policy`, `auth`, `ca`, `proxy`, `admin`, `cli`, `sg`) en un solo proceso `tokio`. El proxy (`hyper` + `tokio-rustls`) autentica por `Proxy-Authorization`, termina TLS con una CA acotada por name constraints (`rcgen`) y reenvía en streaming. El estado vive en SQLite con valores cifrados AES-256-GCM bajo una DEK envuelta por la clave maestra. La administración es una API `axum` servida por socket Unix (CLI) y por `127.0.0.1` (web embebida).

**Tech Stack:** Rust estable, tokio, hyper 1, rustls 0.23 (ring), tokio-rustls, rcgen 0.13, rusqlite (bundled), aes-gcm, argon2, ed25519-dalek, axum 0.8, clap 4, rust-embed.

**Spec:** `docs/specs/2026-10-16-secret-guardian-vault.md` (leerla antes de empezar; este plan la implementa entera).

> **Nota de ejecución:** el código de este plan es la implementación de referencia, escrita sin poder compilar (no había `cargo` al redactarla). Cada tarea termina con `cargo test -p <crate>` y el implementador debe corregir los errores de compilación o de versión de crates que aparezcan sin cambiar el comportamiento ni los tests. Si una API de un crate difiere, comprobar su documentación con Context7 antes de improvisar. Los mensajes de commit terminan con la línea `Co-Authored-By` que dicte el harness.

## Global Constraints

- Rust estable (`rust-toolchain.toml`), edición 2021; sin `unsafe`.
- Binario `sg`, paquete `secret-guardian`. Puertos por defecto: proxy `127.0.0.1:8080`, web `127.0.0.1:9090`.
- Cifrado: AES-256-GCM, nonce aleatorio de 96 bits por valor, AAD = identificador del registro. KDF: Argon2id con sal guardada en la DB. Una DEK aleatoria de 32 bytes envuelta por la KEK cifra valores secretos, clave privada de la CA y clave de firma de tokens.
- Fuentes de la KEK: `--key-file` / `SG_KEY_FILE`, `SG_MASTER_KEY` (base64), `--passphrase`.
- Tokens: JWT EdDSA con claims `iss`, `jti`, `sub` (máquina), `role`, `iat`, `exp` opcional; se envían en `Proxy-Authorization` como `Basic` (token en la contraseña) o `Bearer`.
- Proxy: `407` sin token válido, `403` sin regla o método no permitido, `502` si falla el destino; certificados de hoja de 24 h cacheados; sin almacenar cuerpos en memoria; entrada de audit escrita antes del primer byte de respuesta al agente.
- Ninguna ruta de API, CLI ni web devuelve el valor de un secreto guardado. Los valores secretos y los tokens nunca se registran en logs. El audit no guarda query strings.
- Los valores de secreto no pueden contener CR, LF ni NUL; en `query` se codifican en porcentaje.
- Las reglas comparan hostname normalizado (minúsculas, sin punto final, sin puerto); no admiten IPs. El path se normaliza y se reenvía normalizado.
- Inyección sobre HTTP en claro: `403` salvo host `localhost`.
- CA con name constraints siempre presentes (`invalid` si no hay dominios); `allow-domain` rechaza TLDs y dominios de una etiqueta (salvo `localhost`).
- CLI por socket Unix `$XDG_RUNTIME_DIR/secret-guardian.sock` con permisos `0600`; los valores de secreto se leen de stdin o de un prompt sin eco, nunca de argumentos.
- Web: solo `127.0.0.1` salvo `--admin-bind` explícito (con aviso); validación de `Host`; cookie `HttpOnly` + `SameSite=Strict`; cabecera anti-CSRF en escrituras; CSP restrictiva sin recursos de terceros; el frontend no usa `innerHTML`.
- Rama de trabajo: `feature/phase1-core`. Commits Conventional Commits por tarea. **Altitud de tests:** cada tarea ejecuta solo los tests de su crate; la suite completa corre una única vez en `/ship`. En `/ship` se ejecuta además `cargo test --workspace --release -- --include-ignored` (incluye el test exhaustivo de rutas de `policy`, ~40 s).

## Review Focus

Entradas que la spec implica y que ninguna tarea de "camino feliz" cubriría. Cada una tiene su test en la tarea indicada.

1. Secreto o plantilla con CR/LF/NUL (inyección de cabeceras): rechazado al guardar y al renderizar. Tareas 2 y 3.
2. El agente envía por su cuenta la cabecera o el parámetro que el vault inyecta (variantes de mayúsculas, valores duplicados): el valor del agente se descarta. Tarea 8.
3. Host con mayúsculas, punto final, puerto, forma de IP, o `Host` distinto del destino del `CONNECT`: normalizado o rechazado (`421`), nunca una regla equivocada. Tareas 3 y 8.
4. Path con reglas de path distintas de `*`: **cerrado por construcción**. Se juzgan todas las lecturas `R_d` (decodificación porcentual 0..8 veces) y se exige que NINGUNA contenga un segmento punto (`.`, `..`, `...`, `.. `, `..+`, solo puntos/espacios/tab/`+`) separando por `/`, `\`, `;`, `?` y `#` a la vez; así resolver segmentos punto es la identidad en cualquier modelo de origen y ningún orden de operaciones (decodificar, quitar `;params`, cortar en `?`/`#`, `\` como `/`) puede salir del prefijo. Cada `R_d` debe empezar por el prefijo del patrón decodificado `d` veces (igualdad exacta para patrones sin `*`). Lo no juzgable falla cerrado con `403` (solo `*` lo admite): `%` mal formado en el path crudo, `%uXXXX`, UTF-8 inválido, NUL/controles C0/DEL, confusables Unicode de `.`/`/`/`\`, espacios y caracteres invisibles no ASCII (NBSP, U+200B, U+FF1F, U+FE68...), más de 8 capas, más de 8 KiB. Los patrones que podrían ensancharse a sí mismos se rechazan al crear la regla. Una regla `GET /repos/*` no autoriza `/repos/../admin`, `/repos/..%2fadmin` ni `/repos/a%2F..%2Fb` (los `..`/`%2e%2e` simples los resuelve `normalize_path` antes de juzgar), pero sí `/repos/a%2Fb`. Una regla más específica con método excluido da `403` (no cae a una más amplia del mismo destino; otro destino, p. ej. un parámetro de query, sí puede aportar). Tareas 3 y 8.
5. Petición `http://` en claro a un host con reglas: no se envía el secreto por la red. Tarea 9.

---

### Task 0: Toolchain y esqueleto del workspace

**Files:**
- Create: `rust-toolchain.toml`, `Cargo.toml`, `.gitignore`
- Create: `crates/{core,policy,auth,ca,proxy,admin,cli,sg}/Cargo.toml` y `src/lib.rs` (`sg`: `src/main.rs`)

**Interfaces:**
- Produces: workspace compilable con los ocho crates vacíos y todas las dependencias declaradas, para que las tareas siguientes no toquen manifiestos.

- [ ] **Step 1: Instalar el toolchain**

```bash
sudo dnf install -y gcc rustup   # Fedora; alternativa: curl https://sh.rustup.rs | sh
rustup-init -y && source ~/.cargo/env
cargo --version
```
Expected: `cargo 1.8x.x`.

- [ ] **Step 2: Crear la rama**

```bash
git checkout -b feature/phase1-core   # parte de docs/vault-spec, que contiene spec y plan
```

- [ ] **Step 3: Escribir los manifiestos**

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`.gitignore`:
```
/target
*.db
*.db-wal
*.db-shm
*.key
*.sock
```

`Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = ["crates/core", "crates/policy", "crates/auth", "crates/ca", "crates/proxy", "crates/admin", "crates/cli", "crates/sg"]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
sg-core = { path = "crates/core" }
sg-policy = { path = "crates/policy" }
sg-auth = { path = "crates/auth" }
sg-ca = { path = "crates/ca" }
sg-proxy = { path = "crates/proxy" }
sg-admin = { path = "crates/admin" }
sg-cli = { path = "crates/cli" }

anyhow = "1"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
rusqlite = { version = "0.32", features = ["bundled"] }
aes-gcm = { version = "0.10", features = ["zeroize"] }
argon2 = "0.5"
rand = "0.8"
zeroize = "1"
base64 = "0.22"
hex = "0.4"
sha2 = "0.10"
uuid = { version = "1", features = ["v4"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
rcgen = { version = "0.13", default-features = false, features = ["ring", "pem"] }
time = "0.3"
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12"] }
rustls-pemfile = "2"
rustls-native-certs = "0.8"
hyper = { version = "1", features = ["server", "client", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto", "http1", "http2"] }
http = "1"
http-body-util = "0.1"
bytes = "1"
percent-encoding = "2"
axum = "0.8"
tower = { version = "0.5", features = ["util"] }
rust-embed = "8"
clap = { version = "4", features = ["derive", "env"] }
rpassword = "7"
tempfile = "3"
assert_cmd = "2"
```

Cada `crates/<x>/Cargo.toml` sigue este patrón (ejemplo `core`; sustituir nombre y dependencias según la tabla):
```toml
[package]
name = "sg-core"
version.workspace = true
edition.workspace = true

[dependencies]
rusqlite.workspace = true
aes-gcm.workspace = true
argon2.workspace = true
rand.workspace = true
zeroize.workspace = true
base64.workspace = true
hex.workspace = true
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

| Crate (paquete) | dependencies | dev-dependencies |
|---|---|---|
| `core` (`sg-core`) | ver arriba | tempfile |
| `policy` (`sg-policy`) | sg-core, rusqlite, thiserror, http, percent-encoding, serde | tempfile |
| `auth` (`sg-auth`) | sg-core, rusqlite, ed25519-dalek, rand, base64, hex, sha2, serde, serde_json, thiserror, uuid | tempfile |
| `ca` (`sg-ca`) | sg-core, rusqlite, rcgen, rustls, rustls-pemfile, time, thiserror, serde_json, tracing | tokio, tokio-rustls, tempfile |
| `proxy` (`sg-proxy`) | sg-core, sg-policy, sg-auth, sg-ca, tokio, hyper, hyper-util, http, http-body-util, bytes, tokio-rustls, rustls, rustls-native-certs, rustls-pemfile, percent-encoding, thiserror, tracing, zeroize | tempfile, rcgen, serde_json, base64 |
| `admin` (`sg-admin`) | sg-core, sg-policy, sg-auth, sg-ca, axum, tokio, serde, serde_json, rust-embed, rand, hex, tracing, thiserror, http | tower, http-body-util, bytes, tempfile |
| `cli` (`sg-cli`) | sg-core, clap, tokio, hyper, hyper-util, http-body-util, bytes, http, serde_json, rpassword, anyhow | axum, tempfile |
| `sg` (`sg`, binario) | todos los `sg-*`, clap, tokio, anyhow, tracing, tracing-subscriber, rpassword, base64, rand, hex, rustls, rustls-pemfile | assert_cmd, tempfile |

Cada `lib.rs` queda en `// placeholder: se rellena en su tarea` solo durante este paso; `crates/sg/src/main.rs` es `fn main() {}`.

- [ ] **Step 4: Verificar que compila**

Run: `cargo check --workspace`
Expected: `Finished` sin errores (descarga de dependencias incluida).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "chore: scaffold cargo workspace for phase 1"
```

---

### Task 1: `core::crypto`

**Files:**
- Create: `crates/core/src/error.rs`, `crates/core/src/crypto.rs`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Produces:
  - `pub type Key32 = Zeroizing<[u8; 32]>`
  - `pub fn random_key() -> Key32`, `pub fn random_bytes<const N: usize>() -> [u8; N]`
  - `pub fn kek_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Key32, CoreError>`
  - `pub fn kek_from_base64(s: &str) -> Result<Key32, CoreError>`
  - `pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8>` (formato `nonce(12) || ciphertext+tag`)
  - `pub fn open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError>`
  - `pub enum CoreError { WrongKey, KeySourceMismatch, InvalidKey, InvalidSecretValue(&'static str), InvalidName(&'static str), NotFound, AlreadyExists, InUse, Crypto, Db(rusqlite::Error), Io(std::io::Error) }`

- [ ] **Step 1: Escribir los tests que fallan** (en `crypto.rs`, módulo `tests`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_key();
        let blob = seal(&key, b"aad", b"hello");
        assert_eq!(&**open(&key, b"aad", &blob).unwrap(), b"hello");
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let blob = seal(&random_key(), b"aad", b"hello");
        assert!(open(&random_key(), b"aad", &blob).is_err());
    }

    #[test]
    fn open_with_wrong_aad_fails() {
        let key = random_key();
        let blob = seal(&key, b"secret:1", b"hello");
        assert!(open(&key, b"secret:2", &blob).is_err());
    }

    #[test]
    fn open_rejects_short_or_tampered_blob() {
        let key = random_key();
        assert!(open(&key, b"a", &[0u8; 5]).is_err());
        let mut blob = seal(&key, b"a", b"hello");
        *blob.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"a", &blob).is_err());
    }

    #[test]
    fn nonce_is_random_per_seal() {
        let key = random_key();
        assert_ne!(seal(&key, b"a", b"x"), seal(&key, b"a", b"x"));
    }

    #[test]
    fn passphrase_kdf_is_deterministic_for_same_salt() {
        let salt = [7u8; 16];
        let a = kek_from_passphrase("correct horse", &salt).unwrap();
        let b = kek_from_passphrase("correct horse", &salt).unwrap();
        let c = kek_from_passphrase("other", &salt).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn base64_key_must_be_32_bytes() {
        assert!(kek_from_base64("AAAA").is_err());
        let ok = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);
        assert_eq!(*kek_from_base64(&ok).unwrap(), [1u8; 32]);
    }
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-core crypto`
Expected: FAIL (no compila: `seal` no definido).

- [ ] **Step 3: Implementar**

`error.rs`:
```rust
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("wrong key or corrupted vault")]
    WrongKey,
    #[error("the vault was created with a different key source")]
    KeySourceMismatch,
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
```

`crypto.rs` (encima de los tests):
```rust
use crate::error::CoreError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

pub type Key32 = Zeroizing<[u8; KEY_LEN]>;

pub fn random_key() -> Key32 {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(&mut *k);
    k
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Explicit Argon2id cost parameters: a future crate default change must never alter existing vaults.
fn argon2id() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, Some(KEY_LEN)).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn kek_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Key32, CoreError> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2id()
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|_| CoreError::Crypto)?;
    Ok(out)
}

pub fn kek_from_base64(s: &str) -> Result<Key32, CoreError> {
    let bytes = Zeroizing::new(STANDARD.decode(s.trim()).map_err(|_| CoreError::InvalidKey)?);
    let arr: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| CoreError::InvalidKey)?;
    Ok(Zeroizing::new(arr))
}

pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("aes-gcm encryption cannot fail for in-memory buffers");
    let mut out = nonce.to_vec();
    out.extend(ct);
    out
}

pub fn open(key: &[u8; KEY_LEN], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    if blob.len() < NONCE_LEN + 16 {
        return Err(CoreError::Crypto);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Crypto)
}
```

`lib.rs`:
```rust
pub mod crypto;
pub mod error;
pub use error::CoreError;
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-core crypto`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): add AES-256-GCM sealing and key derivation"
```

---

### Task 2: `core::vault` (almacén SQLite y secretos)

**Files:**
- Create: `crates/core/src/schema.rs`, `crates/core/src/vault.rs`, `crates/core/src/secrets.rs`, `crates/core/src/paths.rs`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: `crypto::{Key32, random_key, random_bytes, kek_from_passphrase, seal, open}`, `CoreError`.
- Produces:
  - `pub enum KeyInput { Raw(Key32), Passphrase(String) }`
  - `pub struct Vault` con `init(path: &Path, key: KeyInput) -> Result<Vault>`, `open(path, key) -> Result<Vault>`, `open_or_init(path, key)`, `conn(&self) -> MutexGuard<'_, Connection>`, `seal_value(&self, aad: &[u8], pt: &[u8]) -> Vec<u8>`, `open_value(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>>`
  - `pub struct SecretMeta { id: i64, name: String, created_at: i64, rotated_at: Option<i64> }` (`Serialize`)
  - En `Vault`: `add_secret(&self, name: &str, value: &str) -> Result<SecretMeta>`, `rotate_secret(&self, name, value) -> Result<SecretMeta>`, `remove_secret(&self, name) -> Result<()>` (`InUse` si hay reglas), `list_secrets() -> Result<Vec<SecretMeta>>`, `get_secret_meta(name) -> Result<SecretMeta>`, `reveal_for_injection(&self, id: i64) -> Result<Zeroizing<String>>`
  - `pub fn now() -> i64` (segundos Unix) en `lib.rs`
  - `paths::default_data_dir() -> PathBuf`, `paths::default_socket() -> PathBuf`

- [ ] **Step 1: Escribir los tests que fallan** (`crates/core/tests/vault.rs`)

```rust
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
    let err = Vault::open(&path, raw(&crypto::random_key())).err().unwrap();
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
        Vault::open(&p1, KeyInput::Passphrase("bad".into())).err().unwrap(),
        CoreError::WrongKey
    ));
}

#[test]
fn secret_lifecycle_and_metadata_only_listing() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    let meta = v.add_secret("github-pat", "ghp_SUPERSECRET").unwrap();
    assert_eq!(v.list_secrets().unwrap().len(), 1);
    assert_eq!(&**v.reveal_for_injection(meta.id).unwrap(), "ghp_SUPERSECRET");
    let rotated = v.rotate_secret("github-pat", "ghp_NEW").unwrap();
    assert!(rotated.rotated_at.is_some());
    assert_eq!(&**v.reveal_for_injection(meta.id).unwrap(), "ghp_NEW");
    v.remove_secret("github-pat").unwrap();
    assert!(v.list_secrets().unwrap().is_empty());
    assert!(matches!(v.remove_secret("github-pat"), Err(CoreError::NotFound)));
}

#[test]
fn duplicate_name_is_rejected() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    v.add_secret("a", "x").unwrap();
    assert!(matches!(v.add_secret("a", "y"), Err(CoreError::AlreadyExists)));
}

#[test]
fn values_with_crlf_or_nul_or_empty_are_rejected() {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), raw(&crypto::random_key())).unwrap();
    for bad in ["a\r\nX-Evil: 1", "a\nb", "a\0b", ""] {
        assert!(matches!(v.add_secret("s", bad), Err(CoreError::InvalidSecretValue(_))), "{bad:?}");
    }
    assert!(matches!(v.add_secret("Bad Name!", "x"), Err(CoreError::InvalidName(_))));
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
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-core --test vault`
Expected: FAIL (no compila: `Vault` no definido).

- [ ] **Step 3: Implementar**

`schema.rs`:
```rust
pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA: &str = r#"
CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    value_enc BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    rotated_at INTEGER
);
CREATE TABLE roles (
    name TEXT PRIMARY KEY,
    unmatched_policy TEXT NOT NULL CHECK (unmatched_policy IN ('passthrough','deny'))
);
CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    host_pattern TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    methods TEXT NOT NULL,
    injection_kind TEXT NOT NULL CHECK (injection_kind IN ('header','query')),
    target_name TEXT NOT NULL,
    template TEXT NOT NULL,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE RESTRICT
);
CREATE TABLE tokens (
    jti TEXT PRIMARY KEY,
    machine TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    revoked_at INTEGER,
    token_hash TEXT NOT NULL
);
CREATE TABLE audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    jti TEXT, machine TEXT, role TEXT,
    host TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL,
    rule_id INTEGER, decision TEXT NOT NULL, status INTEGER
);
CREATE INDEX audit_ts ON audit(ts);
CREATE TABLE ca (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    cert_pem TEXT NOT NULL,
    key_enc BLOB NOT NULL,
    domains TEXT NOT NULL
);
"#;
```

`vault.rs`:
```rust
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
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        // Any failure after the file exists removes path, path-wal and path-shm.
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
                ("argon2id", salt.to_vec(), crypto::kek_from_passphrase(&p, &salt)?)
            }
        };
        let dek = crypto::random_key();
        let wrapped = crypto::seal(&kek, DEK_AAD, &*dek);
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Schema and meta rows land atomically.
        let tx = conn.transaction()?;
        tx.execute_batch(SCHEMA)?;
        {
            let mut put = tx.prepare("INSERT INTO meta (key, value) VALUES (?1, ?2)")?;
            put.execute(params!["schema_version", SCHEMA_VERSION.to_string().into_bytes()])?;
            put.execute(params!["kdf", kdf.as_bytes()])?;
            put.execute(params!["salt", salt])?;
            put.execute(params!["dek_wrapped", wrapped])?;
        }
        before_commit(&tx)?;
        tx.commit()?;
        Ok(Self { conn: Mutex::new(conn), dek })
    }

    pub fn open(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let kdf = meta_get(&conn, "kdf")?;
        let kek = match (kdf.as_slice(), key) {
            (b"raw", KeyInput::Raw(k)) => k,
            (b"argon2id", KeyInput::Passphrase(p)) => {
                let salt: [u8; 16] = meta_get(&conn, "salt")?.try_into().map_err(|_| CoreError::WrongKey)?;
                crypto::kek_from_passphrase(&p, &salt)?
            }
            _ => return Err(CoreError::KeySourceMismatch),
        };
        let wrapped = meta_get(&conn, "dek_wrapped")?;
        let dek_bytes = crypto::open(&kek, DEK_AAD, &wrapped).map_err(|_| CoreError::WrongKey)?;
        let dek: [u8; 32] = dek_bytes.as_slice().try_into().map_err(|_| CoreError::WrongKey)?;
        Ok(Self { conn: Mutex::new(conn), dek: Zeroizing::new(dek) })
    }

    pub fn open_or_init(path: &Path, key: KeyInput) -> Result<Self, CoreError> {
        if path.exists() { Self::open(path, key) } else { Self::init(path, key) }
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        // Recover from poisoning: rusqlite rolls back any open transaction when it is dropped
        // during unwinding, so a panic cannot leave a half-applied write behind.
        self.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn seal_value(&self, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        crypto::seal(&self.dek, aad, plaintext)
    }

    pub fn open_value(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoreError> {
        crypto::open(&self.dek, aad, blob)
    }
}
```
`secrets.rs`:
```rust
use crate::{error::CoreError, now, vault::Vault};
use rusqlite::{params, OptionalExtension};
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
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-');
    if ok { Ok(()) } else { Err(CoreError::InvalidName("use [a-z0-9._-], max 64 chars")) }
}

fn aad(id: i64) -> Vec<u8> {
    format!("secret:{id}").into_bytes()
}

fn row_meta(r: &rusqlite::Row) -> rusqlite::Result<SecretMeta> {
    Ok(SecretMeta { id: r.get(0)?, name: r.get(1)?, created_at: r.get(2)?, rotated_at: r.get(3)? })
}

fn lookup(conn: &Connection, name: &str) -> Result<SecretMeta, CoreError> {
    conn.query_row("SELECT id, name, created_at, rotated_at FROM secrets WHERE name = ?1", [name], row_meta)
        .optional()?
        .ok_or(CoreError::NotFound)
}

/// UPDATE/DELETE by id map "0 rows affected" to `NotFound`.
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
    if conn.execute("DELETE FROM secrets WHERE id = ?1", [id])? == 0 {
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
        let exists: bool = tx.query_row("SELECT COUNT(*) FROM secrets WHERE name = ?1", [name], |r| r.get::<_, i64>(0))? > 0;
        if exists {
            return Err(CoreError::AlreadyExists);
        }
        let ts = now();
        tx.execute("INSERT INTO secrets (name, value_enc, created_at) VALUES (?1, x'', ?2)", params![name, ts])?;
        let id = tx.last_insert_rowid();
        tx.execute("UPDATE secrets SET value_enc = ?1 WHERE id = ?2", params![self.seal_value(&aad(id), value.as_bytes()), id])?;
        tx.commit()?;
        Ok(SecretMeta { id, name: name.into(), created_at: ts, rotated_at: None })
    }

    pub fn rotate_secret(&self, name: &str, value: &str) -> Result<SecretMeta, CoreError> {
        validate_secret_value(value)?;
        // One guard for lookup and write so the row cannot vanish in between.
        let conn = self.conn();
        let meta = lookup(&conn, name)?;
        let ts = now();
        update_value(&conn, meta.id, &self.seal_value(&aad(meta.id), value.as_bytes()), ts)?;
        Ok(SecretMeta { rotated_at: Some(ts), ..meta })
    }

    pub fn remove_secret(&self, name: &str) -> Result<(), CoreError> {
        let conn = self.conn();
        let meta = lookup(&conn, name)?;
        let used: i64 = conn.query_row("SELECT COUNT(*) FROM rules WHERE secret_id = ?1", [meta.id], |r| r.get(0))?;
        if used > 0 {
            return Err(CoreError::InUse);
        }
        delete_by_id(&conn, meta.id)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretMeta>, CoreError> {
        let conn = self.conn();
        let mut st = conn.prepare("SELECT id, name, created_at, rotated_at FROM secrets ORDER BY name")?;
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
            .query_row("SELECT value_enc FROM secrets WHERE id = ?1", [id], |r| r.get(0))
            .optional()?
            .ok_or(CoreError::NotFound)?;
        let bytes = self.open_value(&aad(id), &blob)?;
        let s = String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::Crypto)?;
        Ok(Zeroizing::new(s))
    }
}
```

Tests añadidos tras la revisión (en el código): `init` fallido limpia ficheros y permite reintento (`vault::tests`), 0-filas => `NotFound` (`secrets::tests`), `paths::tests` con variables vacías, y en `tests/vault.rs` rotate con CR/LF/NUL/vacío, raw-vault con passphrase, límite 8192/8193 y modo 0600 de `-wal`/`-shm`.

`paths.rs`:
```rust
use std::ffi::OsString;
use std::path::PathBuf;

/// Absolute fallback when neither XDG_DATA_HOME nor HOME gives an absolute path.
const FALLBACK_DIR: &str = "/tmp/secret-guardian";

fn absolute(v: Option<OsString>) -> Option<PathBuf> {
    v.map(PathBuf::from).filter(|p| p.is_absolute())
}

fn data_dir_from(xdg_data_home: Option<OsString>, home: Option<OsString>) -> PathBuf {
    if let Some(d) = absolute(xdg_data_home) {
        return d.join("secret-guardian");
    }
    if let Some(h) = absolute(home) {
        return h.join(".local/share/secret-guardian");
    }
    PathBuf::from(FALLBACK_DIR)
}

fn socket_from(xdg_runtime_dir: Option<OsString>, data_dir: PathBuf) -> PathBuf {
    match absolute(xdg_runtime_dir) {
        Some(d) => d.join("secret-guardian.sock"),
        None => data_dir.join("sg.sock"),
    }
}

/// Always absolute: empty/relative env vars are ignored.
pub fn default_data_dir() -> PathBuf {
    data_dir_from(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

pub fn default_socket() -> PathBuf {
    socket_from(std::env::var_os("XDG_RUNTIME_DIR"), default_data_dir())
}
```

`lib.rs`:
```rust
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
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-core`
Expected: todos pasan (crypto + vault).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): add encrypted sqlite vault and secret store"
```

---

### Task 3: `policy` (roles, reglas, matching, renderizado)

**Files:**
- Create: `crates/policy/src/{model.rs,normalize.rs,matcher.rs,render.rs,store.rs}`
- Modify: `crates/policy/src/lib.rs`
- Test: `crates/policy/tests/policy.rs`, tests unitarios en cada módulo

**Interfaces:**
- Consumes: `sg_core::{Vault, CoreError}`.
- Produces:
  - `enum Unmatched { Passthrough, Deny }` (`as_str`, `FromStr`), `struct Role { name: String, unmatched: Unmatched }`
  - `enum InjectionKind { Header, Query }`
  - `struct Rule { id: i64, role: String, host_pattern: String, path_pattern: String, methods: Vec<String>, kind: InjectionKind, target_name: String, template: String, secret_id: i64 }` (`Serialize`)
  - `struct NewRule { role, host_pattern, path_pattern, methods, kind, target_name, template, secret_id }` (`Deserialize`)
  - `fn normalize_host(&str) -> Option<String>`, `fn normalize_path(&str) -> String`
  - `enum Decision<'a> { NoRuleForHost, Forbidden, Inject(Vec<&'a Rule>) }`
  - `fn evaluate<'a>(rules: &'a [Rule], host: &str, method: &str, path: &str) -> Decision<'a>`, `fn has_rules_for_host(rules: &[Rule], host: &str) -> bool`
  - `fn render(template: &str, secret: &str, kind: InjectionKind) -> Result<String, PolicyError>`
  - `PolicyError`, y funciones de almacén: `add_role(&Vault, &str, Unmatched)`, `get_role(&Vault, &str) -> Result<Option<Role>>`, `list_roles`, `remove_role`, `add_rule(&Vault, NewRule) -> Result<Rule>`, `list_rules(&Vault, Option<&str>) -> Result<Vec<Rule>>`, `remove_rule(&Vault, i64)`

- [ ] **Step 1: Escribir los tests que fallan**

`normalize.rs` (módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalization() {
        assert_eq!(normalize_host("API.GitHub.com."), Some("api.github.com".into()));
        assert_eq!(normalize_host("api.github.com:443"), Some("api.github.com".into()));
        assert_eq!(normalize_host("[::1]:8080"), Some("::1".into()));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host("a/b"), None);
    }

    #[test]
    fn path_normalization_resolves_traversal_and_escapes() {
        assert_eq!(normalize_path("/repos/../admin"), "/admin");
        assert_eq!(normalize_path("/repos/%2e%2e/admin"), "/admin");
        assert_eq!(normalize_path("/repos/%2E%2E/admin"), "/admin");
        assert_eq!(normalize_path("//repos///x"), "/repos/x");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/../.."), "/");
        assert_eq!(normalize_path("/repos/"), "/repos/");
        assert_eq!(normalize_path("/%41pi"), "/Api");
    }

    #[test]
    fn ip_literals_are_detected() {
        assert!(is_ip_literal("10.0.0.1"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("example.com"));
    }
}
```

`matcher.rs` (módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InjectionKind::*, Rule};

    fn rule(id: i64, host: &str, path: &str, methods: &[&str], kind: crate::model::InjectionKind, target: &str) -> Rule {
        Rule {
            id, role: "r".into(), host_pattern: host.into(), path_pattern: path.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(), kind,
            target_name: target.into(), template: "{secret}".into(), secret_id: 1,
        }
    }

    #[test]
    fn no_rule_for_host() {
        let rules = [rule(1, "api.github.com", "*", &[], Header, "Authorization")];
        assert!(matches!(evaluate(&rules, "example.com", "GET", "/"), Decision::NoRuleForHost));
    }

    #[test]
    fn method_and_path_restrict() {
        let rules = [rule(1, "api.github.com", "/repos/*", &["GET"], Header, "Authorization")];
        assert!(matches!(evaluate(&rules, "api.github.com", "GET", "/repos/x"), Decision::Inject(_)));
        assert!(matches!(evaluate(&rules, "api.github.com", "POST", "/repos/x"), Decision::Forbidden));
        assert!(matches!(evaluate(&rules, "api.github.com", "GET", "/admin"), Decision::Forbidden));
    }

    #[test]
    fn wildcard_host_matches_exactly_one_label() {
        let rules = [rule(1, "*.example.com", "*", &[], Header, "X-Key")];
        assert!(matches!(evaluate(&rules, "api.example.com", "GET", "/"), Decision::Inject(_)));
        assert!(matches!(evaluate(&rules, "a.b.example.com", "GET", "/"), Decision::NoRuleForHost));
        assert!(matches!(evaluate(&rules, "example.com", "GET", "/"), Decision::NoRuleForHost));
    }

    #[test]
    fn header_and_query_rules_both_apply() {
        let rules = [
            rule(1, "api.x.com", "*", &[], Header, "Authorization"),
            rule(2, "api.x.com", "*", &[], Query, "api_key"),
        ];
        match evaluate(&rules, "api.x.com", "GET", "/") {
            Decision::Inject(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected injection"),
        }
    }

    #[test]
    fn more_specific_rule_wins_for_same_target() {
        let rules = [
            rule(1, "*.x.com", "*", &[], Header, "Authorization"),
            rule(2, "api.x.com", "*", &[], Header, "authorization"),
        ];
        match evaluate(&rules, "api.x.com", "GET", "/") {
            Decision::Inject(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].id, 2);
            }
            _ => panic!("expected injection"),
        }
    }

    #[test]
    fn traversal_cannot_escape_a_path_restricted_rule() {
        let rules = [rule(1, "api.github.com", "/repos/*", &["GET"], Header, "Authorization")];
        let p = crate::normalize::normalize_path("/repos/../admin");
        assert!(matches!(evaluate(&rules, "api.github.com", "GET", &p), Decision::Forbidden));
    }
}
```

`render.rs` (módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InjectionKind::*;

    #[test]
    fn header_template() {
        assert_eq!(render("Bearer {secret}", "tok", Header).unwrap(), "Bearer tok");
    }

    #[test]
    fn query_value_is_percent_encoded() {
        assert_eq!(render("{secret}", "a b&c=d", Query).unwrap(), "a%20b%26c%3Dd");
    }

    #[test]
    fn crlf_in_rendered_header_is_rejected() {
        assert!(render("Bearer {secret}", "x\r\nInjected: 1", Header).is_err());
        assert!(render("{secret}", "x\0y", Header).is_err());
    }
}
```

`tests/policy.rs` (almacén):
```rust
use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;
use tempfile::tempdir;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempdir().unwrap();
    let v = Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap();
    (dir, v)
}

fn new_rule(secret_id: i64) -> NewRule {
    NewRule {
        role: "developer".into(), host_pattern: "api.github.com".into(), path_pattern: "*".into(),
        methods: vec!["GET".into()], kind: InjectionKind::Header, target_name: "Authorization".into(),
        template: "Bearer {secret}".into(), secret_id,
    }
}

#[test]
fn role_and_rule_crud() {
    let (_d, v) = vault();
    let s = v.add_secret("gh", "tok").unwrap();
    add_role(&v, "developer", Unmatched::Passthrough).unwrap();
    let rule = add_rule(&v, new_rule(s.id)).unwrap();
    assert_eq!(list_rules(&v, Some("developer")).unwrap(), vec![rule.clone()]);
    assert!(list_rules(&v, Some("reviewer")).unwrap().is_empty());
    assert_eq!(get_role(&v, "developer").unwrap().unwrap().unmatched, Unmatched::Passthrough);
    remove_rule(&v, rule.id).unwrap();
    remove_role(&v, "developer").unwrap();
    assert!(get_role(&v, "developer").unwrap().is_none());
}

#[test]
fn secret_in_use_cannot_be_removed() {
    let (_d, v) = vault();
    let s = v.add_secret("gh", "tok").unwrap();
    add_role(&v, "developer", Unmatched::Deny).unwrap();
    add_rule(&v, new_rule(s.id)).unwrap();
    assert!(matches!(v.remove_secret("gh"), Err(sg_core::CoreError::InUse)));
}

#[test]
fn invalid_rules_are_rejected() {
    let (_d, v) = vault();
    let s = v.add_secret("gh", "tok").unwrap();
    add_role(&v, "developer", Unmatched::Deny).unwrap();
    let bad = |f: fn(&mut NewRule)| {
        let mut r = new_rule(s.id);
        f(&mut r);
        assert!(add_rule(&v, r).is_err());
    };
    bad(|r| r.host_pattern = "10.0.0.1".into());
    bad(|r| r.host_pattern = "*".into());
    bad(|r| r.host_pattern = "a.*.com".into());
    bad(|r| r.path_pattern = "repos".into());
    bad(|r| r.target_name = "Bad Header\r\n".into());
    bad(|r| r.template = "no placeholder".into());
    bad(|r| r.methods = vec!["GE T".into()]);
    bad(|r| r.role = "ghost".into());
    bad(|r| r.secret_id = 9999);
}
```
Añadir `sg-core` (ya está) y `tempfile` a dev-dependencies de `policy`.

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-policy`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar**

`model.rs`:
```rust
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unmatched { Passthrough, Deny }

impl Unmatched {
    pub fn as_str(&self) -> &'static str {
        match self { Unmatched::Passthrough => "passthrough", Unmatched::Deny => "deny" }
    }
}

impl FromStr for Unmatched {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s { "passthrough" => Ok(Self::Passthrough), "deny" => Ok(Self::Deny), _ => Err(()) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Role { pub name: String, pub unmatched: Unmatched }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectionKind { Header, Query }

impl InjectionKind {
    pub fn as_str(&self) -> &'static str {
        match self { Self::Header => "header", Self::Query => "query" }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rule {
    pub id: i64,
    pub role: String,
    pub host_pattern: String,
    pub path_pattern: String,
    pub methods: Vec<String>,
    pub kind: InjectionKind,
    pub target_name: String,
    pub template: String,
    pub secret_id: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewRule {
    pub role: String,
    pub host_pattern: String,
    #[serde(default = "star")]
    pub path_pattern: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub kind: InjectionKind,
    pub target_name: String,
    pub template: String,
    pub secret_id: i64,
}

fn star() -> String { "*".into() }

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid rule: {0}")]
    Invalid(&'static str),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error(transparent)]
    Core(#[from] sg_core::CoreError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}
```
`normalize.rs` (encima de los tests):
```rust
use std::net::IpAddr;

pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Lowercases, strips brackets, port and trailing dot. Returns None for anything that is not a plain hostname or IP.
pub fn normalize_host(input: &str) -> Option<String> {
    let s = input.trim();
    let host = if let Some(rest) = s.strip_prefix('[') {
        rest.split(']').next()?.to_string()
    } else if s.matches(':').count() == 1 {
        s.split(':').next()?.to_string()
    } else {
        s.to_string()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':' || b == b'_');
    if valid { Some(host) } else { None }
}

fn decode_unreserved(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(v) = segment.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
                    out.push(v as char);
                    i += 3;
                    continue;
                }
            }
        }
        let ch = segment[i..].chars().next().expect("index is on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Resolves `.`/`..`, decodes escapes of unreserved characters, collapses `//`. Encoded `/` stays encoded (forma reenviada). Para comparar reglas con path se usa `judge_readings` (más abajo), nunca la forma reenviada.
pub fn normalize_path(path: &str) -> String {
    let mut segs: Vec<String> = Vec::new();
    for raw in path.split('/') {
        let seg = decode_unreserved(raw);
        match seg.as_str() {
            "" | "." => {}
            ".." => { segs.pop(); }
            _ => segs.push(seg),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    out
}

const MAX_DECODE_ROUNDS: usize = 8;

/// One percent-decoding round. `first` is the round applied to the raw path: there a `%` that is
/// not followed by two hex digits makes the path unjudgeable. Later rounds only see `%` that
/// earlier decoding produced (e.g. `%25` -> `%`), which stay literal, except `%u`/`%U` (the
/// IIS-style `%uXXXX` escape some origins honour), which is never judgeable.
fn decode_round(input: &str, first: bool) -> Option<String> {
    let b = input.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            match (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                _ => {
                    if first || matches!(b.get(i + 1), Some(b'u' | b'U')) {
                        return None;
                    }
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    let text = String::from_utf8(out).ok()?;
    if text.contains('\0') {
        return None;
    }
    Some(text)
}

/// `[P, decode(P), decode(decode(P)), ...]` until the string stops changing. `None` when the path
/// cannot be judged safely: malformed `%`, NUL, invalid UTF-8, or more than 8 decoding layers.
pub(crate) fn decode_chain(p: &str) -> Option<Vec<String>> {
    if p.contains('\0') {
        return None;
    }
    let mut chain = vec![p.to_string()];
    for round in 0..=MAX_DECODE_ROUNDS {
        let next = decode_round(chain.last().expect("chain is never empty"), round == 0)?;
        if &next == chain.last().expect("chain is never empty") {
            return Some(chain);
        }
        if round == MAX_DECODE_ROUNDS {
            return None;
        }
        chain.push(next);
    }
    None
}

/// Longest path (bytes) a restricted rule will judge; anything longer is unjudgeable.
pub(crate) const MAX_JUDGED_PATH_LEN: usize = 8192;

/// Code points that some origin may fold, normalize or trim into `.`, `/`, `\`, `?`, `#`, a
/// space, or nothing (NFKC/NFKD look-alikes, invisible and format characters).
fn is_forbidden_unicode(c: char) -> bool {
    matches!(c,
        '\u{00A0}' | '\u{00AD}' | '\u{034F}' | '\u{037E}' | '\u{1680}' | '\u{180E}'
        | '\u{2000}'..='\u{200F}'
        | '\u{2024}'..='\u{2026}'
        | '\u{2028}'..='\u{202F}'
        | '\u{2044}'
        | '\u{2047}'..='\u{2049}'
        | '\u{205F}'..='\u{2064}'
        | '\u{2215}' | '\u{2216}' | '\u{29F8}' | '\u{3000}'
        | '\u{FE50}'..='\u{FE6B}'
        | '\u{FEFF}'
        | '\u{FF01}'..='\u{FF65}')
}

/// Control characters (C0, DEL), separator/dot look-alikes and non-ASCII whitespace: never
/// judgeable. Ordinary non-ASCII letters (accents, CJK, emoji) are fine.
fn has_forbidden_char(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_ascii_control() || is_forbidden_unicode(c) || (!c.is_ascii() && c.is_whitespace())
    })
}

/// A segment such as `.`, `..`, `...`, `.. `, `..+`: non-empty, has a `.`, only dots, spaces,
/// tabs and `+` (form-style space).
fn is_dot_like(seg: &str) -> bool {
    seg.contains('.') && seg.chars().all(|c| matches!(c, '.' | ' ' | '\t' | '+'))
}

/// True when any segment is dot-like under EVERY separator model at once (`/ \ ; ? #`), so that
/// resolving dot segments is the identity however an origin splits the path.
fn has_dot_segment(s: &str) -> bool {
    s.split(['/', '\\', ';', '?', '#']).any(is_dot_like)
}

/// Every reading `R_0..R_n` (percent-decoded 0..n times, until stable) of a path, used ONLY for
/// matching a restricted rule (the proxy forwards `normalize_path`). `None` means the path
/// cannot be judged: too long, undecodable, or some reading holds a control character, a
/// confusable, or a dot segment under any separator model. When this returns `Some`, there is
/// nothing to resolve, so no ordering of origin operations (decode, `;` strip, `?`/`#` cut,
/// `\` mapping, dot resolution) can move the request out of a prefix.
pub(crate) fn judge_readings(p: &str) -> Option<Vec<String>> {
    if p.len() > MAX_JUDGED_PATH_LEN {
        return None;
    }
    let chain = decode_chain(p)?;
    if chain
        .iter()
        .any(|c| has_forbidden_char(c) || has_dot_segment(c))
    {
        return None;
    }
    Some(chain)
}

/// True when any segment ends with `.` or a space (Windows-style trimming drops them).
fn has_trimmable_segment(s: &str) -> bool {
    s.split(['/', '\\', ';', '?', '#'])
        .any(|seg| seg.ends_with(['.', ' ']))
}

/// Pattern prefix/body readings: decoded until stable (same cap as paths).
pub(crate) fn pattern_readings(body: &str) -> Option<Vec<String>> {
    decode_chain(body)
}

/// True when a path PATTERN could widen itself: at any decoding depth its text contains `;`,
/// `\`, `?`, `#`, NUL or any control character, a forbidden Unicode character, a dot segment
/// (under any separator model), a segment ending in `.` or a space (origins that trim those
/// would reinterpret the prefix), or it cannot be decoded safely or is too long.
pub(crate) fn pattern_is_self_widening(body: &str) -> bool {
    if body.len() > MAX_JUDGED_PATH_LEN {
        return true;
    }
    let Some(chain) = decode_chain(body) else {
        return true;
    };
    chain.iter().any(|c| {
        c.contains([';', '\\', '?', '#'])
            || has_forbidden_char(c)
            || has_dot_segment(c)
            || has_trimmable_segment(c)
    })
}
```
`matcher.rs` (encima de los tests):
```rust
use crate::model::{InjectionKind, Rule};
use crate::normalize::{judge_readings, pattern_readings};
use std::cell::OnceCell;
use std::collections::HashMap;

pub enum Decision<'a> {
    NoRuleForHost,
    Forbidden,
    Inject(Vec<&'a Rule>),
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|h| h.strip_suffix('.'))
            .map(|label| !label.is_empty() && !label.contains('.'))
            .unwrap_or(false),
        None => false,
    }
}

/// Path matching, closed by construction. `readings` are the judged readings `R_0..R_n` of the
/// request path (`judge_readings`; `None` = unjudgeable, never matches a restricted rule). They
/// contain no dot segment under any separator model, so there is nothing for an origin to
/// resolve. A prefix pattern then needs `R_d` to start with the pattern prefix decoded `d` times
/// (its fixed point past its own chain), an exact pattern needs equality at every depth. `*`
/// matches everything.
fn path_matches(pattern: &str, readings: Option<&[String]>) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some(readings) = readings else {
        return false;
    };
    let (body, prefix) = match pattern.strip_suffix('*') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let Some(pat) = pattern_readings(body) else {
        return false;
    };
    let depths = readings.len().max(pat.len());
    (0..depths).all(|d| {
        let got = &readings[d.min(readings.len() - 1)];
        let want = &pat[d.min(pat.len() - 1)];
        if prefix {
            got.starts_with(want.as_str())
        } else {
            got == want
        }
    })
}

/// (exact host, wildcard suffix length, exact path, path pattern length): higher wins.
fn specificity(r: &Rule, host: &str) -> (bool, usize, bool, usize) {
    (
        r.host_pattern == host,
        if r.host_pattern.starts_with("*.") {
            r.host_pattern.len()
        } else {
            0
        },
        !r.path_pattern.ends_with('*'),
        r.path_pattern.len(),
    )
}

pub fn has_rules_for_host(rules: &[Rule], host: &str) -> bool {
    rules.iter().any(|r| host_matches(&r.host_pattern, host))
}

pub fn evaluate<'a>(rules: &'a [Rule], host: &str, method: &str, path: &str) -> Decision<'a> {
    if !has_rules_for_host(rules, host) {
        return Decision::NoRuleForHost;
    }
    // Judged lazily and once per call, only if a host-matching rule is path-restricted.
    let judged: OnceCell<Option<Vec<String>>> = OnceCell::new();
    // Candidates match host and path; methods are applied only AFTER the
    // specificity comparison so a narrower rule is never shadowed by a broader one.
    let mut groups: HashMap<(InjectionKind, String), Vec<&Rule>> = HashMap::new();
    for r in rules {
        if host_matches(&r.host_pattern, host)
            && (r.path_pattern == "*"
                || path_matches(&r.path_pattern, judged.get_or_init(|| judge_readings(path)).as_deref()))
        {
            groups
                .entry((r.kind, r.target_name.to_ascii_lowercase()))
                .or_default()
                .push(r);
        }
    }
    let mut chosen: Vec<&Rule> = Vec::new();
    for cands in groups.values() {
        let Some(top) = cands.iter().map(|r| specificity(r, host)).max() else {
            continue;
        };
        let winner = cands
            .iter()
            .filter(|r| specificity(r, host) == top)
            .filter(|r| {
                r.methods.is_empty() || r.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            })
            .min_by_key(|r| r.id);
        if let Some(r) = winner {
            chosen.push(r);
        }
    }
    if chosen.is_empty() {
        return Decision::Forbidden;
    }
    chosen.sort_by_key(|r| r.id);
    Decision::Inject(chosen)
}
```
`render.rs` (encima de los tests):
```rust
use crate::model::{InjectionKind, PolicyError};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub fn render(template: &str, secret: &str, kind: InjectionKind) -> Result<String, PolicyError> {
    let value = match kind {
        InjectionKind::Header => secret.to_string(),
        InjectionKind::Query => utf8_percent_encode(secret, NON_ALPHANUMERIC).to_string(),
    };
    let out = template.replace("{secret}", &value);
    if out.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(PolicyError::Invalid("rendered value contains CR, LF or NUL"));
    }
    Ok(out)
}
```
Nota: `NON_ALPHANUMERIC` codifica también `-._~`; es seguro y aceptable (el destino decodifica igual).

`store.rs`:
```rust
use crate::model::*;
use crate::normalize::{is_ip_literal, pattern_is_self_widening};
use rusqlite::{params, OptionalExtension};
use sg_core::Vault;

fn valid_host_pattern(p: &str) -> bool {
    let body = p.strip_prefix("*.").unwrap_or(p);
    !body.is_empty()
        && !is_ip_literal(body)
        && body.contains(|c: char| c.is_ascii_alphabetic())
        && !body.contains('*')
        && body.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        && p == p.to_ascii_lowercase()
}

fn validate(v: &Vault, r: &NewRule) -> Result<(), PolicyError> {
    if !valid_host_pattern(&r.host_pattern) {
        return Err(PolicyError::Invalid("host_pattern must be a lowercase hostname or *.hostname (no IPs)"));
    }
    // `*`, o path normalizado con `*` final opcional que no pueda ensancharse a sí mismo (ver `valid_path_pattern` en el código: hex en mayúsculas, sin `;?#\`, sin segmentos punto ni confusables ni segmentos que terminen en `.` o espacio en ninguna profundidad).
    if !(r.path_pattern == "*" || (r.path_pattern.starts_with('/') && !pattern_is_self_widening(r.path_pattern.strip_suffix('*').unwrap_or(&r.path_pattern)))) {
        return Err(PolicyError::Invalid("path_pattern must be * or a normalized path starting with / (optional trailing *)"));
    }
    if r.methods.iter().any(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic())) {
        return Err(PolicyError::Invalid("methods must be alphabetic HTTP methods"));
    }
    let name_ok = match r.kind {
        InjectionKind::Header => http::HeaderName::from_bytes(r.target_name.as_bytes()).is_ok(),
        InjectionKind::Query => !r.target_name.is_empty() && r.target_name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'),
    };
    if !name_ok {
        return Err(PolicyError::Invalid("invalid target_name"));
    }
    if !r.template.contains("{secret}") || r.template.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(PolicyError::Invalid("template must contain {secret} and no CR/LF/NUL"));
    }
    if get_role(v, &r.role)?.is_none() {
        return Err(PolicyError::Invalid("unknown role"));
    }
    let exists: i64 = v.conn().query_row("SELECT COUNT(*) FROM secrets WHERE id = ?1", [r.secret_id], |x| x.get(0))?;
    if exists == 0 {
        return Err(PolicyError::Invalid("unknown secret"));
    }
    Ok(())
}

pub fn add_role(v: &Vault, name: &str, unmatched: Unmatched) -> Result<Role, PolicyError> {
    let ok = !name.is_empty() && name.len() <= 64 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !ok {
        return Err(PolicyError::Invalid("role name must be [a-z0-9_-]"));
    }
    if get_role(v, name)?.is_some() {
        return Err(PolicyError::AlreadyExists);
    }
    v.conn().execute("INSERT INTO roles (name, unmatched_policy) VALUES (?1, ?2)", params![name, unmatched.as_str()])?;
    Ok(Role { name: name.into(), unmatched })
}

pub fn get_role(v: &Vault, name: &str) -> Result<Option<Role>, PolicyError> {
    let row: Option<String> = v
        .conn()
        .query_row("SELECT unmatched_policy FROM roles WHERE name = ?1", [name], |r| r.get(0))
        .optional()?;
    Ok(row.map(|p| Role { name: name.into(), unmatched: p.parse().unwrap_or(Unmatched::Deny) }))
}

pub fn list_roles(v: &Vault) -> Result<Vec<Role>, PolicyError> {
    let conn = v.conn();
    let mut st = conn.prepare("SELECT name, unmatched_policy FROM roles ORDER BY name")?;
    let rows = st
        .query_map([], |r| {
            let p: String = r.get(1)?;
            Ok(Role { name: r.get(0)?, unmatched: p.parse().unwrap_or(Unmatched::Deny) })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn remove_role(v: &Vault, name: &str) -> Result<(), PolicyError> {
    let n = v.conn().execute("DELETE FROM roles WHERE name = ?1", [name])?;
    if n == 0 { Err(PolicyError::NotFound) } else { Ok(()) }
}

pub fn add_rule(v: &Vault, r: NewRule) -> Result<Rule, PolicyError> {
    validate(v, &r)?;
    let methods: Vec<String> = r.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
    let conn = v.conn();
    conn.execute(
        "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![r.role, r.host_pattern, r.path_pattern, methods.join(","), r.kind.as_str(), r.target_name, r.template, r.secret_id],
    )?;
    Ok(Rule {
        id: conn.last_insert_rowid(), role: r.role, host_pattern: r.host_pattern, path_pattern: r.path_pattern,
        methods, kind: r.kind, target_name: r.target_name, template: r.template, secret_id: r.secret_id,
    })
}

pub fn list_rules(v: &Vault, role: Option<&str>) -> Result<Vec<Rule>, PolicyError> {
    let conn = v.conn();
    let mut st = conn.prepare(
        "SELECT id, role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id
         FROM rules WHERE (?1 IS NULL OR role = ?1) ORDER BY id",
    )?;
    let rows = st
        .query_map([role], |r| {
            let methods: String = r.get(4)?;
            let kind: String = r.get(5)?;
            Ok(Rule {
                id: r.get(0)?, role: r.get(1)?, host_pattern: r.get(2)?, path_pattern: r.get(3)?,
                methods: methods.split(',').filter(|m| !m.is_empty()).map(String::from).collect(),
                kind: if kind == "query" { InjectionKind::Query } else { InjectionKind::Header },
                target_name: r.get(6)?, template: r.get(7)?, secret_id: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn remove_rule(v: &Vault, id: i64) -> Result<(), PolicyError> {
    let n = v.conn().execute("DELETE FROM rules WHERE id = ?1", [id])?;
    if n == 0 { Err(PolicyError::NotFound) } else { Ok(()) }
}
```

`lib.rs`:
```rust
mod matcher;
mod model;
mod normalize;
mod render;
mod store;

pub use matcher::{evaluate, has_rules_for_host, Decision};
pub use model::*;
pub use normalize::{is_ip_literal, normalize_host, normalize_path};
pub use render::render;
pub use store::*;
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-policy`
Expected: todos pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(policy): add roles, rules, matching and normalization"
```

---

### Task 4: `auth` (tokens EdDSA)

**Files:**
- Create: `crates/auth/src/{lib.rs,token.rs,header.rs}`
- Test: tests unitarios en los módulos, `crates/auth/tests/tokens.rs`

**Interfaces:**
- Consumes: `sg_core::{Vault, CoreError, now}`.
- Produces:
  - `struct Identity { jti: String, machine: String, role: String }` (`Clone`, `Debug`)
  - `trait TokenVerifier: Send + Sync { fn verify(&self, token: &str) -> Result<Identity, AuthError>; }`
  - `struct TokenService` con `new(Arc<Vault>) -> Result<Self, AuthError>`, `issue(&self, machine: &str, role: &str, ttl: Option<Duration>) -> Result<IssuedToken, AuthError>`, `revoke(&self, jti: &str) -> Result<(), AuthError>`, `revoke_machine(&self, machine: &str) -> Result<usize, AuthError>`, `list(&self) -> Result<Vec<TokenMeta>, AuthError>`; `impl TokenVerifier for TokenService`
  - `struct IssuedToken { token: String, jti: String }`, `struct TokenMeta { jti, machine, role, created_at, expires_at: Option<i64>, revoked_at: Option<i64> }` (`Serialize`)
  - `fn extract_proxy_token(header: &str) -> Option<String>`
  - `enum AuthError { Invalid, Expired, Revoked, InvalidTtl, Core(CoreError), Db(rusqlite::Error) }`

- [ ] **Step 1: Escribir los tests que fallan**

`header.rs` (módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn basic_takes_token_from_password() {
        let h = format!("Basic {}", STANDARD.encode("machine:the.jwt.token"));
        assert_eq!(extract_proxy_token(&h).as_deref(), Some("the.jwt.token"));
    }

    #[test]
    fn bearer_and_case_insensitive_scheme() {
        assert_eq!(extract_proxy_token("Bearer abc.def.ghi").as_deref(), Some("abc.def.ghi"));
        assert_eq!(extract_proxy_token("bearer abc").as_deref(), Some("abc"));
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(extract_proxy_token(""), None);
        assert_eq!(extract_proxy_token("Basic !!!notbase64"), None);
        assert_eq!(extract_proxy_token("Basic bm9jb2xvbg=="), None);
        assert_eq!(extract_proxy_token("Digest abc"), None);
        assert_eq!(extract_proxy_token("Bearer "), None);
    }
}
```

`tests/tokens.rs`:
```rust
use sg_auth::*;
use sg_core::{crypto, KeyInput, Vault};
use std::{sync::Arc, time::Duration};
use tempfile::tempdir;

fn svc() -> (tempfile::TempDir, Arc<Vault>, TokenService) {
    let dir = tempdir().unwrap();
    let v = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let s = TokenService::new(v.clone()).unwrap();
    (dir, v, s)
}

#[test]
fn issue_and_verify_roundtrip() {
    let (_d, _v, s) = svc();
    let t = s.issue("laptop", "developer", None).unwrap();
    let id = s.verify(&t.token).unwrap();
    assert_eq!((id.machine.as_str(), id.role.as_str(), id.jti.as_str()), ("laptop", "developer", t.jti.as_str()));
}

#[test]
fn signing_key_persists_across_service_instances() {
    let (_d, v, s) = svc();
    let t = s.issue("laptop", "developer", None).unwrap();
    let s2 = TokenService::new(v).unwrap();
    assert!(s2.verify(&t.token).is_ok());
}

#[test]
fn expired_token_is_rejected() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", Some(Duration::from_secs(0))).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    assert!(matches!(s.verify(&t.token), Err(AuthError::Expired)));
}

#[test]
fn revoked_token_is_rejected_and_machine_revocation_counts() {
    let (_d, _v, s) = svc();
    let a = s.issue("laptop", "developer", None).unwrap();
    let b = s.issue("laptop", "reviewer", None).unwrap();
    let c = s.issue("other", "reviewer", None).unwrap();
    s.revoke(&a.jti).unwrap();
    assert!(matches!(s.verify(&a.token), Err(AuthError::Revoked)));
    assert_eq!(s.revoke_machine("laptop").unwrap(), 1);
    assert!(matches!(s.verify(&b.token), Err(AuthError::Revoked)));
    assert!(s.verify(&c.token).is_ok());
}

#[test]
fn tampered_payload_and_foreign_signer_are_rejected() {
    let (_d, _v, s) = svc();
    let (_d2, _v2, other) = svc();
    let t = s.issue("m", "reviewer", None).unwrap();
    assert!(other.verify(&t.token).is_err());
    let parts: Vec<&str> = t.token.split('.').collect();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    let evil = B64.encode(br#"{"iss":"secret-guardian","jti":"x","sub":"m","role":"developer","iat":1}"#);
    assert!(s.verify(&format!("{}.{}.{}", parts[0], evil, parts[2])).is_err());
}

#[test]
fn alg_none_and_malformed_tokens_are_rejected() {
    let (_d, _v, s) = svc();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    let h = B64.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let p = B64.encode(br#"{"iss":"secret-guardian","jti":"x","sub":"m","role":"developer","iat":1}"#);
    assert!(s.verify(&format!("{h}.{p}.")).is_err());
    for bad in ["", "a", "a.b", "a.b.c", "....", "💥.💥.💥"] {
        assert!(s.verify(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn listing_never_exposes_the_token() {
    let (_d, _v, s) = svc();
    let t = s.issue("m", "r", None).unwrap();
    let json = serde_json::to_string(&s.list().unwrap()).unwrap();
    assert!(!json.contains(&t.token));
    assert!(json.contains(&t.jti));
}
```
Añadir `serde_json` (ya está) y `base64` (ya está) a `auth`; `tempfile` en dev.

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-auth`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar**

`header.rs` (encima de los tests):
```rust
use base64::{engine::general_purpose::STANDARD, Engine};

/// Extracts the token from a `Proxy-Authorization` value: `Bearer <t>` or `Basic base64(user:<t>)`.
pub fn extract_proxy_token(header: &str) -> Option<String> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.to_string());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
        let (_, token) = decoded.split_once(':')?;
        return if token.is_empty() { None } else { Some(token.to_string()) };
    }
    None
}
```

`token.rs`:
```rust
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sg_core::{now, CoreError, Vault};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

const ISS: &str = "secret-guardian";
const KEY_AAD: &[u8] = b"sg:token-signing-key";
const HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    Invalid,
    #[error("token expired")]
    Expired,
    #[error("token revoked")]
    Revoked,
    #[error("ttl out of range")]
    InvalidTtl,
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub jti: String,
    pub machine: String,
    pub role: String,
}

pub trait TokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<Identity, AuthError>;
}

#[derive(Serialize, Deserialize)]
struct Claims {
    iss: String,
    jti: String,
    sub: String,
    role: String,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
}

pub struct IssuedToken {
    pub token: String,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenMeta {
    pub jti: String,
    pub machine: String,
    pub role: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

pub struct TokenService {
    vault: Arc<Vault>,
    key: SigningKey,
}

impl TokenService {
    pub fn new(vault: Arc<Vault>) -> Result<Self, AuthError> {
        let stored: Option<Vec<u8>> = vault
            .conn()
            .query_row("SELECT value FROM meta WHERE key = 'token_signing_key'", [], |r| r.get(0))
            .optional()?;
        let key = match stored {
            Some(blob) => {
                let raw = vault.open_value(KEY_AAD, &blob)?;
                let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| AuthError::Invalid)?;
                SigningKey::from_bytes(&bytes)
            }
            None => {
                let seed = sg_core::crypto::random_key();
                let key = SigningKey::from_bytes(&seed);
                let blob = vault.seal_value(KEY_AAD, &*seed);
                vault
                    .conn()
                    .execute("INSERT INTO meta (key, value) VALUES ('token_signing_key', ?1)", [blob])?;
                key
            }
        };
        Ok(Self { vault, key })
    }

    pub fn issue(&self, machine: &str, role: &str, ttl: Option<Duration>) -> Result<IssuedToken, AuthError> {
        let iat = now();
        let claims = Claims {
            iss: ISS.into(),
            jti: uuid::Uuid::new_v4().to_string(),
            sub: machine.into(),
            role: role.into(),
            iat,
            exp: ttl.map(|t| iat + t.as_secs() as i64),
        };
        let signing_input = format!("{}.{}", B64.encode(HEADER), B64.encode(serde_json::to_vec(&claims).unwrap()));
        let sig = self.key.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        self.vault.conn().execute(
            "INSERT INTO tokens (jti, machine, role, created_at, expires_at, token_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![claims.jti, machine, role, iat, claims.exp, token_hash],
        )?;
        Ok(IssuedToken { token, jti: claims.jti })
    }

    pub fn revoke(&self, jti: &str) -> Result<(), AuthError> {
        let n = self.vault.conn().execute(
            "UPDATE tokens SET revoked_at = ?1 WHERE jti = ?2 AND revoked_at IS NULL",
            params![now(), jti],
        )?;
        if n == 0 { Err(AuthError::Core(CoreError::NotFound)) } else { Ok(()) }
    }

    pub fn revoke_machine(&self, machine: &str) -> Result<usize, AuthError> {
        Ok(self.vault.conn().execute(
            "UPDATE tokens SET revoked_at = ?1 WHERE machine = ?2 AND revoked_at IS NULL",
            params![now(), machine],
        )?)
    }

    pub fn list(&self) -> Result<Vec<TokenMeta>, AuthError> {
        let conn = self.vault.conn();
        let mut st = conn.prepare("SELECT jti, machine, role, created_at, expires_at, revoked_at FROM tokens ORDER BY created_at DESC")?;
        let rows = st
            .query_map([], |r| {
                Ok(TokenMeta { jti: r.get(0)?, machine: r.get(1)?, role: r.get(2)?, created_at: r.get(3)?, expires_at: r.get(4)?, revoked_at: r.get(5)? })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

impl TokenVerifier for TokenService {
    fn verify(&self, token: &str) -> Result<Identity, AuthError> {
        let mut it = token.split('.');
        let (h, p, s) = match (it.next(), it.next(), it.next(), it.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(AuthError::Invalid),
        };
        if B64.decode(h).map_err(|_| AuthError::Invalid)? != HEADER.as_bytes() {
            return Err(AuthError::Invalid); // rejects alg=none and any other algorithm
        }
        let sig_bytes: [u8; 64] = B64.decode(s).map_err(|_| AuthError::Invalid)?.try_into().map_err(|_| AuthError::Invalid)?;
        let vk: VerifyingKey = self.key.verifying_key();
        vk.verify(format!("{h}.{p}").as_bytes(), &Signature::from_bytes(&sig_bytes)).map_err(|_| AuthError::Invalid)?;
        let claims: Claims = serde_json::from_slice(&B64.decode(p).map_err(|_| AuthError::Invalid)?).map_err(|_| AuthError::Invalid)?;
        if claims.iss != ISS {
            return Err(AuthError::Invalid);
        }
        if claims.exp.map(|e| now() >= e).unwrap_or(false) {
            return Err(AuthError::Expired);
        }
        let revoked: Option<Option<i64>> = self
            .vault
            .conn()
            .query_row("SELECT revoked_at FROM tokens WHERE jti = ?1", [&claims.jti], |r| r.get(0))
            .optional()?;
        match revoked {
            None => Err(AuthError::Invalid),
            Some(Some(_)) => Err(AuthError::Revoked),
            Some(None) => Ok(Identity { jti: claims.jti, machine: claims.sub, role: claims.role }),
        }
    }
}
```
`lib.rs`:
```rust
mod header;
mod token;

pub use header::extract_proxy_token;
pub use token::*;
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-auth`
Expected: todos pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(auth): add EdDSA machine tokens with revocation"
```

---

### Task 5: `ca` (CA acotada y certificados de hoja)

**Files:**
- Create: `crates/ca/src/lib.rs`, `crates/ca/src/service.rs`
- Test: `crates/ca/tests/ca.rs`

**Interfaces:**
- Consumes: `sg_core::{Vault, CoreError}`.
- Produces:
  - `struct CaService` con `init_or_load(vault: Arc<Vault>) -> Result<Self, CaError>`, `cert_pem(&self) -> String`, `domains(&self) -> Vec<String>`, `allow_domain(&self, domain: &str) -> Result<(), CaError>`, `is_host_permitted(&self, host: &str) -> bool`, `server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CaError>`
  - `enum CaError { DomainRejected(&'static str), NotPermitted, Core(CoreError), Db(..), Tls(String) }`
  - `pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider>` (ring)

- [ ] **Step 1: Escribir los tests que fallan** (`crates/ca/tests/ca.rs`)

```rust
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sg_ca::*;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn ca() -> (tempfile::TempDir, Arc<Vault>, CaService) {
    let dir = tempdir().unwrap();
    let v = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let ca = CaService::init_or_load(v.clone()).unwrap();
    (dir, v, ca)
}

fn roots(pem: &str) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut pem.as_bytes()) {
        store.add(CertificateDer::from(c.unwrap().to_vec())).unwrap();
    }
    store
}

/// In-memory TLS handshake: a client trusting `ca_pem` against a server using `server_cfg` for `host`.
async fn handshake_raw(server_cfg: Arc<rustls::ServerConfig>, ca_pem: &str, host: &str) -> Result<(), String> {
    let client_cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(roots(ca_pem))
        .with_no_client_auth();
    let (c, s) = tokio::io::duplex(8192);
    let acceptor = TlsAcceptor::from(server_cfg);
    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(s).await.map_err(|e| e.to_string())?;
        tls.write_all(b"ok").await.map_err(|e| e.to_string())?;
        tls.shutdown().await.ok();
        Ok::<_, String>(())
    });
    let name = ServerName::try_from(host.to_string()).unwrap();
    let mut tls = TlsConnector::from(Arc::new(client_cfg)).connect(name, c).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.ok();
    let _ = server.await;
    Ok(())
}

async fn handshake(ca: &CaService, host: &str) -> Result<(), String> {
    let cfg = ca.server_config_for(host).map_err(|e| e.to_string())?;
    handshake_raw(cfg, &ca.cert_pem(), host).await
}

fn forged_server_config(host: &str, ca_cert: &rcgen::Certificate, ca_key: &KeyPair) -> Arc<rustls::ServerConfig> {
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_string()]).unwrap().signed_by(&leaf_key, ca_cert, ca_key).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions().unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())))
            .unwrap(),
    )
}

#[tokio::test]
async fn leaf_for_allowed_domain_and_subdomain_verifies() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    handshake(&ca, "github.com").await.unwrap();
    handshake(&ca, "api.github.com").await.unwrap();
}

#[tokio::test]
async fn fresh_ca_is_never_unconstrained() {
    let (_d, _v, ca) = ca();
    assert!(!ca.is_host_permitted("github.com"));
    assert!(ca.server_config_for("github.com").is_err());
}

#[tokio::test]
async fn verifier_enforces_name_constraints_against_a_forged_leaf() {
    // A CA constrained to github.com whose key is used to forge a leaf for evil.com: the client must refuse it.
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name = DistinguishedName::new();
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName("github.com".into())],
        excluded_subtrees: vec![],
    });
    let ca_cert = p.self_signed(&key).unwrap();
    let pem = ca_cert.pem();
    // control: a leaf inside the constraint passes, so a failure below is caused by the constraint itself
    handshake_raw(forged_server_config("api.github.com", &ca_cert, &key), &pem, "api.github.com").await.unwrap();
    assert!(handshake_raw(forged_server_config("evil.com", &ca_cert, &key), &pem, "evil.com").await.is_err());
}

#[test]
fn too_broad_domains_are_rejected() {
    let (_d, _v, ca) = ca();
    for bad in ["com", "", "*.github.com", "github.com/path", "invalid", "a b.com", "10.0.0.1"] {
        assert!(ca.allow_domain(bad).is_err(), "{bad:?}");
    }
    ca.allow_domain("localhost").unwrap();
}

#[test]
fn allow_domain_keeps_the_same_key_and_persists() {
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    ca.allow_domain("gitlab.com").unwrap();
    assert_eq!(ca.domains(), vec!["github.com".to_string(), "gitlab.com".to_string()]);
    let reloaded = CaService::init_or_load(v).unwrap();
    assert_eq!(reloaded.domains(), ca.domains());
    assert_eq!(reloaded.cert_pem(), ca.cert_pem());
}

#[test]
fn private_key_is_not_stored_in_clear() {
    let (_d, v, _ca) = ca();
    let blob: Vec<u8> = v.conn().query_row("SELECT key_enc FROM ca WHERE id = 1", [], |r| r.get(0)).unwrap();
    assert!(!String::from_utf8_lossy(&blob).contains("PRIVATE KEY"));
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-ca`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar** (`service.rs`; `lib.rs` re-exporta)

```rust
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, GeneralSubtree, IsCa,
    KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sg_core::{CoreError, Vault};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::{Duration as TDuration, OffsetDateTime};

const KEY_AAD: &[u8] = b"sg:ca-key";
const PLACEHOLDER_TLD: &str = "invalid";
const LEAF_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("domain rejected: {0}")]
    DomainRejected(&'static str),
    #[error("host not permitted by the CA name constraints")]
    NotPermitted,
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("tls error: {0}")]
    Tls(String),
}

fn tls<E: std::fmt::Display>(e: E) -> CaError {
    CaError::Tls(e.to_string())
}

pub fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

struct State {
    cert_pem: String,
    domains: Vec<String>,
}

pub struct CaService {
    vault: Arc<Vault>,
    key: KeyPair,
    state: Mutex<State>,
    cache: Mutex<HashMap<String, (Instant, Arc<rustls::ServerConfig>)>>,
}

fn ca_params(domains: &[String]) -> Result<CertificateParams, CaError> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Secret Guardian CA");
    p.distinguished_name = dn;
    // serial aleatorio positivo de 16 bytes (las reemisiones no deben repetir emisor+serie)
    let mut serial: [u8; 16] = sg_core::crypto::random_bytes();
    serial[0] &= 0x7f;
    p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let names: Vec<String> = if domains.is_empty() { vec![PLACEHOLDER_TLD.into()] } else { domains.to_vec() };
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: names.into_iter().map(GeneralSubtree::DnsName).collect(),
        // las restricciones DNS no limitan los SAN IP: se excluyen todas las IP
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(rcgen::CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(rcgen::CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    p.not_before = OffsetDateTime::now_utc() - TDuration::days(1);
    p.not_after = OffsetDateTime::now_utc() + TDuration::days(3650);
    Ok(p)
}

// Además de lo siguiente: etiquetas de 1..=63 sin `-` inicial/final, longitud <= 253 y última etiqueta no numérica (reglas de webpki).
fn validate_domain(d: &str) -> Result<(), CaError> {
    let ok_chars = d.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if d.is_empty() || !ok_chars || d.starts_with('.') || d.ends_with('.') || d.contains("..") {
        return Err(CaError::DomainRejected("use a plain lowercase domain such as github.com"));
    }
    if d.parse::<std::net::IpAddr>().is_ok() {
        return Err(CaError::DomainRejected("IP addresses are not supported"));
    }
    if d == PLACEHOLDER_TLD || d.ends_with(".invalid") {
        return Err(CaError::DomainRejected("reserved"));
    }
    if d != "localhost" && !d.contains('.') {
        return Err(CaError::DomainRejected("too broad: single-label domains are not allowed"));
    }
    Ok(())
}

impl CaService {
    pub fn init_or_load(vault: Arc<Vault>) -> Result<Self, CaError> {
        let row: Option<(String, Vec<u8>, String)> = {
            use rusqlite::OptionalExtension;
            vault
                .conn()
                .query_row("SELECT cert_pem, key_enc, domains FROM ca WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional()?
        };
        match row {
            Some((cert_pem, key_enc, domains)) => {
                let key_pem = vault.open_value(KEY_AAD, &key_enc)?;
                let key = KeyPair::from_pem(std::str::from_utf8(&key_pem).map_err(tls)?).map_err(tls)?;
                let domains: Vec<String> = serde_json::from_str(&domains).map_err(tls)?;
                Ok(Self::build(vault, key, State { cert_pem, domains }))
            }
            None => {
                let key = KeyPair::generate().map_err(tls)?;
                let cert = ca_params(&[])?.self_signed(&key).map_err(tls)?;
                let key_enc = vault.seal_value(KEY_AAD, key.serialize_pem().as_bytes());
                vault.conn().execute(
                    "INSERT INTO ca (id, cert_pem, key_enc, domains) VALUES (1, ?1, ?2, '[]')",
                    rusqlite::params![cert.pem(), key_enc],
                )?;
                Ok(Self::build(vault, key, State { cert_pem: cert.pem(), domains: vec![] }))
            }
        }
    }

    fn build(vault: Arc<Vault>, key: KeyPair, state: State) -> Self {
        Self { vault, key, state: Mutex::new(state), cache: Mutex::new(HashMap::new()) }
    }

    pub fn cert_pem(&self) -> String {
        self.state.lock().unwrap().cert_pem.clone()
    }

    pub fn domains(&self) -> Vec<String> {
        self.state.lock().unwrap().domains.clone()
    }

    /// Re-issues the CA certificate with the same key and a wider permitted set. Agents must reload the certificate.
    /// Recorta y pasa a minúsculas; no consulta la Public Suffix List. Antes de persistir, una sonda
    /// (hoja `probe.<dominio>` verificada contra el nuevo certificado) debe pasar para todos los dominios.
    pub fn allow_domain(&self, domain: &str) -> Result<(), CaError> {
        let domain = domain.trim().to_ascii_lowercase();
        let domain = domain.as_str();
        validate_domain(domain)?;
        let mut st = self.state.lock().unwrap();
        if st.domains.iter().any(|d| d == domain) {
            return Ok(());
        }
        let mut domains = st.domains.clone();
        domains.push(domain.to_string());
        domains.sort();
        let cert = ca_params(&domains)?.self_signed(&self.key).map_err(tls)?;
        self.vault.conn().execute(
            "UPDATE ca SET cert_pem = ?1, domains = ?2 WHERE id = 1",
            rusqlite::params![cert.pem(), serde_json::to_string(&domains).map_err(tls)?],
        )?;
        *st = State { cert_pem: cert.pem(), domains };
        self.cache.lock().unwrap().clear();
        Ok(())
    }

    pub fn is_host_permitted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.state.lock().unwrap().domains.iter().any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CaError> {
        if !self.is_host_permitted(host) {
            return Err(CaError::NotPermitted);
        }
        if let Some((at, cfg)) = self.cache.lock().unwrap().get(host) {
            if at.elapsed() < LEAF_CACHE_TTL {
                return Ok(cfg.clone());
            }
        }
        let domains = self.domains();
        let ca_cert = ca_params(&domains)?.self_signed(&self.key).map_err(tls)?;
        let leaf_key = KeyPair::generate().map_err(tls)?;
        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(tls)?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - TDuration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + TDuration::hours(24);
        let leaf = params.signed_by(&leaf_key, &ca_cert, &self.key).map_err(tls)?;
        let der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(tls)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], der)
            .map_err(tls)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.cache.lock().unwrap().insert(host.to_string(), (Instant::now(), cfg.clone()));
        Ok(cfg)
    }
}
```

`lib.rs`:
```rust
mod service;
pub use service::*;
```

Nota técnica: el certificado de CA que firma las hojas se vuelve a derivar de `ca_params(&domains)` con la misma clave; los clientes validan por nombre del emisor y clave, así que no necesitan el certificado exacto que se exportó. El test `client_rejects_leaf_outside_name_constraints_even_if_forged` confirma que las name constraints se aplican en el lado del cliente.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-ca`
Expected: todos pasan. Si el test de constraints falla porque el verificador de `rustls` no aplica las name constraints de la raíz de confianza, documentar el hallazgo en la spec (sección 11) y avisar antes de continuar: es un riesgo de diseño.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(ca): add name-constrained CA and leaf issuance"
```

---

### Task 6: `core::audit`

**Files:**
- Create: `crates/core/src/audit.rs`
- Modify: `crates/core/src/lib.rs` (añadir `pub mod audit;`)
- Test: `crates/core/tests/audit.rs`

**Interfaces:**
- Produces:
  - `struct AuditEntry { ts: i64, jti: Option<String>, machine: Option<String>, role: Option<String>, host: String, method: String, path: String, rule_id: Option<i64>, decision: String, status: Option<u16> }` (`Serialize`), con `AuditEntry::new(host: &str, method: &str, raw_path_and_query: &str, decision: &str) -> AuditEntry` que **elimina el query string**
  - `struct AuditFilter { role: Option<String>, host: Option<String>, since: Option<i64>, limit: usize }` (`Default`, `Deserialize`)
  - `Vault::record_audit(&self, e: &AuditEntry) -> Result<(), CoreError>`, `Vault::list_audit(&self, f: &AuditFilter) -> Result<Vec<AuditEntry>, CoreError>`

- [ ] **Step 1: Escribir los tests que fallan**

```rust
use sg_core::audit::{AuditEntry, AuditFilter};
use sg_core::{crypto, KeyInput, Vault};
use tempfile::tempdir;

fn vault() -> (tempfile::TempDir, Vault) {
    let d = tempdir().unwrap();
    let v = Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap();
    (d, v)
}

#[test]
fn query_string_is_never_stored() {
    let e = AuditEntry::new("api.x.com", "GET", "/v1/items?api_key=SHOULD-NOT-LEAK&x=1", "inject");
    assert_eq!(e.path, "/v1/items");
}

#[test]
fn record_and_filter() {
    let (_d, v) = vault();
    let mut a = AuditEntry::new("api.github.com", "GET", "/repos", "inject");
    a.role = Some("developer".into());
    a.status = Some(200);
    let mut b = AuditEntry::new("example.com", "POST", "/", "forbidden");
    b.role = Some("reviewer".into());
    v.record_audit(&a).unwrap();
    v.record_audit(&b).unwrap();
    assert_eq!(v.list_audit(&AuditFilter { limit: 10, ..Default::default() }).unwrap().len(), 2);
    let only_dev = v.list_audit(&AuditFilter { role: Some("developer".into()), limit: 10, ..Default::default() }).unwrap();
    assert_eq!(only_dev.len(), 1);
    assert_eq!(only_dev[0].host, "api.github.com");
    let by_host = v.list_audit(&AuditFilter { host: Some("example.com".into()), limit: 10, ..Default::default() }).unwrap();
    assert_eq!(by_host[0].decision, "forbidden");
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-core --test audit`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar** (`audit.rs`)

```rust
use crate::{error::CoreError, now, vault::Vault};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts: i64,
    pub jti: Option<String>,
    pub machine: Option<String>,
    pub role: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<i64>,
    pub decision: String,
    pub status: Option<u16>,
}

impl AuditEntry {
    pub fn new(host: &str, method: &str, raw_path_and_query: &str, decision: &str) -> Self {
        let path = raw_path_and_query.split(['?', '#']).next().unwrap_or("/").to_string();
        Self {
            ts: now(), jti: None, machine: None, role: None, host: host.into(), method: method.into(),
            path, rule_id: None, decision: decision.into(), status: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditFilter {
    pub role: Option<String>,
    pub host: Option<String>,
    pub since: Option<i64>,
    #[serde(default)]
    pub limit: usize,
}

impl Vault {
    pub fn record_audit(&self, e: &AuditEntry) -> Result<(), CoreError> {
        self.conn().execute(
            "INSERT INTO audit (ts, jti, machine, role, host, method, path, rule_id, decision, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![e.ts, e.jti, e.machine, e.role, e.host, e.method, e.path, e.rule_id, e.decision, e.status],
        )?;
        Ok(())
    }

    pub fn list_audit(&self, f: &AuditFilter) -> Result<Vec<AuditEntry>, CoreError> {
        let limit = if f.limit == 0 { 100 } else { f.limit.min(1000) } as i64;
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT ts, jti, machine, role, host, method, path, rule_id, decision, status FROM audit
             WHERE (?1 IS NULL OR role = ?1) AND (?2 IS NULL OR host = ?2) AND (?3 IS NULL OR ts >= ?3)
             ORDER BY id DESC LIMIT ?4",
        )?;
        let rows = st
            .query_map(params![f.role, f.host, f.since, limit], |r| {
                Ok(AuditEntry {
                    ts: r.get(0)?, jti: r.get(1)?, machine: r.get(2)?, role: r.get(3)?, host: r.get(4)?, method: r.get(5)?,
                    path: r.get(6)?, rule_id: r.get(7)?, decision: r.get(8)?, status: r.get::<_, Option<i64>>(9)?.map(|s| s as u16),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
```
Y en `lib.rs`: `pub mod audit;`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-core --test audit`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): add audit log without query strings"
```

---

### Task 7: `proxy` (autenticación, CONNECT, passthrough y deny)

**Files:**
- Create: `crates/proxy/src/{lib.rs,server.rs,upstream.rs,inject.rs}` (los dos últimos con stubs mínimos que compilen; se completan en la Tarea 8)
- Create: `crates/proxy/tests/common/mod.rs`, `crates/proxy/tests/connect.rs`

**Interfaces:**
- Consumes: `sg_core::{Vault, audit::AuditEntry}`, `sg_policy::{get_role, list_rules, has_rules_for_host, normalize_host, Unmatched}`, `sg_auth::{TokenVerifier, extract_proxy_token, Identity}`, `sg_ca::CaService`.
- Produces:
  - `struct ProxyState { vault: Arc<Vault>, verifier: Arc<dyn TokenVerifier>, ca: Arc<CaService>, upstream: UpstreamConfig }`
  - `struct UpstreamConfig { tls: Arc<rustls::ClientConfig>, resolve_override: HashMap<String, SocketAddr> }` con `UpstreamConfig::new(extra_roots: Vec<CertificateDer<'static>>) -> Self`
  - `async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> std::io::Result<()>`
  - Helpers de test en `tests/common`: `Env::new(upstream_host) -> Env`, `Env::token(role) -> String`, `Env::proxy_addr`, `raw_connect(addr, authority, proxy_auth: Option<&str>) -> String` (devuelve la línea de estado).

- [ ] **Step 1: Escribir `tests/common/mod.rs` y los tests que fallan**

`tests/common/mod.rs`:
```rust
#![allow(dead_code)]
use rustls::pki_types::CertificateDer;
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use sg_proxy::{ProxyState, UpstreamConfig};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};

pub struct Env {
    pub dir: TempDir,
    pub vault: Arc<Vault>,
    pub tokens: Arc<TokenService>,
    pub ca: Arc<CaService>,
    pub proxy_addr: SocketAddr,
}

impl Env {
    pub async fn new(upstream: UpstreamConfig) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
        let tokens = Arc::new(TokenService::new(vault.clone()).unwrap());
        let ca = Arc::new(CaService::init_or_load(vault.clone()).unwrap());
        let state = Arc::new(ProxyState { vault: vault.clone(), verifier: tokens.clone(), ca: ca.clone(), upstream });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(sg_proxy::serve(listener, state));
        Env { dir, vault, tokens, ca, proxy_addr }
    }

    pub fn token(&self, machine: &str, role: &str) -> String {
        self.tokens.issue(machine, role, None).unwrap().token
    }
}

pub fn basic(token: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    format!("Basic {}", STANDARD.encode(format!("agent:{token}")))
}

/// Sends a CONNECT and returns the first response line, then (if 200) the raw stream for tunnelling.
pub async fn raw_connect(proxy: SocketAddr, authority: &str, auth: Option<&str>) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 { break; }
        buf.push(b[0]);
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    (text.lines().next().unwrap_or("").to_string(), s)
}

pub async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() { break; }
                }
            });
        }
    });
    addr
}

pub fn no_extra_roots() -> UpstreamConfig {
    UpstreamConfig::new(Vec::<CertificateDer<'static>>::new())
}
```

`tests/connect.rs`:
```rust
mod common;
use common::*;
use sg_policy::{add_role, Unmatched};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn missing_or_garbage_credentials_get_407() {
    let env = Env::new(no_extra_roots()).await;
    for auth in [None, Some("Basic !!!"), Some("Bearer not.a.token"), Some("Digest x")] {
        let (line, _) = raw_connect(env.proxy_addr, "example.com:443", auth).await;
        assert!(line.contains("407"), "{auth:?} -> {line}");
    }
}

#[tokio::test]
async fn revoked_token_gets_407() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let issued = env.tokens.issue("m", "developer", None).unwrap();
    env.tokens.revoke(&issued.jti).unwrap();
    let (line, _) = raw_connect(env.proxy_addr, "example.com:443", Some(&basic(&issued.token))).await;
    assert!(line.contains("407"));
}

#[tokio::test]
async fn unknown_role_in_a_valid_token_gets_403() {
    let env = Env::new(no_extra_roots()).await;
    let t = env.token("m", "ghost");
    let (line, _) = raw_connect(env.proxy_addr, "example.com:443", Some(&basic(&t))).await;
    assert!(line.contains("403"));
}

#[tokio::test]
async fn passthrough_tunnels_hosts_without_rules() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, mut s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn deny_policy_blocks_hosts_without_rules_and_audits_it() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "reviewer", Unmatched::Deny).unwrap();
    let t = env.token("laptop", "reviewer");
    let (line, _) = raw_connect(env.proxy_addr, "example.com:443", Some(&basic(&t))).await;
    assert!(line.contains("403"));
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].host, "example.com");
    assert_eq!(rows[0].decision, "unmatched-denied");
    assert_eq!(rows[0].machine.as_deref(), Some("laptop"));
}

#[tokio::test]
async fn host_with_rule_but_not_permitted_by_ca_gets_502_with_hint() {
    use sg_policy::*;
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "v").unwrap();
    add_rule(&env.vault, NewRule {
        role: "developer".into(), host_pattern: "api.github.com".into(), path_pattern: "*".into(),
        methods: vec![], kind: InjectionKind::Header, target_name: "Authorization".into(),
        template: "Bearer {secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("m", "developer");
    let (line, _) = raw_connect(env.proxy_addr, "api.github.com:443", Some(&basic(&t))).await;
    assert!(line.contains("502"), "{line}");
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-proxy --test connect`
Expected: FAIL (no compila: `ProxyState` no definido).

- [ ] **Step 3: Implementar**

`lib.rs`:
```rust
mod inject;
mod mitm;
mod server;
mod upstream;

pub use upstream::UpstreamConfig;

use sg_auth::TokenVerifier;
use sg_ca::CaService;
use sg_core::Vault;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct ProxyState {
    pub vault: Arc<Vault>,
    pub verifier: Arc<dyn TokenVerifier>,
    pub ca: Arc<CaService>,
    pub upstream: UpstreamConfig,
}

pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = server::handle_connection(stream, state).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}
```

`upstream.rs` (versión completa; se usa ya en la Tarea 8):
```rust
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("tls failed: {0}")]
    Tls(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("timeout")]
    Timeout,
}

#[derive(Clone)]
pub struct UpstreamConfig {
    pub tls: Arc<rustls::ClientConfig>,
    /// Test/ops knob: connect to this address instead of resolving the host.
    pub resolve_override: HashMap<String, SocketAddr>,
}

impl UpstreamConfig {
    pub fn new(extra_roots: Vec<CertificateDer<'static>>) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        for c in extra_roots {
            let _ = roots.add(c);
        }
        let tls = rustls::ClientConfig::builder_with_provider(sg_ca::crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self { tls: Arc::new(tls), resolve_override: HashMap::new() }
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
        let fut = async {
            match self.resolve_override.get(host) {
                Some(addr) => TcpStream::connect(addr).await,
                None => TcpStream::connect((host, port)).await,
            }
        };
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Connect(e.to_string()))
    }

    pub async fn send(&self, host: &str, port: u16, tls: bool, req: Request<ProxyBody>) -> Result<Response<Incoming>, UpstreamError> {
        let tcp = self.connect_tcp(host, port).await?;
        let fut = async {
            if tls {
                let name = ServerName::try_from(host.to_string()).map_err(|e| UpstreamError::Tls(e.to_string()))?;
                let s = TlsConnector::from(self.tls.clone()).connect(name, tcp).await.map_err(|e| UpstreamError::Tls(e.to_string()))?;
                roundtrip(TokioIo::new(s), req).await
            } else {
                roundtrip(TokioIo::new(tcp), req).await
            }
        };
        tokio::time::timeout(Duration::from_secs(60), fut).await.map_err(|_| UpstreamError::Timeout)?
    }
}

async fn roundtrip<I>(io: I, req: Request<ProxyBody>) -> Result<Response<Incoming>, UpstreamError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|e| UpstreamError::Request(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender.send_request(req).await.map_err(|e| UpstreamError::Request(e.to_string()))
}
```

`inject.rs` (stub; se completa en la Tarea 8):
```rust
// Completed in Task 8.
```

`server.rs` (solo CONNECT; las peticiones no-CONNECT devuelven `501` hasta la Tarea 9):
```rust
use crate::{upstream::ProxyBody, ProxyState};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sg_auth::{extract_proxy_token, Identity};
use sg_core::audit::AuditEntry;
use sg_policy::{get_role, has_rules_for_host, list_rules, normalize_host, Unmatched};
use std::{convert::Infallible, sync::Arc};
use tokio::net::TcpStream;

pub async fn handle_connection(stream: TcpStream, state: Arc<ProxyState>) -> Result<(), hyper::Error> {
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(req, state).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await
}

pub(crate) fn text(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())).map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r
}

fn empty(status: StatusCode) -> Response<ProxyBody> {
    let mut r = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r
}

fn proxy_auth_required() -> Response<ProxyBody> {
    let mut r = text(StatusCode::PROXY_AUTHENTICATION_REQUIRED, "proxy authentication required\n");
    r.headers_mut().insert("proxy-authenticate", "Basic realm=\"secret-guardian\"".parse().unwrap());
    r
}

fn authenticate<B>(req: &Request<B>, state: &ProxyState) -> Option<Identity> {
    let header = req.headers().get(hyper::header::PROXY_AUTHORIZATION)?.to_str().ok()?;
    let token = extract_proxy_token(header)?;
    state.verifier.verify(&token).ok()
}

pub(crate) fn audit(state: &ProxyState, id: &Identity, host: &str, method: &str, path: &str, decision: &str, status: Option<u16>, rule_id: Option<i64>) {
    let mut e = AuditEntry::new(host, method, path, decision);
    e.jti = Some(id.jti.clone());
    e.machine = Some(id.machine.clone());
    e.role = Some(id.role.clone());
    e.status = status;
    e.rule_id = rule_id;
    if let Err(err) = state.vault.record_audit(&e) {
        tracing::error!(error = %err, "failed to write audit entry");
    }
}

async fn handle_request(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<ProxyBody> {
    let Some(identity) = authenticate(&req, &state) else {
        return proxy_auth_required();
    };
    if req.method() == Method::CONNECT {
        connect(req, identity, state).await
    } else {
        text(StatusCode::NOT_IMPLEMENTED, "plain HTTP proxying is not enabled yet\n")
    }
}

async fn connect(req: Request<Incoming>, identity: Identity, state: Arc<ProxyState>) -> Response<ProxyBody> {
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT target\n");
    };
    let Some(host) = normalize_host(authority.host()) else {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT host\n");
    };
    let port = authority.port_u16().unwrap_or(443);

    let role = match get_role(&state.vault, &identity.role) {
        Ok(Some(r)) => r,
        _ => {
            audit(&state, &identity, &host, "CONNECT", "/", "unknown-role", Some(403), None);
            return text(StatusCode::FORBIDDEN, "role not found\n");
        }
    };
    let rules = list_rules(&state.vault, Some(&identity.role)).unwrap_or_default();

    if has_rules_for_host(&rules, &host) {
        if !state.ca.is_host_permitted(&host) {
            audit(&state, &identity, &host, "CONNECT", "/", "ca-not-permitted", Some(502), None);
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("the CA does not permit {host}; run `sg ca allow-domain <domain>` and reload the CA certificate\n"),
            );
        }
        audit(&state, &identity, &host, "CONNECT", "/", "mitm", Some(200), None);
        tokio::spawn(crate::mitm::serve(req, host, port, identity, state));
        return empty(StatusCode::OK);
    }

    match role.unmatched {
        Unmatched::Deny => {
            audit(&state, &identity, &host, "CONNECT", "/", "unmatched-denied", Some(403), None);
            text(StatusCode::FORBIDDEN, "host not allowed for this role\n")
        }
        Unmatched::Passthrough => {
            let Ok(mut upstream) = state.upstream.connect_tcp(&host, port).await else {
                audit(&state, &identity, &host, "CONNECT", "/", "tunnel-connect-failed", Some(502), None);
                return text(StatusCode::BAD_GATEWAY, "could not reach the destination\n");
            };
            audit(&state, &identity, &host, "CONNECT", "/", "passthrough", Some(200), None);
            tokio::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    let mut client = TokioIo::new(upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
            empty(StatusCode::OK)
        }
    }
}
```
`mitm.rs` provisional (se sustituye en la Tarea 8):
```rust
use crate::ProxyState;
use hyper::{body::Incoming, Request};
use sg_auth::Identity;
use std::sync::Arc;

pub(crate) async fn serve(_req: Request<Incoming>, _host: String, _port: u16, _id: Identity, _state: Arc<ProxyState>) {}
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-proxy --test connect`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): authenticate CONNECT and tunnel or deny unmatched hosts"
```

---

### Task 8: `proxy` MITM e inyección

**Files:**
- Modify: `crates/proxy/src/inject.rs`, `crates/proxy/src/mitm.rs`, `crates/proxy/src/server.rs` (exponer `forward`)
- Create: `crates/proxy/src/forward.rs`
- Modify: `crates/proxy/tests/common/mod.rs` (upstream de prueba y cliente)
- Create: `crates/proxy/tests/inject.rs`, tests unitarios en `inject.rs`

**Interfaces:**
- Consumes: Tarea 7 (`ProxyState`, `UpstreamConfig::send`, `audit`, `text`), `sg_policy::{evaluate, Decision, render, normalize_path}`, `Vault::reveal_for_injection`.
- Produces:
  - `inject::ResolvedInjection { kind: InjectionKind, name: String, value: Zeroizing<String> }`
  - `inject::apply(parts: &mut http::request::Parts, path: &str, injections: &[ResolvedInjection]) -> Result<(), InjectError>` (reescribe la URI a forma origin con el path normalizado, elimina cabeceras/parámetros del agente con el mismo nombre e inyecta)
  - `forward::forward(req: Request<Incoming>, ctx: &Ctx) -> Response<ProxyBody>` con `Ctx { state: Arc<ProxyState>, identity: Identity, host: String, port: u16, tls: bool, allow_unruled: bool }`
  - helpers de test: `spawn_tls_upstream(host) -> TestUpstream { addr, received, ca_der }`, `proxy_request(env, token, host, method, path, headers, body) -> Resp { status, body }`

- [ ] **Step 1: Escribir los tests que fallan**

Tests unitarios en `inject.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sg_policy::InjectionKind::*;
    use zeroize::Zeroizing;

    fn parts(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn inj(kind: sg_policy::InjectionKind, name: &str, value: &str) -> ResolvedInjection {
        ResolvedInjection { kind, name: name.into(), value: Zeroizing::new(value.into()) }
    }

    #[test]
    fn header_overwrites_every_agent_supplied_variant() {
        let mut p = parts("/x", &[("authorization", "Bearer AGENT-1"), ("Authorization", "Bearer AGENT-2"), ("x-keep", "1")]);
        apply(&mut p, "/x", &[inj(Header, "Authorization", "Bearer REAL")]).unwrap();
        let all: Vec<_> = p.headers.get_all("authorization").iter().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "Bearer REAL");
        assert!(all[0].is_sensitive());
        assert_eq!(p.headers.get("x-keep").unwrap(), "1");
    }

    #[test]
    fn query_param_is_replaced_not_duplicated() {
        let mut p = parts("/x?API_KEY=agent&a=1&api_key=agent2&b=2", &[]);
        apply(&mut p, "/x", &[inj(Query, "api_key", "a%20b")]).unwrap();
        assert_eq!(p.uri.to_string(), "/x?a=1&b=2&api_key=a%20b");
    }

    #[test]
    fn path_is_rewritten_to_the_normalized_one() {
        let mut p = parts("/repos/../admin?z=1", &[]);
        apply(&mut p, "/admin", &[]).unwrap();
        assert_eq!(p.uri.to_string(), "/admin?z=1");
    }

    #[test]
    fn proxy_headers_are_stripped() {
        let mut p = parts("/x", &[("proxy-authorization", "Basic x"), ("proxy-connection", "keep-alive"), ("connection", "close")]);
        apply(&mut p, "/x", &[]).unwrap();
        assert!(p.headers.get("proxy-authorization").is_none());
        assert!(p.headers.get("proxy-connection").is_none());
        assert!(p.headers.get("connection").is_none());
    }
}
```

Añadir a `tests/common/mod.rs`:
```rust
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
}

pub struct TestUpstream {
    pub addr: SocketAddr,
    pub received: Arc<Mutex<Vec<Recorded>>>,
    pub ca_der: CertificateDer<'static>,
}

impl TestUpstream {
    pub fn header(&self, i: usize, name: &str) -> Vec<String> {
        self.received.lock().unwrap()[i].headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).collect()
    }
}

async fn serve_recording<IO>(io: IO, received: Arc<Mutex<Vec<Recorded>>>)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let received = received.clone();
        async move {
            let (parts, body) = req.into_parts();
            let n = body.collect().await.map(|b| b.to_bytes().len()).unwrap_or(0);
            received.lock().unwrap().push(Recorded {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers.iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect(),
                body_len: n,
            });
            Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"ok"))))
        }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new()).serve_connection(io, svc).await;
}

pub async fn spawn_tls_upstream(host: &str) -> TestUpstream {
    use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_string()]).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(sg_ca::crypto_provider())
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        ).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, rec) = (acceptor.clone(), rec.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_recording(TokioIo::new(tls), rec).await;
                }
            });
        }
    });
    TestUpstream { addr, received, ca_der: ca.der().clone() }
}

pub async fn spawn_plain_upstream() -> TestUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let rec = rec.clone();
            tokio::spawn(serve_recording(TokioIo::new(tcp), rec));
        }
    });
    TestUpstream { addr, received, ca_der: CertificateDer::from(Vec::new()) }
}

pub struct Resp {
    pub status: u16,
    pub body: String,
}

/// CONNECT through the proxy, TLS-handshake trusting the proxy CA, then send one request (HTTP/1.1 or HTTP/2).
pub async fn proxy_request(
    env: &Env, token: &str, host: &str, method: &str, path: &str, headers: &[(&str, &str)], body: Vec<u8>, http2: bool,
) -> Resp {
    let (line, tcp) = raw_connect(env.proxy_addr, &format!("{host}:443"), Some(&basic(token))).await;
    if !line.contains("200") {
        return Resp { status: line.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0), body: line };
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut env.ca.cert_pem().as_bytes()) {
        roots.add(CertificateDer::from(c.unwrap().to_vec())).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(sg_ca::crypto_provider())
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![if http2 { b"h2".to_vec() } else { b"http/1.1".to_vec() }];
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(), tcp)
        .await
        .expect("client must trust the proxy CA for this host");
    let mut rb = hyper::Request::builder().method(method).uri(format!("https://{host}{path}"));
    if !http2 {
        rb = rb.header("host", host);
    }
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    let req = rb.body(Full::new(Bytes::from(body))).unwrap();
    let resp = if http2 {
        let (mut s, c) = hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), TokioIo::new(tls)).await.unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    } else {
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    };
    let status = resp.status().as_u16();
    let body = String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    Resp { status, body }
}

/// Env wired to a TLS test upstream reachable under `host`, with the CA allowing `host`.
pub async fn env_with_upstream(host: &str) -> (Env, TestUpstream) {
    let up = spawn_tls_upstream(host).await;
    let mut cfg = UpstreamConfig::new(vec![up.ca_der.clone()]);
    cfg.resolve_override.insert(host.to_string(), up.addr);
    let env = Env::new(cfg).await;
    env.ca.allow_domain(host).unwrap();
    (env, up)
}
```
`tests/inject.rs`:
```rust
mod common;
use common::*;
use sg_policy::*;

const HOST: &str = "api.example.test";

async fn setup(methods: &[&str], path: &str) -> (Env, TestUpstream, String) {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(&env.vault, NewRule {
        role: "developer".into(), host_pattern: HOST.into(), path_pattern: path.into(),
        methods: methods.iter().map(|m| m.to_string()).collect(), kind: InjectionKind::Header,
        target_name: "Authorization".into(), template: "Bearer {secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("laptop", "developer");
    (env, up, t)
}

#[tokio::test]
async fn injects_header_and_agent_never_sees_the_secret() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/v1/x", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert!(!r.body.contains("REAL-SECRET"));
    assert_eq!(up.header(0, "authorization"), vec!["Bearer REAL-SECRET".to_string()]);
}

#[tokio::test]
async fn agent_supplied_credentials_are_discarded() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[("authorization", "Bearer AGENT-A"), ("Authorization", "Bearer AGENT-B")], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.header(0, "authorization"), vec!["Bearer REAL-SECRET".to_string()]);
}

#[tokio::test]
async fn query_injection_replaces_agent_param_and_encodes() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "dev", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("q", "a b&c").unwrap();
    add_rule(&env.vault, NewRule {
        role: "dev".into(), host_pattern: HOST.into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Query, target_name: "api_key".into(), template: "{secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("m", "dev");
    proxy_request(&env, &t, HOST, "GET", "/p?API_KEY=agent&z=1", &[], vec![], false).await;
    assert_eq!(up.received.lock().unwrap()[0].uri, "/p?z=1&api_key=a%20b%26c");
}

#[tokio::test]
async fn disallowed_method_is_403_and_never_reaches_upstream() {
    let (env, up, t) = setup(&["GET"], "*").await;
    let r = proxy_request(&env, &t, HOST, "POST", "/x", &[], b"data".to_vec(), false).await;
    assert_eq!(r.status, 403);
    assert!(up.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn path_traversal_cannot_escape_a_restricted_rule() {
    let (env, up, t) = setup(&["GET"], "/repos/*").await;
    assert_eq!(proxy_request(&env, &t, HOST, "GET", "/repos/ok", &[], vec![], false).await.status, 200);
    for p in ["/repos/../admin", "/repos/%2e%2e/admin", "/repos/..%2fadmin", "/repos/..;/admin", "/repos/%252e%252e%252fadmin", "/repos/x%252F..%252F..%252Frepos%252Fz%252Fw%2F..%2F..%2Fadmin", "/repos/..;%2Frepos%2Fx/..;/admin", "/repos/..%2F..%2Fadmin%3F%2F..%2F..%2Frepos%2Fy", "/repos/%u002e%u002e/admin", "/repos/a\\..%3B\\k/../admin", "/repos/a;%2Fk/..%3B/..%3B/admin", "/repos/..%20/admin", "/repos/.../admin", "/repos/%E2%80%A5/admin", "/repos/%EF%BC%8E%EF%BC%8E/admin", "/repos/a%09b", "/repos/a%0Ab", "/other"] {
        assert_eq!(proxy_request(&env, &t, HOST, "GET", p, &[], vec![], false).await.status, 403, "{p}");
    }
    assert_eq!(up.received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn normalized_path_is_what_gets_forwarded() {
    let (env, up, t) = setup(&["GET"], "*").await;
    proxy_request(&env, &t, HOST, "GET", "//a/./b//c", &[], vec![], false).await;
    assert_eq!(up.received.lock().unwrap()[0].uri, "/a/b/c");
}

#[tokio::test]
async fn host_header_different_from_connect_target_is_421() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[("host", "evil.example.test")], vec![], false).await;
    assert_eq!(r.status, 421);
    assert!(up.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn uppercase_host_and_trailing_dot_still_hit_the_same_rule() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[("host", "API.Example.Test.")], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn every_request_is_audited_with_identity_and_without_query() {
    let (env, _up, t) = setup(&[], "*").await;
    proxy_request(&env, &t, HOST, "GET", "/v1?secret_param=1", &[], vec![], false).await;
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    let e = rows.iter().find(|r| r.decision == "inject").unwrap();
    assert_eq!((e.path.as_str(), e.status, e.machine.as_deref()), ("/v1", Some(200), Some("laptop")));
}

#[tokio::test]
async fn http2_from_the_agent_is_supported() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/h2", &[], vec![], true).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.header(0, "authorization"), vec!["Bearer REAL-SECRET".to_string()]);
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-proxy`
Expected: FAIL (unitarios y de integración).

- [ ] **Step 3: Implementar**

`inject.rs` (encima de los tests):
```rust
use http::{header::HeaderName, request::Parts, HeaderValue, Uri};
use percent_encoding::percent_decode_str;
use sg_policy::InjectionKind;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("invalid header name or value")]
    Header,
    #[error("invalid uri")]
    Uri,
}

pub struct ResolvedInjection {
    pub kind: InjectionKind,
    pub name: String,
    /// Header: the full value. Query: already percent-encoded.
    pub value: Zeroizing<String>,
}

const HOP_BY_HOP: &[&str] = &["proxy-authorization", "proxy-connection", "connection", "keep-alive", "te", "upgrade", "transfer-encoding"];

pub fn apply(parts: &mut Parts, path: &str, injections: &[ResolvedInjection]) -> Result<(), InjectError> {
    for h in HOP_BY_HOP {
        parts.headers.remove(*h);
    }
    let mut query: Vec<String> = parts.uri.query().map(|q| q.split('&').filter(|p| !p.is_empty()).map(String::from).collect()).unwrap_or_default();

    for inj in injections {
        match inj.kind {
            InjectionKind::Header => {
                let name = HeaderName::from_bytes(inj.name.as_bytes()).map_err(|_| InjectError::Header)?;
                parts.headers.remove(&name);
                let mut v = HeaderValue::from_str(&inj.value).map_err(|_| InjectError::Header)?;
                v.set_sensitive(true);
                parts.headers.insert(name, v);
            }
            InjectionKind::Query => {
                query.retain(|pair| {
                    let key = pair.split('=').next().unwrap_or("");
                    !percent_decode_str(key).decode_utf8_lossy().eq_ignore_ascii_case(&inj.name)
                });
                query.push(format!("{}={}", inj.name, &*inj.value)); // names are validated as [A-Za-z0-9_.-] at rule creation
            }
        }
    }

    let pq = if query.is_empty() { path.to_string() } else { format!("{path}?{}", query.join("&")) };
    parts.uri = pq.parse::<Uri>().map_err(|_| InjectError::Uri)?;
    Ok(())
}
```
`forward.rs`:
```rust
use crate::{inject, server::{audit, text}, upstream::ProxyBody, ProxyState};
use http_body_util::BodyExt;
use hyper::{body::Incoming, header::HOST, Request, Response, StatusCode};
use sg_auth::Identity;
use sg_policy::{evaluate, list_rules, normalize_host, normalize_path, render, Decision};
use std::sync::Arc;

pub struct Ctx {
    pub state: Arc<ProxyState>,
    pub identity: Identity,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// True only for plain-HTTP requests to hosts with no rules under a `passthrough` role.
    pub allow_unruled: bool,
}

pub async fn forward(req: Request<Incoming>, ctx: &Ctx) -> Response<ProxyBody> {
    let (mut parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let raw_target = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
    let st = &ctx.state;
    let id = &ctx.identity;

    let declared = parts
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()));
    if declared.as_deref().and_then(normalize_host).as_deref() != Some(ctx.host.as_str()) {
        audit(st, id, &ctx.host, &method, &raw_target, "host-mismatch", Some(421), None);
        return text(StatusCode::MISDIRECTED_REQUEST, "Host does not match the CONNECT target\n");
    }

    let path = normalize_path(parts.uri.path());
    let rules = list_rules(&st.vault, Some(&id.role)).unwrap_or_default();
    let (matched, rule_id) = match evaluate(&rules, &ctx.host, &method, &path) {
        Decision::Inject(m) => {
            if !ctx.tls && ctx.host != "localhost" {
                audit(st, id, &ctx.host, &method, &raw_target, "plaintext-refused", Some(403), None);
                return text(StatusCode::FORBIDDEN, "refusing to inject credentials over plain HTTP\n");
            }
            let rid = m.first().map(|r| r.id);
            (m, rid)
        }
        Decision::NoRuleForHost if ctx.allow_unruled => (vec![], None),
        Decision::NoRuleForHost | Decision::Forbidden => {
            audit(st, id, &ctx.host, &method, &raw_target, "forbidden", Some(403), None);
            return text(StatusCode::FORBIDDEN, "not allowed for this role\n");
        }
    };

    let mut resolved = Vec::new();
    for r in matched {
        let secret = match st.vault.reveal_for_injection(r.secret_id) {
            Ok(s) => s,
            Err(_) => return text(StatusCode::BAD_GATEWAY, "secret unavailable\n"),
        };
        match render(&r.template, &secret, r.kind) {
            Ok(v) => resolved.push(inject::ResolvedInjection { kind: r.kind, name: r.target_name.clone(), value: zeroize::Zeroizing::new(v) }),
            Err(_) => return text(StatusCode::BAD_GATEWAY, "invalid injection value\n"),
        }
    }

    if inject::apply(&mut parts, &path, &resolved).is_err() {
        return text(StatusCode::BAD_GATEWAY, "could not build the upstream request\n");
    }
    let default_port = if ctx.tls { 443 } else { 80 };
    let host_header = if ctx.port == default_port { ctx.host.clone() } else { format!("{}:{}", ctx.host, ctx.port) };
    parts.headers.insert(HOST, host_header.parse().unwrap());
    parts.version = hyper::Version::HTTP_11;

    let outgoing = Request::from_parts(parts, body.boxed());
    match st.upstream.send(&ctx.host, ctx.port, ctx.tls, outgoing).await {
        Ok(resp) => {
            audit(st, id, &ctx.host, &method, &raw_target, if resolved.is_empty() { "passthrough" } else { "inject" }, Some(resp.status().as_u16()), rule_id);
            resp.map(|b| b.boxed())
        }
        Err(e) => {
            tracing::warn!(error = %e, host = %ctx.host, "upstream failure");
            audit(st, id, &ctx.host, &method, &raw_target, "upstream-error", Some(502), rule_id);
            text(StatusCode::BAD_GATEWAY, "upstream request failed\n")
        }
    }
}
```
Declarar `mod forward;` en `lib.rs` y hacer `pub(crate)` el módulo.

`mitm.rs`:
```rust
use crate::{forward::{forward, Ctx}, ProxyState};
use hyper::{body::Incoming, service::service_fn, Request};
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto};
use sg_auth::Identity;
use std::{convert::Infallible, sync::Arc};
use tokio_rustls::TlsAcceptor;

pub(crate) async fn serve(req: Request<Incoming>, host: String, port: u16, identity: Identity, state: Arc<ProxyState>) {
    let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
    let Ok(cfg) = state.ca.server_config_for(&host) else { return };
    let Ok(tls) = TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await else { return };
    let ctx = Arc::new(Ctx { state, identity, host, port, tls: true, allow_unruled: false });
    let svc = service_fn(move |req: Request<Incoming>| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(forward(req, &ctx).await) }
    });
    let _ = auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), svc).await;
}
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-proxy`
Expected: unitarios de `inject` + `connect` + `inject` (integración) pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): terminate TLS and inject credentials per role rules"
```

---

### Task 9: `proxy` HTTP en claro, streaming y robustez

**Files:**
- Modify: `crates/proxy/src/server.rs` (manejar peticiones `http://` en forma absoluta)
- Create: `crates/proxy/tests/plain_and_streaming.rs`

**Interfaces:**
- Consumes: `forward::{forward, Ctx}`.
- Produces: soporte de `GET http://host/path` a través del proxy, con política por rol y rechazo de inyección sin TLS (excepto `localhost`).

- [ ] **Step 1: Escribir los tests que fallan**

```rust
mod common;
use common::*;
use sg_policy::*;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

async fn plain_get(env: &Env, token: &str, target: &str, host_hdr: &str) -> String {
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host_hdr}\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
        basic(token)
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

fn status(raw: &str) -> &str {
    raw.lines().next().unwrap_or("")
}

#[tokio::test]
async fn plain_http_to_a_host_with_rules_never_gets_the_secret() {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert("api.example.test".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(&env.vault, NewRule {
        role: "developer".into(), host_pattern: "api.example.test".into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Header, target_name: "Authorization".into(), template: "Bearer {secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("m", "developer");
    let raw = plain_get(&env, &t, "http://api.example.test/x", "api.example.test").await;
    assert!(status(&raw).contains("403"), "{raw}");
    assert!(up.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn plain_http_to_localhost_with_a_rule_is_allowed() {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert("localhost".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Deny).unwrap();
    let s = env.vault.add_secret("k", "LOCAL-SECRET").unwrap();
    add_rule(&env.vault, NewRule {
        role: "developer".into(), host_pattern: "localhost".into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Header, target_name: "X-Api-Key".into(), template: "{secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("m", "developer");
    let raw = plain_get(&env, &t, "http://localhost/ping", "localhost").await;
    assert!(status(&raw).contains("200"), "{raw}");
    assert_eq!(up.header(0, "x-api-key"), vec!["LOCAL-SECRET".to_string()]);
}

#[tokio::test]
async fn plain_http_without_rules_follows_the_unmatched_policy() {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert("free.example.test".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    add_role(&env.vault, "closed", Unmatched::Deny).unwrap();
    let open = env.token("m", "open");
    let closed = env.token("m", "closed");
    assert!(status(&plain_get(&env, &open, "http://free.example.test/a", "free.example.test").await).contains("200"));
    assert!(status(&plain_get(&env, &closed, "http://free.example.test/a", "free.example.test").await).contains("403"));
    assert_eq!(up.received.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn large_request_body_streams_through_the_mitm() {
    let host = "api.example.test";
    let (env, up) = env_with_upstream(host).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "v").unwrap();
    add_rule(&env.vault, NewRule {
        role: "developer".into(), host_pattern: host.into(), path_pattern: "*".into(), methods: vec![],
        kind: InjectionKind::Header, target_name: "Authorization".into(), template: "Bearer {secret}".into(), secret_id: s.id,
    }).unwrap();
    let t = env.token("m", "developer");
    let body = vec![7u8; 8 * 1024 * 1024];
    let r = proxy_request(&env, &t, host, "POST", "/upload", &[], body, false).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap()[0].body_len, 8 * 1024 * 1024);
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-proxy --test plain_and_streaming`
Expected: FAIL (el proxy responde 501 a las peticiones no-CONNECT).

- [ ] **Step 3: Implementar** en `server.rs`

Sustituir la rama `else` de `handle_request` por:
```rust
    } else {
        plain(req, identity, state).await
    }
```
y añadir:
```rust
async fn plain(req: Request<Incoming>, identity: Identity, state: Arc<ProxyState>) -> Response<ProxyBody> {
    if req.uri().scheme_str() != Some("http") {
        return text(StatusCode::BAD_REQUEST, "send absolute-form http:// requests, or CONNECT for https\n");
    }
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "missing host\n");
    };
    let Some(host) = normalize_host(authority.host()) else {
        return text(StatusCode::BAD_REQUEST, "bad host\n");
    };
    let port = authority.port_u16().unwrap_or(80);
    let role = match get_role(&state.vault, &identity.role) {
        Ok(Some(r)) => r,
        _ => {
            audit(&state, &identity, &host, req.method().as_str(), "/", "unknown-role", Some(403), None);
            return text(StatusCode::FORBIDDEN, "role not found\n");
        }
    };
    let rules = list_rules(&state.vault, Some(&identity.role)).unwrap_or_default();
    let has_rules = has_rules_for_host(&rules, &host);
    if !has_rules && role.unmatched == Unmatched::Deny {
        audit(&state, &identity, &host, req.method().as_str(), "/", "unmatched-denied", Some(403), None);
        return text(StatusCode::FORBIDDEN, "host not allowed for this role\n");
    }
    let ctx = crate::forward::Ctx { state, identity, host, port, tls: false, allow_unruled: !has_rules };
    crate::forward::forward(req, &ctx).await
}
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-proxy`
Expected: todos los tests del crate pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(proxy): handle plain http requests and refuse insecure injection"
```

---

### Task 10: `admin` (API REST, sesiones y guardas web)

**Files:**
- Create: `crates/admin/src/{lib.rs,state.rs,error.rs,api.rs,web.rs,sessions.rs,serve.rs}`
- Test: `crates/admin/tests/api.rs`, `crates/admin/tests/web_guard.rs`

**Interfaces:**
- Consumes: `sg_core::Vault`, `sg_policy::*`, `sg_auth::TokenService`, `sg_ca::CaService`.
- Produces:
  - `struct AppState { vault: Arc<Vault>, tokens: Arc<TokenService>, ca: Arc<CaService>, sessions: Arc<Sessions>, allowed_hosts: Vec<String> }` (`Clone`)
  - `fn api_router(state: AppState) -> Router` (sin guarda; para el socket Unix)
  - `fn web_router(state: AppState) -> Router` (guarda de `Host`, `/login`, `/api` con sesión + CSRF, estáticos con CSP)
  - `struct Sessions` con `new() -> Self`, `new_login_token(&self) -> String`, `exchange(&self, token: &str) -> Option<String>`, `is_valid(&self, session: &str) -> bool`
  - `async fn serve_unix(path: &Path, state: AppState) -> io::Result<()>`, `async fn serve_web(addr: SocketAddr, state: AppState) -> io::Result<()>`
  - Rutas JSON: `GET|POST /secrets`, `GET|PUT|DELETE /secrets/{name}`, `GET|POST /roles`, `DELETE /roles/{name}`, `GET|POST /rules`, `DELETE /rules/{id}`, `GET|POST /tokens`, `DELETE /tokens/{jti}`, `POST /machines/{machine}/revoke`, `GET /ca`, `GET /ca/cert`, `POST /ca/domains`, `GET /audit`

- [ ] **Step 1: Escribir los tests que fallan**

`tests/api.rs`:
```rust
use axum::{body::Body, http::{Request, StatusCode}, Router};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sg_admin::{api_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

fn app() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let state = AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: Arc::new(Sessions::new()),
        allowed_hosts: vec!["localhost:9090".into()],
    };
    (dir, api_router(state))
}

async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => { b = b.header("content-type", "application/json"); Body::from(v.to_string()) }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(b.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    (status, String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string())
}

#[tokio::test]
async fn no_route_ever_returns_a_secret_value() {
    let (_d, app) = app();
    let (st, _) = call(&app, "POST", "/secrets", Some(json!({"name":"gh","value":"TOPSECRET-VALUE"}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let mut dump = String::new();
    for uri in ["/secrets", "/secrets/gh", "/roles", "/rules", "/tokens", "/ca", "/audit"] {
        dump.push_str(&call(&app, "GET", uri, None).await.1);
    }
    let (_, rot) = call(&app, "PUT", "/secrets/gh", Some(json!({"value":"ROTATED-VALUE"}))).await;
    dump.push_str(&rot);
    assert!(!dump.contains("TOPSECRET-VALUE") && !dump.contains("ROTATED-VALUE"));
}

#[tokio::test]
async fn secret_with_crlf_is_rejected_with_400() {
    let (_d, app) = app();
    let (st, _) = call(&app, "POST", "/secrets", Some(json!({"name":"x","value":"a\r\nEvil: 1"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_policy_flow_and_conflicts() {
    let (_d, app) = app();
    call(&app, "POST", "/secrets", Some(json!({"name":"gh","value":"v"}))).await;
    assert_eq!(call(&app, "POST", "/roles", Some(json!({"name":"dev","unmatched":"passthrough"}))).await.0, StatusCode::CREATED);
    assert_eq!(call(&app, "POST", "/roles", Some(json!({"name":"dev","unmatched":"deny"}))).await.0, StatusCode::CONFLICT);
    let (st, body) = call(&app, "POST", "/rules", Some(json!({
        "role":"dev","host_pattern":"api.github.com","methods":["GET"],"kind":"header",
        "target_name":"Authorization","template":"Bearer {secret}","secret_id":1
    }))).await;
    assert_eq!(st, StatusCode::CREATED);
    let v: Value = serde_json::from_str(&body).unwrap();
    assert!(v["ca_warning"].as_str().unwrap().contains("allow-domain"));
    assert_eq!(call(&app, "DELETE", "/secrets/gh", None).await.0, StatusCode::CONFLICT);
    assert_eq!(call(&app, "DELETE", &format!("/rules/{}", v["rule"]["id"]), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, "DELETE", "/secrets/gh", None).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn token_is_shown_once_and_can_be_revoked() {
    let (_d, app) = app();
    call(&app, "POST", "/roles", Some(json!({"name":"dev","unmatched":"deny"}))).await;
    let (st, body) = call(&app, "POST", "/tokens", Some(json!({"machine":"laptop","role":"dev","ttl_secs":3600}))).await;
    assert_eq!(st, StatusCode::CREATED);
    let created: Value = serde_json::from_str(&body).unwrap();
    let token = created["token"].as_str().unwrap().to_string();
    let listing = call(&app, "GET", "/tokens", None).await.1;
    assert!(!listing.contains(&token));
    let jti = created["jti"].as_str().unwrap();
    assert_eq!(call(&app, "DELETE", &format!("/tokens/{jti}"), None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(call(&app, "POST", "/tokens", Some(json!({"machine":"m","role":"ghost"}))).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ca_endpoints() {
    let (_d, app) = app();
    let (st, pem) = call(&app, "GET", "/ca/cert", None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(call(&app, "POST", "/ca/domains", Some(json!({"domain":"github.com"}))).await.0, StatusCode::OK);
    assert_eq!(call(&app, "POST", "/ca/domains", Some(json!({"domain":"com"}))).await.0, StatusCode::BAD_REQUEST);
    let (_, status) = call(&app, "GET", "/ca", None).await;
    assert!(status.contains("github.com"));
}
```

`tests/web_guard.rs`:
```rust
use axum::{body::Body, http::{header, Request, StatusCode}, Router};
use sg_admin::{web_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

fn app() -> (tempfile::TempDir, Router, Arc<Sessions>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let sessions = Arc::new(Sessions::new());
    let state = AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault, sessions: sessions.clone(), allowed_hosts: vec!["localhost:9090".into(), "127.0.0.1:9090".into()],
    };
    (dir, web_router(state), sessions)
}

fn req(method: &str, uri: &str, host: &str, cookie: Option<&str>, csrf: bool) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri).header(header::HOST, host);
    if let Some(c) = cookie { b = b.header(header::COOKIE, format!("sg_session={c}")); }
    if csrf { b = b.header("x-sg-csrf", "1"); }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn wrong_host_header_is_rejected_everywhere() {
    let (_d, app, _s) = app();
    for uri in ["/", "/login?t=x", "/api/secrets"] {
        let r = app.clone().oneshot(req("GET", uri, "evil.com", None, false)).await.unwrap();
        assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn api_requires_a_session() {
    let (_d, app, _s) = app();
    let r = app.oneshot(req("GET", "/api/secrets", "localhost:9090", None, false)).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_token_is_single_use_and_sets_a_strict_cookie() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    let r = app.clone().oneshot(req("GET", &format!("/login?t={t}"), "localhost:9090", None, false)).await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let cookie = r.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let again = app.oneshot(req("GET", &format!("/login?t={t}"), "localhost:9090", None, false)).await.unwrap();
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn writes_need_the_csrf_header() {
    let (_d, app, sessions) = app();
    let s = sessions.exchange(&sessions.new_login_token()).unwrap();
    let no = app.clone().oneshot(req("POST", "/api/roles", "localhost:9090", Some(&s), false)).await.unwrap();
    assert_eq!(no.status(), StatusCode::FORBIDDEN);
    let get = app.oneshot(req("GET", "/api/secrets", "localhost:9090", Some(&s), false)).await.unwrap();
    assert_eq!(get.status(), StatusCode::OK);
}

#[tokio::test]
async fn static_pages_carry_a_strict_csp() {
    let (_d, app, _s) = app();
    let r = app.oneshot(req("GET", "/", "localhost:9090", None, false)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let csp = r.headers().get("content-security-policy").unwrap().to_str().unwrap();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-admin`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar**

`sessions.rs`:
```rust
use std::{collections::{HashMap, HashSet}, sync::Mutex, time::{Duration, Instant}};

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

#[derive(Default)]
pub struct Sessions {
    login: Mutex<HashSet<String>>,
    active: Mutex<HashMap<String, Instant>>,
}

fn random_hex() -> String {
    hex::encode(sg_core::crypto::random_bytes::<32>())
}

impl Sessions {
    pub fn new() -> Self { Self::default() }

    pub fn new_login_token(&self) -> String {
        let t = random_hex();
        self.login.lock().unwrap().insert(t.clone());
        t
    }

    pub fn exchange(&self, token: &str) -> Option<String> {
        if !self.login.lock().unwrap().remove(token) {
            return None;
        }
        let s = random_hex();
        self.active.lock().unwrap().insert(s.clone(), Instant::now());
        Some(s)
    }

    pub fn is_valid(&self, session: &str) -> bool {
        let mut a = self.active.lock().unwrap();
        a.retain(|_, at| at.elapsed() < SESSION_TTL);
        a.contains_key(session)
    }
}
```

`state.rs`:
```rust
use crate::sessions::Sessions;
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::Vault;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<Vault>,
    pub tokens: Arc<TokenService>,
    pub ca: Arc<CaService>,
    pub sessions: Arc<Sessions>,
    pub allowed_hosts: Vec<String>,
}
```

`error.rs`:
```rust
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

pub struct ApiError(pub StatusCode, pub String);
pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sg_core::CoreError> for ApiError {
    fn from(e: sg_core::CoreError) -> Self {
        use sg_core::CoreError::*;
        let code = match e {
            InvalidSecretValue(_) | InvalidName(_) | InvalidKey => StatusCode::BAD_REQUEST,
            NotFound => StatusCode::NOT_FOUND,
            AlreadyExists | InUse => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(code, e.to_string())
    }
}

impl From<sg_policy::PolicyError> for ApiError {
    fn from(e: sg_policy::PolicyError) -> Self {
        use sg_policy::PolicyError::*;
        match e {
            Invalid(m) => ApiError(StatusCode::BAD_REQUEST, m.into()),
            NotFound => ApiError(StatusCode::NOT_FOUND, "not found".into()),
            AlreadyExists => ApiError(StatusCode::CONFLICT, "already exists".into()),
            Core(c) => c.into(),
            Db(d) => ApiError(StatusCode::INTERNAL_SERVER_ERROR, d.to_string()),
        }
    }
}

impl From<sg_auth::AuthError> for ApiError {
    fn from(e: sg_auth::AuthError) -> Self {
        match e {
            sg_auth::AuthError::Core(c) => c.into(),
            sg_auth::AuthError::InvalidTtl => ApiError(StatusCode::BAD_REQUEST, "ttl out of range".into()),
            other => ApiError(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        }
    }
}

impl From<sg_ca::CaError> for ApiError {
    fn from(e: sg_ca::CaError) -> Self {
        match e {
            sg_ca::CaError::DomainRejected(m) => ApiError(StatusCode::BAD_REQUEST, m.into()),
            other => ApiError(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        }
    }
}
```

`api.rs`:
```rust
use crate::{error::*, state::AppState};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sg_core::{audit::AuditFilter, SecretMeta};
use sg_policy::{NewRule, Unmatched};
use std::time::Duration;

pub fn api_router(state: AppState) -> Router {
    Router::new()
        .route("/secrets", get(list_secrets).post(add_secret))
        .route("/secrets/{name}", get(get_secret).put(rotate_secret).delete(delete_secret))
        .route("/roles", get(list_roles).post(add_role))
        .route("/roles/{name}", delete(delete_role))
        .route("/rules", get(list_rules).post(add_rule))
        .route("/rules/{id}", delete(delete_rule))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{jti}", delete(revoke_token))
        .route("/machines/{machine}/revoke", post(revoke_machine))
        .route("/ca", get(ca_status))
        .route("/ca/cert", get(ca_cert))
        .route("/ca/domains", post(ca_allow))
        .route("/audit", get(audit))
        .with_state(state)
}

#[derive(Deserialize)]
struct NewSecret { name: String, value: String }
#[derive(Deserialize)]
struct RotateSecret { value: String }

async fn list_secrets(State(s): State<AppState>) -> ApiResult<Json<Vec<SecretMeta>>> {
    Ok(Json(s.vault.list_secrets()?))
}
async fn get_secret(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<Json<SecretMeta>> {
    Ok(Json(s.vault.get_secret_meta(&name)?))
}
async fn add_secret(State(s): State<AppState>, Json(b): Json<NewSecret>) -> ApiResult<(StatusCode, Json<SecretMeta>)> {
    Ok((StatusCode::CREATED, Json(s.vault.add_secret(&b.name, &b.value)?)))
}
async fn rotate_secret(State(s): State<AppState>, Path(name): Path<String>, Json(b): Json<RotateSecret>) -> ApiResult<Json<SecretMeta>> {
    Ok(Json(s.vault.rotate_secret(&name, &b.value)?))
}
async fn delete_secret(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<StatusCode> {
    s.vault.remove_secret(&name)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NewRole { name: String, unmatched: Unmatched }

async fn list_roles(State(s): State<AppState>) -> ApiResult<Json<Vec<sg_policy::Role>>> {
    Ok(Json(sg_policy::list_roles(&s.vault)?))
}
async fn add_role(State(s): State<AppState>, Json(b): Json<NewRole>) -> ApiResult<(StatusCode, Json<sg_policy::Role>)> {
    Ok((StatusCode::CREATED, Json(sg_policy::add_role(&s.vault, &b.name, b.unmatched)?)))
}
async fn delete_role(State(s): State<AppState>, Path(name): Path<String>) -> ApiResult<StatusCode> {
    sg_policy::remove_role(&s.vault, &name)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RuleQuery { role: Option<String> }

async fn list_rules(State(s): State<AppState>, Query(q): Query<RuleQuery>) -> ApiResult<Json<Vec<sg_policy::Rule>>> {
    Ok(Json(sg_policy::list_rules(&s.vault, q.role.as_deref())?))
}
async fn add_rule(State(s): State<AppState>, Json(b): Json<NewRule>) -> ApiResult<(StatusCode, Json<Value>)> {
    let host = b.host_pattern.trim_start_matches("*.").to_string();
    let rule = sg_policy::add_rule(&s.vault, b)?;
    let warning = (!s.ca.is_host_permitted(&host)).then(|| {
        format!("the CA does not permit {host}: run `sg ca allow-domain {host}` and reload the CA certificate in your agents")
    });
    Ok((StatusCode::CREATED, Json(json!({ "rule": rule, "ca_warning": warning }))))
}
async fn delete_rule(State(s): State<AppState>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    sg_policy::remove_rule(&s.vault, id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct NewToken { machine: String, role: String, ttl_secs: Option<u64> }

async fn create_token(State(s): State<AppState>, Json(b): Json<NewToken>) -> ApiResult<(StatusCode, Json<Value>)> {
    if b.machine.trim().is_empty() || sg_policy::get_role(&s.vault, &b.role)?.is_none() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "machine is required and the role must exist".into()));
    }
    if b.ttl_secs.is_some_and(|t| t > 315_360_000) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "ttl_secs must be at most 10 years (315360000)".into()));
    }
    let t = s.tokens.issue(&b.machine, &b.role, b.ttl_secs.map(Duration::from_secs))?;
    Ok((StatusCode::CREATED, Json(json!({ "token": t.token, "jti": t.jti, "machine": b.machine, "role": b.role }))))
}
async fn list_tokens(State(s): State<AppState>) -> ApiResult<Json<Vec<sg_auth::TokenMeta>>> {
    Ok(Json(s.tokens.list()?))
}
async fn revoke_token(State(s): State<AppState>, Path(jti): Path<String>) -> ApiResult<StatusCode> {
    s.tokens.revoke(&jti)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn revoke_machine(State(s): State<AppState>, Path(machine): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "revoked": s.tokens.revoke_machine(&machine)? })))
}

async fn ca_status(State(s): State<AppState>) -> Json<Value> {
    Json(json!({ "domains": s.ca.domains() }))
}
async fn ca_cert(State(s): State<AppState>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/x-pem-file")], s.ca.cert_pem())
}
#[derive(Deserialize)]
struct AllowDomain { domain: String }
async fn ca_allow(State(s): State<AppState>, Json(b): Json<AllowDomain>) -> ApiResult<Json<Value>> {
    s.ca.allow_domain(&b.domain)?;
    Ok(Json(json!({
        "domains": s.ca.domains(),
        "notice": "the CA certificate changed: agents must reload it (sg ca export)"
    })))
}

async fn audit(State(s): State<AppState>, Query(f): Query<AuditFilter>) -> ApiResult<Json<Vec<sg_core::audit::AuditEntry>>> {
    Ok(Json(s.vault.list_audit(&f)?))
}
```

`web.rs`:
```rust
use crate::{api::api_router, state::AppState};
use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;

#[derive(RustEmbed)]
#[folder = "../../web/"]
struct Assets;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub fn web_router(state: AppState) -> Router {
    let api = api_router(state.clone()).layer(from_fn_with_state(state.clone(), session_guard));
    Router::new()
        .route("/login", get(login))
        .nest("/api", api)
        .fallback(static_asset)
        .layer(from_fn_with_state(state.clone(), host_guard))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
}

async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    resp
}

async fn host_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| s.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)))
        .unwrap_or(false);
    if !ok {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected Host header").into_response();
    }
    next.run(req).await
}

fn session_cookie(req: &Request) -> Option<String> {
    let raw = req.headers().get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|p| p.trim().strip_prefix("sg_session=").map(String::from))
}

async fn session_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match session_cookie(&req) {
        Some(c) if s.sessions.is_valid(&c) => {}
        _ => return (StatusCode::UNAUTHORIZED, "login required: use the URL printed by `sg serve`").into_response(),
    }
    let is_write = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_write && req.headers().get("x-sg-csrf").is_none() {
        return (StatusCode::FORBIDDEN, "missing X-SG-CSRF header").into_response();
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct LoginQuery { t: String }

async fn login(State(s): State<AppState>, Query(q): Query<LoginQuery>) -> Response {
    match s.sessions.exchange(&q.t) {
        Some(session) => {
            let cookie = format!("sg_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800");
            let mut r = Redirect::to("/").into_response();
            r.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
            r
        }
        None => (StatusCode::UNAUTHORIZED, "invalid or already used login link").into_response(),
    }
}

async fn static_asset(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(file) => ([(header::CONTENT_TYPE, file.metadata.mimetype().to_string())], file.data.into_owned()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
```

`serve.rs`:
```rust
use crate::{api::api_router, state::AppState, web::web_router};
use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::Path};
use tokio::net::{TcpListener, UnixListener};

pub async fn serve_unix(path: &Path, state: AppState) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    axum::serve(listener, api_router(state)).await
}

pub async fn serve_web(listener: TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, web_router(state)).await
}

pub fn allowed_hosts_for(addr: SocketAddr) -> Vec<String> {
    let p = addr.port();
    vec![format!("localhost:{p}"), format!("127.0.0.1:{p}"), format!("[::1]:{p}")]
}
```
(Para `--admin-bind` no-loopback se añade en la Tarea 13 el aviso y, si procede, el host publicado.)

`lib.rs`:
```rust
mod api;
mod error;
mod serve;
mod sessions;
mod state;
mod web;

pub use api::api_router;
pub use serve::{allowed_hosts_for, serve_unix, serve_web};
pub use sessions::Sessions;
pub use state::AppState;
pub use web::web_router;
```

Crear antes un `web/index.html` mínimo (`<!doctype html><title>Secret Guardian</title>`) para que `rust-embed` compile; la interfaz real llega en la Tarea 12.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-admin`
Expected: todos pasan (`api` y `web_guard`).

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(admin): add admin API, web session guards and CSP"
```

---

### Task 11: `cli` (cliente por socket Unix)

**Files:**
- Create: `crates/cli/src/{lib.rs,client.rs,commands.rs}`
- Test: `crates/cli/tests/client.rs`, tests de parseo en `commands.rs`

**Interfaces:**
- Consumes: la API de la Tarea 10 por socket Unix.
- Produces:
  - `async fn call(socket: &Path, method: http::Method, path: &str, body: Option<serde_json::Value>) -> anyhow::Result<(http::StatusCode, serde_json::Value)>`
  - `#[derive(Subcommand)] enum ClientCommand { Secret(..), Role(..), Rule(..), Token(..), Ca(..), Audit(..) }`
  - `async fn run(socket: &Path, cmd: ClientCommand) -> anyhow::Result<()>`

- [ ] **Step 1: Escribir los tests que fallan**

Parseo (`commands.rs`, módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap { #[command(subcommand)] cmd: ClientCommand }

    #[test]
    fn rule_add_parses_all_flags() {
        let w = Wrap::try_parse_from([
            "sg", "rule", "add", "--role", "reviewer", "--host", "api.github.com", "--path", "/repos/*",
            "--methods", "GET,HEAD", "--header", "Authorization", "--template", "Bearer {secret}", "--secret", "gh",
        ]).unwrap();
        assert!(matches!(w.cmd, ClientCommand::Rule(_)));
    }

    #[test]
    fn rule_needs_header_or_query_but_not_both() {
        assert!(Wrap::try_parse_from(["sg", "rule", "add", "--role", "r", "--host", "h.com", "--template", "{secret}", "--secret", "s"]).is_err());
        assert!(Wrap::try_parse_from([
            "sg", "rule", "add", "--role", "r", "--host", "h.com", "--header", "A", "--query", "b", "--template", "{secret}", "--secret", "s",
        ]).is_err());
    }

    #[test]
    fn secret_add_has_no_value_argument() {
        assert!(Wrap::try_parse_from(["sg", "secret", "add", "gh", "ghp_literal_value"]).is_err());
        assert!(Wrap::try_parse_from(["sg", "secret", "add", "gh"]).is_ok());
    }
}
```

`tests/client.rs`:
```rust
use axum::{routing::get, Json, Router};
use serde_json::json;
use tokio::net::UnixListener;

#[tokio::test]
async fn call_roundtrips_json_over_a_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().route("/ping", get(|| async { Json(json!({"pong": true})) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (st, v) = sg_cli::call(&sock, http::Method::GET, "/ping", None).await.unwrap();
    assert_eq!(st, 200);
    assert_eq!(v["pong"], true);
}

#[tokio::test]
async fn missing_socket_gives_an_actionable_error() {
    let err = sg_cli::call(std::path::Path::new("/nonexistent/sg.sock"), http::Method::GET, "/ping", None).await.unwrap_err();
    assert!(err.to_string().contains("sg serve"));
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-cli`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar**

`client.rs`:
```rust
use anyhow::Context;
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::path::Path;

pub async fn call(socket: &Path, method: Method, path: &str, body: Option<Value>) -> anyhow::Result<(StatusCode, Value)> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| format!("cannot reach the vault at {} (is `sg serve` running?)", socket.display()))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)))?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await?.to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    Ok((status, value))
}
```

`commands.rs` (encima de los tests):
```rust
use crate::client::call;
use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use http::Method;
use serde_json::{json, Value};
use std::{io::Read, path::Path};

#[derive(Subcommand)]
pub enum ClientCommand {
    /// Manage secrets (values are write-only)
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Manage roles
    #[command(subcommand)]
    Role(RoleCmd),
    /// Manage injection rules
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Manage machine tokens
    #[command(subcommand)]
    Token(TokenCmd),
    /// Manage the certificate authority
    #[command(subcommand)]
    Ca(CaCmd),
    /// Show the audit log
    Audit(AuditArgs),
}

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Add a secret; the value is read from stdin or a hidden prompt
    Add { name: String },
    /// Rotate a secret's value
    Rotate { name: String },
    Rm { name: String },
    Ls,
}

#[derive(Subcommand)]
pub enum RoleCmd {
    Add { name: String, #[arg(long, default_value = "passthrough", value_parser = ["passthrough", "deny"])] unmatched: String },
    Rm { name: String },
    Ls,
}

#[derive(Args)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["header", "query"])))]
pub struct RuleAdd {
    #[arg(long)] role: String,
    #[arg(long)] host: String,
    #[arg(long, default_value = "*")] path: String,
    #[arg(long, value_delimiter = ',')] methods: Vec<String>,
    #[arg(long)] header: Option<String>,
    #[arg(long)] query: Option<String>,
    #[arg(long, default_value = "{secret}")] template: String,
    /// Name of an existing secret
    #[arg(long)] secret: String,
}

#[derive(Subcommand)]
pub enum RuleCmd {
    Add(RuleAdd),
    Rm { id: i64 },
    Ls { #[arg(long)] role: Option<String> },
}

#[derive(Subcommand)]
pub enum TokenCmd {
    Create {
        #[arg(long)] machine: String,
        #[arg(long)] role: String,
        /// Lifetime in seconds (omit for no expiry)
        #[arg(long)] ttl: Option<u64>,
    },
    Revoke { jti: String },
    RevokeMachine { machine: String },
    Ls,
}

#[derive(Subcommand)]
pub enum CaCmd {
    /// Print the CA certificate (PEM)
    Export,
    /// Permit a domain (and its subdomains); re-issues the CA certificate
    AllowDomain { domain: String },
    Status,
}

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long)] role: Option<String>,
    #[arg(long)] host: Option<String>,
    #[arg(long)] since: Option<i64>,
    #[arg(long, default_value_t = 50)] limit: usize,
}

fn read_secret_value() -> anyhow::Result<String> {
    use std::io::IsTerminal;
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Secret value: ")?
    } else {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim_end_matches(['\r', '\n']).to_string()
    };
    if value.is_empty() {
        bail!("empty value");
    }
    Ok(value)
}

async fn ok(socket: &Path, m: Method, path: &str, body: Option<Value>) -> anyhow::Result<Value> {
    let (status, v) = call(socket, m, path, body).await?;
    if !status.is_success() {
        let msg = v.get("error").and_then(|e| e.as_str()).map(String::from).unwrap_or_else(|| v.to_string());
        bail!("{status}: {msg}");
    }
    Ok(v)
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

pub async fn run(socket: &Path, cmd: ClientCommand) -> anyhow::Result<()> {
    match cmd {
        ClientCommand::Secret(c) => match c {
            SecretCmd::Add { name } => {
                let value = read_secret_value()?;
                ok(socket, Method::POST, "/secrets", Some(json!({ "name": name, "value": value }))).await?;
                println!("secret '{name}' stored");
            }
            SecretCmd::Rotate { name } => {
                let value = read_secret_value()?;
                ok(socket, Method::PUT, &format!("/secrets/{name}"), Some(json!({ "value": value }))).await?;
                println!("secret '{name}' rotated");
            }
            SecretCmd::Rm { name } => {
                ok(socket, Method::DELETE, &format!("/secrets/{name}"), None).await?;
                println!("secret '{name}' removed");
            }
            SecretCmd::Ls => print_json(&ok(socket, Method::GET, "/secrets", None).await?),
        },
        ClientCommand::Role(c) => match c {
            RoleCmd::Add { name, unmatched } => {
                ok(socket, Method::POST, "/roles", Some(json!({ "name": name, "unmatched": unmatched }))).await?;
                println!("role '{name}' created");
            }
            RoleCmd::Rm { name } => {
                ok(socket, Method::DELETE, &format!("/roles/{name}"), None).await?;
                println!("role '{name}' removed");
            }
            RoleCmd::Ls => print_json(&ok(socket, Method::GET, "/roles", None).await?),
        },
        ClientCommand::Rule(c) => match c {
            RuleCmd::Add(a) => {
                let secrets = ok(socket, Method::GET, "/secrets", None).await?;
                let secret_id = secrets
                    .as_array()
                    .and_then(|l| l.iter().find(|s| s["name"] == a.secret.as_str()))
                    .and_then(|s| s["id"].as_i64())
                    .with_context(|| format!("secret '{}' not found", a.secret))?;
                let (kind, target) = match (&a.header, &a.query) {
                    (Some(h), None) => ("header", h.clone()),
                    (None, Some(q)) => ("query", q.clone()),
                    _ => bail!("use exactly one of --header or --query"),
                };
                let v = ok(socket, Method::POST, "/rules", Some(json!({
                    "role": a.role, "host_pattern": a.host, "path_pattern": a.path, "methods": a.methods,
                    "kind": kind, "target_name": target, "template": a.template, "secret_id": secret_id
                }))).await?;
                println!("rule {} created", v["rule"]["id"]);
                if let Some(w) = v["ca_warning"].as_str() {
                    eprintln!("warning: {w}");
                }
            }
            RuleCmd::Rm { id } => {
                ok(socket, Method::DELETE, &format!("/rules/{id}"), None).await?;
                println!("rule {id} removed");
            }
            RuleCmd::Ls { role } => {
                let path = role.map(|r| format!("/rules?role={r}")).unwrap_or_else(|| "/rules".into());
                print_json(&ok(socket, Method::GET, &path, None).await?)
            }
        },
        ClientCommand::Token(c) => match c {
            TokenCmd::Create { machine, role, ttl } => {
                let v = ok(socket, Method::POST, "/tokens", Some(json!({ "machine": machine, "role": role, "ttl_secs": ttl }))).await?;
                let token = v["token"].as_str().unwrap_or_default();
                println!("token (shown once): {token}\n");
                println!("export HTTPS_PROXY=http://{machine}:{token}@127.0.0.1:8080");
                println!("export HTTP_PROXY=$HTTPS_PROXY");
                println!("sg ca export > sg-ca.pem   # then SSL_CERT_FILE / NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE");
            }
            TokenCmd::Revoke { jti } => {
                ok(socket, Method::DELETE, &format!("/tokens/{jti}"), None).await?;
                println!("token {jti} revoked");
            }
            TokenCmd::RevokeMachine { machine } => {
                let v = ok(socket, Method::POST, &format!("/machines/{machine}/revoke"), None).await?;
                println!("{} token(s) revoked for '{machine}'", v["revoked"]);
            }
            TokenCmd::Ls => print_json(&ok(socket, Method::GET, "/tokens", None).await?),
        },
        ClientCommand::Ca(c) => match c {
            CaCmd::Export => {
                let (st, v) = call(socket, Method::GET, "/ca/cert", None).await?;
                if !st.is_success() {
                    bail!("{st}");
                }
                print!("{}", v.as_str().unwrap_or_default());
            }
            CaCmd::AllowDomain { domain } => {
                let v = ok(socket, Method::POST, "/ca/domains", Some(json!({ "domain": domain }))).await?;
                println!("{}", v["notice"].as_str().unwrap_or("done"));
            }
            CaCmd::Status => print_json(&ok(socket, Method::GET, "/ca", None).await?),
        },
        ClientCommand::Audit(a) => {
            let mut q = vec![format!("limit={}", a.limit)];
            if let Some(r) = a.role { q.push(format!("role={r}")); }
            if let Some(h) = a.host { q.push(format!("host={h}")); }
            if let Some(s) = a.since { q.push(format!("since={s}")); }
            print_json(&ok(socket, Method::GET, &format!("/audit?{}", q.join("&")), None).await?);
        }
    }
    Ok(())
}
```

`lib.rs`:
```rust
mod client;
mod commands;

pub use client::call;
pub use commands::{run, ClientCommand};
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-cli`
Expected: todos pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(cli): add unix-socket admin client and commands"
```

---

### Task 12: Interfaz web

**Files:**
- Create: `web/index.html`, `web/app.js`, `web/style.css`
- Test: `crates/admin/tests/web_assets.rs`

**Interfaces:**
- Consumes: la API `/api/*` (Tarea 10) con la cookie de sesión y la cabecera `X-SG-CSRF: 1` en escrituras.
- Produces: SPA estática con pestañas Secretos, Roles y reglas, Tokens, CA, Audit.

- [ ] **Step 1: Escribir el test que falla** (`crates/admin/tests/web_assets.rs`)

```rust
use axum::{body::Body, http::{header, Request, StatusCode}};
use http_body_util::BodyExt;
use sg_admin::{web_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

async fn get(path: &str) -> (StatusCode, String) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::init(&dir.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let app = web_router(AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault, sessions: Arc::new(Sessions::new()), allowed_hosts: vec!["localhost:9090".into()],
    });
    let r = app.oneshot(Request::builder().uri(path).header(header::HOST, "localhost:9090").body(Body::empty()).unwrap()).await.unwrap();
    let st = r.status();
    (st, String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).to_string())
}

#[tokio::test]
async fn assets_are_served() {
    for p in ["/", "/app.js", "/style.css"] {
        assert_eq!(get(p).await.0, StatusCode::OK, "{p}");
    }
}

#[tokio::test]
async fn frontend_never_uses_dangerous_dom_sinks_or_external_resources() {
    let (_, js) = get("/app.js").await;
    let (_, html) = get("/").await;
    for sink in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"] {
        assert!(!js.contains(sink), "app.js uses {sink}");
    }
    assert!(!html.contains("http://") && !html.contains("https://"), "index.html references an external origin");
    assert!(!html.contains("<script>") && !html.contains("onclick="), "inline script is blocked by the CSP");
}

#[tokio::test]
async fn frontend_sends_the_csrf_header_on_writes() {
    let (_, js) = get("/app.js").await;
    assert!(js.contains("X-SG-CSRF"));
}
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg-admin --test web_assets`
Expected: FAIL (`/app.js` devuelve 404).

- [ ] **Step 3: Implementar**

`web/index.html`:
```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secret Guardian</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header><h1>Secret Guardian</h1><nav id="tabs"></nav></header>
  <main id="view"></main>
  <script src="/app.js" defer></script>
</body>
</html>
```

`web/style.css`:
```css
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; }
header { display: flex; gap: 2rem; align-items: center; padding: .75rem 1.5rem; border-bottom: 1px solid #8884; }
h1 { font-size: 1.1rem; margin: 0; }
nav button { margin-right: .4rem; }
nav button.active { font-weight: bold; }
main { padding: 1.5rem; max-width: 70rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid #8883; font-size: .9rem; }
form { display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0; }
input, select, button { padding: .35rem .6rem; font: inherit; }
.notice { padding: .6rem 1rem; background: #fc03; border-radius: .3rem; margin: 1rem 0; }
.error { padding: .6rem 1rem; background: #f003; border-radius: .3rem; margin: 1rem 0; }
code, pre { font-family: ui-monospace, monospace; word-break: break-all; }
```

`web/app.js`:
```js
"use strict";

const view = document.getElementById("view");
const tabsEl = document.getElementById("tabs");

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "onclick" || k === "onsubmit" || k === "onchange") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) node.append(c instanceof Node ? c : document.createTextNode(String(c ?? "")));
  return node;
}

async function api(method, path, body) {
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET") headers["X-SG-CSRF"] = "1";
  const resp = await fetch("/api" + path, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: "same-origin" });
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!resp.ok) throw new Error((data && data.error) || `${resp.status} ${resp.statusText}`);
  return data;
}

function message(kind, text) {
  const box = el("div", { class: kind }, text);
  view.prepend(box);
}

function table(headers, rows) {
  return el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((r) => el("tr", {}, r.map((c) => el("td", {}, c))))));
}

function form(fields, submitLabel, onSubmit) {
  const inputs = fields.map((f) => f.options
    ? el("select", { name: f.name }, f.options.map((o) => el("option", { value: o }, o)))
    : el("input", { name: f.name, placeholder: f.label, type: f.type || "text", required: f.optional ? null : "required", autocomplete: "off" }));
  const node = el("form", { onsubmit: async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(inputs.map((i) => [i.name, i.value]));
    try { await onSubmit(data); inputs.forEach((i) => { i.value = ""; }); } catch (err) { message("error", err.message); }
  } }, inputs, el("button", { type: "submit" }, submitLabel));
  return node;
}

const tabs = {
  async Secrets() {
    const list = await api("GET", "/secrets");
    return [
      el("p", {}, "Values are write-only: they can be added or rotated but never read back."),
      table(["Name", "Created", "Rotated", ""], list.map((s) => [s.name, new Date(s.created_at * 1000).toLocaleString(),
        s.rotated_at ? new Date(s.rotated_at * 1000).toLocaleString() : "-",
        el("button", { onclick: async () => { await api("DELETE", `/secrets/${encodeURIComponent(s.name)}`).catch((e) => message("error", e.message)); show("Secrets"); } }, "Delete")])),
      form([{ name: "name", label: "name" }, { name: "value", label: "value", type: "password" }], "Add secret",
        async (d) => { await api("POST", "/secrets", d); show("Secrets"); }),
    ];
  },
  async Roles() {
    const [roles, rules, secrets] = await Promise.all([api("GET", "/roles"), api("GET", "/rules"), api("GET", "/secrets")]);
    return [
      table(["Role", "Unmatched hosts", ""], roles.map((r) => [r.name, r.unmatched,
        el("button", { onclick: async () => { await api("DELETE", `/roles/${encodeURIComponent(r.name)}`).catch((e) => message("error", e.message)); show("Roles"); } }, "Delete")])),
      form([{ name: "name", label: "role name" }, { name: "unmatched", options: ["passthrough", "deny"] }], "Add role",
        async (d) => { await api("POST", "/roles", d); show("Roles"); }),
      el("h3", {}, "Rules"),
      table(["#", "Role", "Host", "Path", "Methods", "Injection", "Secret", ""], rules.map((r) => [r.id, r.role, r.host_pattern, r.path_pattern,
        r.methods.join(",") || "any", `${r.kind}:${r.target_name} = ${r.template}`,
        (secrets.find((s) => s.id === r.secret_id) || {}).name || r.secret_id,
        el("button", { onclick: async () => { await api("DELETE", `/rules/${r.id}`).catch((e) => message("error", e.message)); show("Roles"); } }, "Delete")])),
      form([
        { name: "role", options: roles.map((r) => r.name) }, { name: "host_pattern", label: "host (api.github.com or *.example.com)" },
        { name: "path_pattern", label: "path (default *)", optional: true }, { name: "methods", label: "methods (GET,HEAD; empty = any)", optional: true },
        { name: "kind", options: ["header", "query"] }, { name: "target_name", label: "header or parameter name" },
        { name: "template", label: "template, e.g. Bearer {secret}" }, { name: "secret", options: secrets.map((s) => s.name) },
      ], "Add rule", async (d) => {
        const secret = secrets.find((s) => s.name === d.secret);
        const out = await api("POST", "/rules", {
          role: d.role, host_pattern: d.host_pattern, path_pattern: d.path_pattern || "*",
          methods: d.methods ? d.methods.split(",").map((m) => m.trim()).filter(Boolean) : [],
          kind: d.kind, target_name: d.target_name, template: d.template, secret_id: secret.id,
        });
        await show("Roles");
        if (out.ca_warning) message("notice", out.ca_warning);
      }),
    ];
  },
  async Tokens() {
    const [tokens, roles] = await Promise.all([api("GET", "/tokens"), api("GET", "/roles")]);
    return [
      table(["Machine", "Role", "Created", "Expires", "Status", ""], tokens.map((t) => [t.machine, t.role,
        new Date(t.created_at * 1000).toLocaleString(), t.expires_at ? new Date(t.expires_at * 1000).toLocaleString() : "never",
        t.revoked_at ? "revoked" : "active",
        t.revoked_at ? "" : el("button", { onclick: async () => { await api("DELETE", `/tokens/${t.jti}`).catch((e) => message("error", e.message)); show("Tokens"); } }, "Revoke")])),
      form([{ name: "machine", label: "machine" }, { name: "role", options: roles.map((r) => r.name) }, { name: "ttl", label: "ttl seconds (optional)", optional: true }], "Create token",
        async (d) => {
          const out = await api("POST", "/tokens", { machine: d.machine, role: d.role, ttl_secs: d.ttl ? Number(d.ttl) : null });
          await show("Tokens");
          view.prepend(el("div", { class: "notice" }, el("p", {}, "Copy this token now; it is shown only once:"), el("pre", {}, out.token),
            el("pre", {}, `export HTTPS_PROXY=http://${out.machine}:${out.token}@127.0.0.1:8080`)));
        }),
    ];
  },
  async CA() {
    const status = await api("GET", "/ca");
    return [
      el("p", {}, "Agents must trust this CA (per process, via SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE)."),
      el("p", {}, el("a", { href: "/api/ca/cert", download: "sg-ca.pem" }, "Download CA certificate")),
      el("h3", {}, "Permitted domains (subdomains included)"),
      el("ul", {}, status.domains.map((d) => el("li", {}, d))),
      form([{ name: "domain", label: "github.com" }], "Allow domain", async (d) => {
        const out = await api("POST", "/ca/domains", d);
        await show("CA");
        message("notice", out.notice);
      }),
    ];
  },
  async Audit() {
    const rows = await api("GET", "/audit?limit=200");
    return [table(["Time", "Machine", "Role", "Method", "Host", "Path", "Decision", "Status"],
      rows.map((r) => [new Date(r.ts * 1000).toLocaleString(), r.machine || "-", r.role || "-", r.method, r.host, r.path, r.decision, r.status ?? "-"]))];
  },
};

async function show(name) {
  tabsEl.replaceChildren(...Object.keys(tabs).map((n) => el("button", { class: n === name ? "active" : "", onclick: () => show(n) }, n)));
  try {
    view.replaceChildren(...(await tabs[name]()));
  } catch (err) {
    view.replaceChildren(el("div", { class: "error" }, err.message, " (open the login URL printed by `sg serve` if your session expired)"));
  }
}

show("Secrets");
```

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg-admin --test web_assets`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(web): add embedded admin UI without dom injection sinks"
```

---

### Task 13: `sg serve`, `sg keygen` y ensamblado

**Files:**
- Create: `crates/sg/src/main.rs`, `crates/sg/src/serve.rs`, `crates/sg/src/keys.rs`
- Test: `crates/sg/tests/cli_e2e.rs`, tests unitarios en `keys.rs`

**Interfaces:**
- Consumes: todos los crates.
- Produces:
  - `sg serve [--data-dir] [--socket] [--proxy-bind] [--admin-bind] [--key-file|SG_KEY_FILE] [--passphrase] [--upstream-ca <pem>]` (variable `SG_MASTER_KEY` como tercera fuente)
  - `sg keygen [--out <fichero>]`
  - Subcomandos de cliente aplanados (`sg secret ...`, `sg --socket <ruta> ...`)
  - `keys::resolve_key(args: &KeySource, interactive_confirm: bool) -> anyhow::Result<KeyInput>`

- [ ] **Step 1: Escribir los tests que fallan**

`keys.rs` (módulo `tests`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn key_file_must_hold_32_bytes_base64_and_be_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.key");
        write_new_key_file(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let src = KeySource { key_file: Some(p.clone()), master_key: None, passphrase: false };
        assert!(matches!(resolve_key(&src, false).unwrap(), sg_core::KeyInput::Raw(_)));
        assert!(write_new_key_file(&p).is_err(), "must not overwrite an existing key");
    }

    #[test]
    fn master_key_env_value_is_decoded() {
        let src = KeySource { key_file: None, master_key: Some(STANDARD.encode([9u8; 32])), passphrase: false };
        assert!(matches!(resolve_key(&src, false).unwrap(), sg_core::KeyInput::Raw(_)));
    }

    #[test]
    fn no_key_source_is_an_error_and_two_sources_are_ambiguous() {
        let none = KeySource { key_file: None, master_key: None, passphrase: false };
        assert!(resolve_key(&none, false).is_err());
        let both = KeySource { key_file: Some("/x".into()), master_key: Some("y".into()), passphrase: false };
        assert!(resolve_key(&both, false).is_err());
    }
}
```

`tests/cli_e2e.rs`:
```rust
use assert_cmd::cargo::cargo_bin;
use std::{io::{BufRead, BufReader, Write}, process::{Command, Stdio}, time::Duration};

struct Server { child: std::process::Child, socket: std::path::PathBuf, proxy: String, login: String, dir: tempfile::TempDir }

impl Drop for Server { fn drop(&mut self) { let _ = self.child.kill(); } }

fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    assert!(Command::new(cargo_bin("sg")).args(["keygen", "--out", key.to_str().unwrap()]).status().unwrap().success());
    let socket = dir.path().join("sg.sock");
    let mut child = Command::new(cargo_bin("sg"))
        .args(["serve", "--data-dir", dir.path().to_str().unwrap(), "--socket", socket.to_str().unwrap(),
               "--key-file", key.to_str().unwrap(), "--proxy-bind", "127.0.0.1:0", "--admin-bind", "127.0.0.1:0"])
        .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let (mut proxy, mut login) = (String::new(), String::new());
    while proxy.is_empty() || login.is_empty() {
        let l = lines.next().expect("server exited early").unwrap();
        if let Some(r) = l.strip_prefix("proxy: ") { proxy = r.into(); }
        if let Some(r) = l.strip_prefix("admin: ") { login = r.into(); }
    }
    std::thread::sleep(Duration::from_millis(200));
    Server { child, socket, proxy, login, dir }
}

fn sg(s: &Server, args: &[&str], stdin: Option<&str>) -> (bool, String) {
    let mut cmd = Command::new(cargo_bin("sg"));
    cmd.arg("--socket").arg(&s.socket).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(i) = stdin { child.stdin.take().unwrap().write_all(i.as_bytes()).unwrap(); } else { drop(child.stdin.take()); }
    let out = child.wait_with_output().unwrap();
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn full_cli_flow_never_echoes_the_secret_and_db_stays_encrypted() {
    let s = start();
    assert!(s.login.contains("/login?t="));
    assert!(sg(&s, &["secret", "add", "gh"], Some("E2E-PLAINTEXT-MARKER\n")).0);
    assert!(sg(&s, &["role", "add", "reviewer", "--unmatched", "deny"], None).0);
    assert!(sg(&s, &["ca", "allow-domain", "github.com"], None).0);
    let (ok, out) = sg(&s, &["rule", "add", "--role", "reviewer", "--host", "api.github.com", "--methods", "GET",
                              "--header", "Authorization", "--template", "Bearer {secret}", "--secret", "gh"], None);
    assert!(ok, "{out}");
    let (ok, token_out) = sg(&s, &["token", "create", "--machine", "laptop", "--role", "reviewer"], None);
    assert!(ok && token_out.contains("HTTPS_PROXY=http://laptop:"), "{token_out}");
    let mut everything = token_out;
    for args in [vec!["secret", "ls"], vec!["role", "ls"], vec!["rule", "ls"], vec!["token", "ls"], vec!["ca", "status"], vec!["audit"]] {
        everything.push_str(&sg(&s, &args, None).1);
    }
    assert!(!everything.contains("E2E-PLAINTEXT-MARKER"));
    assert!(!sg(&s, &["secret", "add", "bad"], Some("x\r\ny\n")).0, "CRLF values must be refused");
    assert!(!sg(&s, &["secret", "rm", "gh"], None).0, "secret in use must be refused");
    for e in std::fs::read_dir(s.dir.path()).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("vault.db") {
            let bytes = std::fs::read(e.path()).unwrap();
            assert!(!bytes.windows(20).any(|w| w == b"E2E-PLAINTEXT-MARKER"), "{name} holds the secret in clear");
        }
    }
    assert!(s.proxy.starts_with("http://127.0.0.1:"));
}
```
- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `cargo test -p sg`
Expected: FAIL (no compila).

- [ ] **Step 3: Implementar**

`keys.rs`:
```rust
use anyhow::{bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use sg_core::{crypto, KeyInput};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::{Path, PathBuf}};

pub struct KeySource {
    pub key_file: Option<PathBuf>,
    pub master_key: Option<String>,
    pub passphrase: bool,
}

pub fn write_new_key_file(path: &Path) -> anyhow::Result<()> {
    let key = crypto::random_key();
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
        .with_context(|| format!("cannot create {} (it must not exist yet)", path.display()))?;
    f.write_all(STANDARD.encode(*key).as_bytes())?;
    Ok(())
}

pub fn resolve_key(src: &KeySource, confirm_passphrase: bool) -> anyhow::Result<KeyInput> {
    let chosen = [src.key_file.is_some(), src.master_key.is_some(), src.passphrase].iter().filter(|b| **b).count();
    match chosen {
        0 => bail!("no key source: use --key-file, SG_MASTER_KEY or --passphrase"),
        1 => {}
        _ => bail!("ambiguous key source: use exactly one of --key-file, SG_MASTER_KEY, --passphrase"),
    }
    if let Some(p) = &src.key_file {
        let text = std::fs::read_to_string(p).with_context(|| format!("cannot read key file {}", p.display()))?;
        return Ok(KeyInput::Raw(crypto::kek_from_base64(&text)?));
    }
    if let Some(v) = &src.master_key {
        return Ok(KeyInput::Raw(crypto::kek_from_base64(v)?));
    }
    let pw = rpassword::prompt_password("Vault passphrase: ")?;
    if confirm_passphrase && rpassword::prompt_password("Repeat passphrase: ")? != pw {
        bail!("passphrases do not match");
    }
    Ok(KeyInput::Passphrase(pw))
}
```

`serve.rs`:
```rust
use crate::keys::{resolve_key, KeySource};
use anyhow::Context;
use clap::Args;
use rustls::pki_types::CertificateDer;
use sg_admin::{allowed_hosts_for, serve_unix, serve_web, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{paths, Vault};
use sg_proxy::{ProxyState, UpstreamConfig};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::TcpListener;

#[derive(Args)]
pub struct ServeArgs {
    #[arg(long)] data_dir: Option<PathBuf>,
    #[arg(long, env = "SG_PROXY_BIND", default_value = "127.0.0.1:8080")] proxy_bind: SocketAddr,
    #[arg(long, env = "SG_ADMIN_BIND", default_value = "127.0.0.1:9090")] admin_bind: SocketAddr,
    #[arg(long, env = "SG_KEY_FILE")] key_file: Option<PathBuf>,
    #[arg(long, env = "SG_MASTER_KEY", hide_env_values = true)] master_key: Option<String>,
    #[arg(long)] passphrase: bool,
    /// Extra PEM CA bundle trusted for upstream TLS (internal services with a private CA)
    #[arg(long, env = "SG_UPSTREAM_CA")] upstream_ca: Vec<PathBuf>,
}

pub async fn run(args: ServeArgs, socket: PathBuf) -> anyhow::Result<()> {
    let data_dir = args.data_dir.unwrap_or_else(paths::default_data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let db = data_dir.join("vault.db");
    let first_run = !db.exists();
    let key = resolve_key(&KeySource { key_file: args.key_file, master_key: args.master_key, passphrase: args.passphrase }, first_run)?;
    let vault = Arc::new(Vault::open_or_init(&db, key).context("could not unlock the vault (wrong key?)")?);
    let tokens = Arc::new(TokenService::new(vault.clone())?);
    let ca = Arc::new(CaService::init_or_load(vault.clone())?);

    let mut roots: Vec<CertificateDer<'static>> = Vec::new();
    for p in &args.upstream_ca {
        let pem = std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?;
        for c in rustls_pemfile::certs(&mut pem.as_slice()) {
            roots.push(CertificateDer::from(c?.to_vec()));
        }
    }
    let proxy_state = Arc::new(ProxyState { vault: vault.clone(), verifier: tokens.clone(), ca: ca.clone(), upstream: UpstreamConfig::new(roots) });

    let proxy_listener = TcpListener::bind(args.proxy_bind).await.context("cannot bind the proxy address")?;
    let admin_listener = TcpListener::bind(args.admin_bind).await.context("cannot bind the admin address")?;
    let proxy_addr = proxy_listener.local_addr()?;
    let admin_addr = admin_listener.local_addr()?;
    if !admin_addr.ip().is_loopback() {
        eprintln!("WARNING: the admin interface is bound to {admin_addr}, which is not loopback. Publish it only to 127.0.0.1 of the host; there is no remote login in this version.");
    }

    let sessions = Arc::new(Sessions::new());
    let login = sessions.new_login_token();
    let app = AppState { vault, tokens, ca, sessions, allowed_hosts: allowed_hosts_for(admin_addr) };

    println!("proxy: http://{proxy_addr}");
    println!("admin: http://localhost:{}/login?t={login}", admin_addr.port());
    println!("socket: {}", socket.display());

    tokio::select! {
        r = sg_proxy::serve(proxy_listener, proxy_state) => r.context("proxy stopped")?,
        r = serve_web(admin_listener, app.clone()) => r.context("web admin stopped")?,
        r = serve_unix(&socket, app) => r.context("admin socket stopped")?,
        _ = shutdown() => {}
    }
    let _ = std::fs::remove_file(&socket);
    Ok(())
}

async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("sigterm handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
```

`main.rs`:
```rust
mod keys;
mod serve;

use clap::{Parser, Subcommand};
use sg_cli::ClientCommand;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sg", version, about = "Secret Guardian: a vault whose proxy injects credentials so agents never see them")]
struct Cli {
    /// Admin socket of a running `sg serve`
    #[arg(long, global = true, env = "SG_SOCKET")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the vault (proxy, admin socket and local web UI)
    Serve(serve::ServeArgs),
    /// Generate a random master key file (mode 0600)
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    #[command(flatten)]
    Client(ClientCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();
    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(sg_core::paths::default_socket);
    match cli.command {
        Command::Serve(args) => serve::run(args, socket).await,
        Command::Keygen { out } => {
            keys::write_new_key_file(&out)?;
            println!("wrote {} (keep it safe; without it the vault cannot be opened)", out.display());
            Ok(())
        }
        Command::Client(cmd) => sg_cli::run(&socket, cmd).await,
    }
}
```
- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `cargo test -p sg`
Expected: tests unitarios de `keys` y `cli_e2e` pasan.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(sg): add serve, keygen and CLI entrypoint"
```

---

### Task 14: Docker, script E2E y documentación

**Files:**
- Create: `Dockerfile`, `docker-compose.example.yml`, `.dockerignore`, `scripts/e2e.sh`, `README.md`

**Interfaces:**
- Consumes: el binario `sg` completo.
- Produces: imagen Docker no-root, ejemplo de compose con la administración publicada solo en `127.0.0.1` del host, y un E2E real con `curl`.

- [ ] **Step 1: Escribir el E2E que falla** (`scripts/e2e.sh`, `chmod +x`)

```bash
#!/usr/bin/env bash
# End-to-end: real curl through the proxy; developer can POST, reviewer cannot; the secret never reaches the agent.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q
SG="$PWD/target/debug/sg"
W="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$W"' EXIT
SECRET="E2E-SECRET-$RANDOM$RANDOM"
export SG_SOCKET="$W/sg.sock"

# 1. TLS upstream that logs the Authorization header it receives.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -keyout "$W/up.key" -out "$W/up.pem" 2>/dev/null
cat > "$W/up.py" <<'PY'
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        open(sys.argv[3], "a").write(f"{self.command} {self.path} auth={self.headers.get('Authorization')}\n")
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    do_GET = do_POST = _h
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[1], sys.argv[2])
s = http.server.HTTPServer(("127.0.0.1", 18443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
python3 "$W/up.py" "$W/up.pem" "$W/up.key" "$W/upstream.log" &

# 2. The vault.
"$SG" keygen --out "$W/k.key" >/dev/null
"$SG" serve --data-dir "$W" --key-file "$W/k.key" --proxy-bind 127.0.0.1:18080 --admin-bind 127.0.0.1:19090 \
  --upstream-ca "$W/up.pem" >"$W/serve.log" 2>&1 &
for _ in $(seq 50); do [ -S "$SG_SOCKET" ] && break; sleep 0.1; done

printf '%s' "$SECRET" | "$SG" secret add api-key
"$SG" role add developer --unmatched deny
"$SG" role add reviewer --unmatched deny
"$SG" ca allow-domain localhost
"$SG" rule add --role developer --host localhost --header Authorization --template 'Bearer {secret}' --secret api-key
"$SG" rule add --role reviewer  --host localhost --methods GET --header Authorization --template 'Bearer {secret}' --secret api-key
"$SG" ca export > "$W/ca.pem"
tok() { "$SG" token create --machine e2e --role "$1" | sed -n 's/^token (shown once): //p'; }
DEV="$(tok developer)"; REV="$(tok reviewer)"

req() { curl -s -o /dev/null -w '%{http_code}' --proxy "http://x:$1@127.0.0.1:18080" --cacert "$W/ca.pem" -X "$2" https://localhost:18443/thing; }

[ "$(req "$DEV" GET)"  = 200 ] || { echo "FAIL: developer GET"; exit 1; }
[ "$(req "$DEV" POST)" = 200 ] || { echo "FAIL: developer POST"; exit 1; }
[ "$(req "$REV" GET)"  = 200 ] || { echo "FAIL: reviewer GET"; exit 1; }
[ "$(req "$REV" POST)" = 403 ] || { echo "FAIL: reviewer POST must be 403"; exit 1; }
[ "$(req bad GET)"     = 407 ] || { echo "FAIL: bad token must be 407"; exit 1; }
grep -q "auth=Bearer $SECRET" "$W/upstream.log" || { echo "FAIL: secret was not injected"; exit 1; }
[ "$(grep -c 'POST' "$W/upstream.log")" = 1 ] || { echo "FAIL: reviewer POST reached upstream"; exit 1; }
if grep -rqa "$SECRET" "$W"/vault.db*; then echo "FAIL: plaintext secret in the database"; exit 1; fi
if grep -q "$SECRET" "$W/serve.log"; then echo "FAIL: secret in server logs"; exit 1; fi
echo "E2E OK"
```

- [ ] **Step 2: Ejecutar y ver el fallo**

Run: `scripts/e2e.sh`
Expected: debe pasar o fallar con un mensaje `FAIL: ...` concreto; corregir el código (no el script) si revela un defecto real. Si falla por entorno (falta `openssl`, `curl` o `python3`), instalarlos.

- [ ] **Step 3: Implementar el empaquetado**

`Dockerfile`:
```dockerfile
FROM rust:1-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p sg

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data sg && mkdir /data && chown sg /data
COPY --from=build /src/target/release/sg /usr/local/bin/sg
USER sg
VOLUME /data
EXPOSE 8080 9090
ENTRYPOINT ["sg"]
CMD ["serve", "--data-dir", "/data", "--socket", "/data/sg.sock", "--key-file", "/run/secrets/sg_key", \
     "--proxy-bind", "0.0.0.0:8080", "--admin-bind", "0.0.0.0:9090"]
```

`docker-compose.example.yml`:
```yaml
services:
  secret-guardian:
    build: .
    restart: unless-stopped
    ports:
      - "127.0.0.1:9090:9090"   # admin UI: host loopback only, there is no remote login
      # The proxy port is reached by agent containers over the compose network; publish it only if you need to.
    volumes:
      - sg-data:/data
    secrets:
      - sg_key
volumes:
  sg-data:
secrets:
  sg_key:
    file: ./sg.key   # create with: sg keygen --out sg.key
```
(La CLI dentro del contenedor usa el socket: `docker compose exec secret-guardian sg --socket /data/sg.sock secret ls`.)

`.dockerignore`:
```
target
.git
*.key
*.db*
```

`README.md`: secciones **Qué es**, **Instalación** (binario y Docker), **Primeros pasos** (los comandos del E2E en orden), **Configurar un agente** (`HTTPS_PROXY` y variables de CA por proceso), **Modelo de seguridad y límites** (copiar el modelo de amenaza y las limitaciones 6.5 de la spec), **Fases futuras**. Enlazar a `docs/specs/2026-10-16-secret-guardian-vault.md`.

- [ ] **Step 4: Ejecutar y ver que pasa**

Run: `scripts/e2e.sh && docker build -t secret-guardian:dev .`
Expected: `E2E OK` y la imagen se construye.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: add docker packaging, e2e script and readme"
```

---

## Cobertura de la spec

| Spec | Tarea |
|---|---|
| 1 Criterios 1-2 (inyección, reviewer vs developer) | 8, 14 |
| 1 Criterio 3 (nunca devolver valores) | 2, 10, 13 |
| 1 Criterio 4 (DB sin clave no revela secretos) | 2, 13, 14 |
| 1 Criterios 5-6 (binario, Docker, CLI y web) | 11-14 |
| 2 Modelo de amenaza | 2, 5, 8, 9, 10, 12 |
| 3 Arquitectura y crates | 0-13 |
| 4 Almacenamiento y cifrado | 1, 2 |
| 5 Autenticación de agentes | 4, 7 |
| 6.1-6.2 Flujo y reglas | 3, 8 |
| 6.3 CA acotada | 5 |
| 6.4 Hosts sin regla | 7, 9 |
| 6.5 Limitaciones | 9, 14 (README) |
| 7.1-7.2 API y seguridad web | 10 |
| 7.3 CLI | 11, 13 |
| 7.4 Web | 12 |
| 8 Errores y observabilidad | 7, 8, 14 |
| 9 Pruebas | todas; E2E en 14 |

**Fuera de este plan (a propósito):** verificación completa, revisión y decisión de integración corren en `/ship`. Las fases 2-5 de la spec tendrán su propio ciclo.
