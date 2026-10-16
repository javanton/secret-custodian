use crate::error::CoreError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
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

pub fn kek_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<Key32, CoreError> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|_| CoreError::Crypto)?;
    Ok(out)
}

pub fn kek_from_base64(s: &str) -> Result<Key32, CoreError> {
    let bytes = Zeroizing::new(
        STANDARD
            .decode(s.trim())
            .map_err(|_| CoreError::InvalidKey)?,
    );
    let arr: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidKey)?;
    Ok(Zeroizing::new(arr))
}

pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
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
