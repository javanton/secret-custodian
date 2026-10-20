use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sg_core::{now, CoreError, Vault};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

const ISS: &str = "secret-custodian";
const KEY_AAD: &[u8] = b"sg:token-signing-key";
const HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

/// Why a token was refused.
///
/// `Expired` and `Revoked` carry the identity read from the claims of a token whose signature and
/// issuer WERE verified: it exists only so the refusal can be audited. It is never a session; the
/// caller must not treat it as an authenticated identity. `Invalid` covers everything else
/// (malformed, wrong signature or issuer, unknown jti) and carries nothing.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid token")]
    Invalid,
    #[error("token expired")]
    Expired(Identity),
    #[error("token revoked")]
    Revoked(Identity),
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
        // Each connection guard below is a temporary dropped at the end of its statement, so it
        // is never held while calling `open_value`/`seal_value`.
        let read = |vault: &Vault| -> Result<Option<Vec<u8>>, AuthError> {
            Ok(vault
                .conn()
                .query_row(
                    "SELECT value FROM meta WHERE key = 'token_signing_key'",
                    [],
                    |r| r.get(0),
                )
                .optional()?)
        };
        let blob = match read(&vault)? {
            Some(blob) => blob,
            None => {
                let seed = sg_core::crypto::random_key();
                let sealed = vault.seal_value(KEY_AAD, &*seed);
                // Racing creators converge: the first insert wins, everyone re-reads the stored key.
                vault.conn().execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('token_signing_key', ?1)",
                    [sealed],
                )?;
                read(&vault)?.ok_or(AuthError::Core(CoreError::Crypto))?
            }
        };
        let raw = vault.open_value(KEY_AAD, &blob)?;
        // A decrypted blob that is not exactly 32 bytes means a corrupt key record.
        let seed =
            Zeroizing::new(<[u8; 32]>::try_from(raw.as_slice()).map_err(|_| CoreError::Crypto)?);
        let key = SigningKey::from_bytes(&seed);
        Ok(Self { vault, key })
    }

    pub fn issue(
        &self,
        machine: &str,
        role: &str,
        ttl: Option<Duration>,
    ) -> Result<IssuedToken, AuthError> {
        let iat = now();
        let exp = ttl
            .map(|t| {
                i64::try_from(t.as_secs())
                    .ok()
                    .and_then(|s| iat.checked_add(s))
                    .ok_or(AuthError::InvalidTtl)
            })
            .transpose()?;
        let claims = Claims {
            iss: ISS.into(),
            jti: uuid::Uuid::new_v4().to_string(),
            sub: machine.into(),
            role: role.into(),
            iat,
            exp,
        };
        let signing_input = format!(
            "{}.{}",
            B64.encode(HEADER),
            B64.encode(serde_json::to_vec(&claims).expect("claims serialize"))
        );
        let sig = self.key.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", B64.encode(sig.to_bytes()));
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
        self.vault.conn().execute(
            "INSERT INTO tokens (jti, machine, role, created_at, expires_at, token_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![claims.jti, machine, role, iat, claims.exp, token_hash],
        )?;
        Ok(IssuedToken {
            token,
            jti: claims.jti,
        })
    }

    pub fn revoke(&self, jti: &str) -> Result<(), AuthError> {
        let n = self.vault.conn().execute(
            "UPDATE tokens SET revoked_at = ?1 WHERE jti = ?2 AND revoked_at IS NULL",
            params![now(), jti],
        )?;
        if n == 0 {
            Err(AuthError::Core(CoreError::NotFound))
        } else {
            Ok(())
        }
    }

    pub fn revoke_machine(&self, machine: &str) -> Result<usize, AuthError> {
        Ok(self.vault.conn().execute(
            "UPDATE tokens SET revoked_at = ?1 WHERE machine = ?2 AND revoked_at IS NULL",
            params![now(), machine],
        )?)
    }

    pub fn list(&self) -> Result<Vec<TokenMeta>, AuthError> {
        let conn = self.vault.conn();
        let mut st = conn.prepare(
            "SELECT jti, machine, role, created_at, expires_at, revoked_at FROM tokens ORDER BY created_at DESC",
        )?;
        let rows = st
            .query_map([], |r| {
                Ok(TokenMeta {
                    jti: r.get(0)?,
                    machine: r.get(1)?,
                    role: r.get(2)?,
                    created_at: r.get(3)?,
                    expires_at: r.get(4)?,
                    revoked_at: r.get(5)?,
                })
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
        // Only the exact header we emit is accepted: rejects alg=none and any other algorithm.
        if B64.decode(h).map_err(|_| AuthError::Invalid)? != HEADER.as_bytes() {
            return Err(AuthError::Invalid);
        }
        let sig_bytes: [u8; 64] = B64
            .decode(s)
            .map_err(|_| AuthError::Invalid)?
            .try_into()
            .map_err(|_| AuthError::Invalid)?;
        // Signature is verified before the claims are parsed.
        let vk: VerifyingKey = self.key.verifying_key();
        vk.verify_strict(
            format!("{h}.{p}").as_bytes(),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| AuthError::Invalid)?;
        let claims: Claims =
            serde_json::from_slice(&B64.decode(p).map_err(|_| AuthError::Invalid)?)
                .map_err(|_| AuthError::Invalid)?;
        if claims.iss != ISS {
            return Err(AuthError::Invalid);
        }
        let identity = Identity {
            jti: claims.jti,
            machine: claims.sub,
            role: claims.role,
        };
        if claims.exp.map(|e| now() >= e).unwrap_or(false) {
            return Err(AuthError::Expired(identity));
        }
        let revoked: Option<Option<i64>> = self
            .vault
            .conn()
            .query_row(
                "SELECT revoked_at FROM tokens WHERE jti = ?1",
                [&identity.jti],
                |r| r.get(0),
            )
            .optional()?;
        match revoked {
            None => Err(AuthError::Invalid),
            Some(Some(_)) => Err(AuthError::Revoked(identity)),
            Some(None) => Ok(identity),
        }
    }
}
