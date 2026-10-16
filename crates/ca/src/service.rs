use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints,
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
const DEFAULT_LEAF_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);

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
    cache_ttl: Mutex<Duration>,
}

fn ca_params(domains: &[String]) -> Result<CertificateParams, CaError> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Secret Guardian CA");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let names: Vec<String> = if domains.is_empty() {
        vec![PLACEHOLDER_TLD.into()]
    } else {
        domains.to_vec()
    };
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: names.into_iter().map(GeneralSubtree::DnsName).collect(),
        excluded_subtrees: vec![],
    });
    p.not_before = OffsetDateTime::now_utc() - TDuration::days(1);
    p.not_after = OffsetDateTime::now_utc() + TDuration::days(3650);
    Ok(p)
}

fn validate_domain(d: &str) -> Result<(), CaError> {
    let ok_chars = d
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    if d.is_empty() || !ok_chars || d.starts_with('.') || d.ends_with('.') || d.contains("..") {
        return Err(CaError::DomainRejected(
            "use a plain lowercase domain such as github.com",
        ));
    }
    if d.parse::<std::net::IpAddr>().is_ok() {
        return Err(CaError::DomainRejected("IP addresses are not supported"));
    }
    if d == PLACEHOLDER_TLD || d.ends_with(".invalid") {
        return Err(CaError::DomainRejected("reserved"));
    }
    if d != "localhost" && !d.contains('.') {
        return Err(CaError::DomainRejected(
            "too broad: single-label domains are not allowed",
        ));
    }
    Ok(())
}

impl CaService {
    pub fn init_or_load(vault: Arc<Vault>) -> Result<Self, CaError> {
        let row: Option<(String, Vec<u8>, String)> = {
            use rusqlite::OptionalExtension;
            vault
                .conn()
                .query_row(
                    "SELECT cert_pem, key_enc, domains FROM ca WHERE id = 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?
        };
        match row {
            Some((cert_pem, key_enc, domains)) => {
                let key_pem = vault.open_value(KEY_AAD, &key_enc)?;
                let key =
                    KeyPair::from_pem(std::str::from_utf8(&key_pem).map_err(tls)?).map_err(tls)?;
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
                Ok(Self::build(
                    vault,
                    key,
                    State {
                        cert_pem: cert.pem(),
                        domains: vec![],
                    },
                ))
            }
        }
    }

    fn build(vault: Arc<Vault>, key: KeyPair, state: State) -> Self {
        Self {
            vault,
            key,
            state: Mutex::new(state),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Mutex::new(DEFAULT_LEAF_CACHE_TTL),
        }
    }

    /// Overrides how long issued leaf configs stay cached (default 12 h). Mainly for tests.
    pub fn set_leaf_cache_ttl(&self, ttl: Duration) {
        *self.cache_ttl.lock().unwrap() = ttl;
    }

    pub fn cert_pem(&self) -> String {
        self.state.lock().unwrap().cert_pem.clone()
    }

    pub fn domains(&self) -> Vec<String> {
        self.state.lock().unwrap().domains.clone()
    }

    /// Re-issues the CA certificate with the same key and a wider permitted set. Agents must reload the certificate.
    pub fn allow_domain(&self, domain: &str) -> Result<(), CaError> {
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
        *st = State {
            cert_pem: cert.pem(),
            domains,
        };
        self.cache.lock().unwrap().clear();
        Ok(())
    }

    pub fn is_host_permitted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.state
            .lock()
            .unwrap()
            .domains
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
    }

    pub fn server_config_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, CaError> {
        let host = host.to_ascii_lowercase();
        if !self.is_host_permitted(&host) {
            return Err(CaError::NotPermitted);
        }
        // Read the state before taking the cache lock (allow_domain locks state, then cache).
        let domains = self.domains();
        let ttl = *self.cache_ttl.lock().unwrap();
        // The cache lock is held while issuing so concurrent callers for one host share a single leaf.
        let mut cache = self.cache.lock().unwrap();
        if let Some((at, cfg)) = cache.get(&host) {
            if at.elapsed() < ttl {
                return Ok(cfg.clone());
            }
        }
        let ca_cert = ca_params(&domains)?.self_signed(&self.key).map_err(tls)?;
        let leaf_key = KeyPair::generate().map_err(tls)?;
        let mut params = CertificateParams::new(vec![host.clone()]).map_err(tls)?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - TDuration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + TDuration::hours(24);
        let leaf = params
            .signed_by(&leaf_key, &ca_cert, &self.key)
            .map_err(tls)?;
        let der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(tls)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], der)
            .map_err(tls)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        cache.insert(host, (Instant::now(), cfg.clone()));
        Ok(cfg)
    }
}
