use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose,
    NameConstraints, SerialNumber,
};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sg_core::{crypto, CoreError, Vault};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};
use time::{Duration as TDuration, OffsetDateTime};

const KEY_AAD: &[u8] = b"sg:ca-key";
const PLACEHOLDER_TLD: &str = "invalid";
const DEFAULT_LEAF_CACHE_TTL: Duration = Duration::from_secs(12 * 3600);
const MAX_LEAF_CACHE_TTL: Duration = Duration::from_secs(20 * 3600);
const MAX_LEAF_CACHE_ENTRIES: usize = 1024;
const MAX_DNS_NAME_LEN: usize = 253;

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
    /// The CA certificate object used as issuer for leaves; built once per load / `allow_domain`.
    signer: Arc<rcgen::Certificate>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct CaService {
    vault: Arc<Vault>,
    key: KeyPair,
    state: Mutex<State>,
    cache: Mutex<HashMap<String, (Instant, Arc<rustls::ServerConfig>)>>,
    cache_ttl: Mutex<Duration>,
    ca_cert_builds: AtomicUsize,
}

fn ca_params(domains: &[String]) -> Result<CertificateParams, CaError> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Secret Guardian CA");
    p.distinguished_name = dn;
    // Random positive 16-byte serial, stored only inside the certificate: re-issued CA certificates
    // (same key, same subject) must not share issuer+serial.
    let mut serial: [u8; 16] = crypto::random_bytes();
    serial[0] &= 0x7f;
    p.serial_number = Some(SerialNumber::from_slice(&serial));
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    // SKI is derived from the (stable) CA key; leaves reference it through their AKI.
    p.key_identifier_method = KeyIdMethod::Sha256;
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let names: Vec<String> = if domains.is_empty() {
        vec![PLACEHOLDER_TLD.into()]
    } else {
        domains.to_vec()
    };
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: names.into_iter().map(GeneralSubtree::DnsName).collect(),
        // DNS constraints do not restrict IP SANs, so exclude every IP address explicitly.
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
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
    // Same DNS rules as rustls-webpki, so a name we accept can never invalidate the whole CA.
    if d.len() > MAX_DNS_NAME_LEN {
        return Err(CaError::DomainRejected("name longer than 253 characters"));
    }
    if d.split('.')
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return Err(CaError::DomainRejected("invalid DNS label"));
    }
    if d.rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(CaError::DomainRejected("last label must not be all digits"));
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
                let signer = Arc::new(ca_params(&domains)?.self_signed(&key).map_err(tls)?);
                Ok(Self::build(
                    vault,
                    key,
                    State {
                        cert_pem,
                        domains,
                        signer,
                    },
                ))
            }
            None => {
                let key = KeyPair::generate().map_err(tls)?;
                let cert = ca_params(&[])?.self_signed(&key).map_err(tls)?;
                let key_enc = vault.seal_value(KEY_AAD, key.serialize_pem().as_bytes());
                vault.conn().execute(
                    "INSERT INTO ca (id, cert_pem, key_enc, domains) VALUES (1, ?1, ?2, '[]')",
                    rusqlite::params![cert.pem(), key_enc],
                )?;
                let cert_pem = cert.pem();
                Ok(Self::build(
                    vault,
                    key,
                    State {
                        cert_pem,
                        domains: vec![],
                        signer: Arc::new(cert),
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
            // the certificate in `state` was built by the caller
            ca_cert_builds: AtomicUsize::new(1),
        }
    }

    /// Overrides how long issued leaf configs stay cached (default 12 h, clamped to 20 h). For tests.
    #[doc(hidden)]
    pub fn set_leaf_cache_ttl(&self, ttl: Duration) {
        *lock(&self.cache_ttl) = ttl.min(MAX_LEAF_CACHE_TTL);
    }

    #[doc(hidden)]
    pub fn leaf_cache_len(&self) -> usize {
        lock(&self.cache).len()
    }

    /// How many times the signing CA certificate object has been built (test hook).
    #[doc(hidden)]
    pub fn ca_cert_builds(&self) -> usize {
        self.ca_cert_builds.load(Ordering::SeqCst)
    }

    pub fn cert_pem(&self) -> String {
        lock(&self.state).cert_pem.clone()
    }

    pub fn domains(&self) -> Vec<String> {
        lock(&self.state).domains.clone()
    }

    /// Re-issues the CA certificate with the same key and a wider permitted set. Agents must reload the certificate.
    ///
    /// The input is trimmed and lowercased first. There is deliberately no Public Suffix List
    /// dependency: multi-label public suffixes such as `co.uk`, `github.io`, `amazonaws.com` or
    /// `com.au` are accepted, so the operator is responsible for not allowing them.
    ///
    /// Before anything is persisted, a throw-away leaf for the new domain and for every already
    /// allowed domain is verified against the new certificate; if any fails the call is rejected.
    pub fn allow_domain(&self, domain: &str) -> Result<(), CaError> {
        let domain = domain.trim().to_ascii_lowercase();
        validate_domain(&domain)?;
        let mut st = lock(&self.state);
        if st.domains.contains(&domain) {
            return Ok(());
        }
        let mut domains = st.domains.clone();
        domains.push(domain);
        domains.sort();
        let cert = ca_params(&domains)?.self_signed(&self.key).map_err(tls)?;
        self.ca_cert_builds.fetch_add(1, Ordering::SeqCst);
        self.probe(&cert, &domains)?;
        self.vault.conn().execute(
            "UPDATE ca SET cert_pem = ?1, domains = ?2 WHERE id = 1",
            rusqlite::params![cert.pem(), serde_json::to_string(&domains).map_err(tls)?],
        )?;
        *st = State {
            cert_pem: cert.pem(),
            domains,
            signer: Arc::new(cert),
        };
        lock(&self.cache).clear();
        Ok(())
    }

    /// Verifies a throw-away leaf for every domain against `cert` as the only trust anchor.
    fn probe(&self, cert: &rcgen::Certificate, domains: &[String]) -> Result<(), CaError> {
        const REJECT: CaError = CaError::DomainRejected("would invalidate the CA name constraints");
        let mut store = rustls::RootCertStore::empty();
        store.add(cert.der().clone()).map_err(|_| REJECT)?;
        let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(store),
            crypto_provider(),
        )
        .build()
        .map_err(|_| REJECT)?;
        for d in domains {
            let name = format!("probe.{d}");
            let name = if name.len() > MAX_DNS_NAME_LEN {
                d.clone()
            } else {
                name
            };
            let leaf = self
                .issue_leaf(&name, cert, &KeyPair::generate().map_err(tls)?)?
                .der()
                .clone();
            let sni = ServerName::try_from(name).map_err(|_| REJECT)?;
            verifier
                .verify_server_cert(&leaf, &[], &sni, &[], UnixTime::now())
                .map_err(|_| REJECT)?;
        }
        Ok(())
    }

    fn issue_leaf(
        &self,
        host: &str,
        signer: &rcgen::Certificate,
        leaf_key: &KeyPair,
    ) -> Result<rcgen::Certificate, CaError> {
        let mut params = CertificateParams::new(vec![host.to_string()]).map_err(tls)?;
        // Strict verifiers (OpenSSL X509_STRICT, Python 3.13+) require an Authority Key Identifier
        // equal to the CA's SKI; both are derived from the CA key, so they survive re-issuing.
        params.use_authority_key_identifier_extension = true;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = OffsetDateTime::now_utc() - TDuration::hours(1);
        params.not_after = OffsetDateTime::now_utc() + TDuration::hours(24);
        params.signed_by(leaf_key, signer, &self.key).map_err(tls)
    }

    /// Issues a fresh leaf for a permitted host and returns `(certificate PEM, private key PEM)`.
    /// For tests only; it goes through the same host check as `server_config_for`.
    #[doc(hidden)]
    pub fn issue_leaf_pem_for_test(&self, host: &str) -> Result<(String, String), CaError> {
        let host = host.to_ascii_lowercase();
        if !self.is_host_permitted(&host) {
            return Err(CaError::NotPermitted);
        }
        let signer = lock(&self.state).signer.clone();
        let leaf_key = KeyPair::generate().map_err(tls)?;
        let leaf = self.issue_leaf(&host, &signer, &leaf_key)?;
        Ok((leaf.pem(), leaf_key.serialize_pem()))
    }

    pub fn is_host_permitted(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        lock(&self.state)
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
        let signer = lock(&self.state).signer.clone();
        let ttl = *lock(&self.cache_ttl);
        // The cache lock is held while issuing so concurrent callers for one host share a single leaf.
        let mut cache = lock(&self.cache);
        if let Some((at, cfg)) = cache.get(&host) {
            if at.elapsed() < ttl {
                return Ok(cfg.clone());
            }
        }
        let leaf_key = KeyPair::generate().map_err(tls)?;
        let leaf_der = self.issue_leaf(&host, &signer, &leaf_key)?.der().clone();
        let der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(tls)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], der)
            .map_err(tls)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        if cache.len() >= MAX_LEAF_CACHE_ENTRIES && !cache.contains_key(&host) {
            cache.retain(|_, (at, _)| at.elapsed() < ttl);
            if cache.len() >= MAX_LEAF_CACHE_ENTRIES {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
        }
        cache.insert(host, (Instant::now(), cfg.clone()));
        Ok(cfg)
    }
}
