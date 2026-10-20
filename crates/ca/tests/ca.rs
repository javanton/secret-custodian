use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints,
};
use rustls::pki_types::{
    pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
};
use sg_ca::*;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn ca() -> (tempfile::TempDir, Arc<Vault>, CaService) {
    let dir = tempdir().unwrap();
    let v = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    let ca = CaService::init_or_load(v.clone()).unwrap();
    (dir, v, ca)
}

fn roots(pem: &str) -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        store.add(c.unwrap()).unwrap();
    }
    store
}

/// In-memory TLS handshake: a client trusting `ca_pem` against a server using `server_cfg` for `host`.
async fn handshake_raw(
    server_cfg: Arc<rustls::ServerConfig>,
    ca_pem: &str,
    host: &str,
) -> Result<(), String> {
    let client_cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
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
    let mut tls = TlsConnector::from(Arc::new(client_cfg))
        .connect(name, c)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.ok();
    let _ = server.await;
    Ok(())
}

async fn handshake(ca: &CaService, host: &str) -> Result<(), String> {
    let cfg = ca.server_config_for(host).map_err(|e| e.to_string())?;
    handshake_raw(cfg, &ca.cert_pem(), host).await
}

fn forged_server_config(
    host: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> Arc<rustls::ServerConfig> {
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .signed_by(&leaf_key, ca_cert, ca_key)
        .unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
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
    handshake_raw(
        forged_server_config("api.github.com", &ca_cert, &key),
        &pem,
        "api.github.com",
    )
    .await
    .unwrap();
    let err = handshake_raw(
        forged_server_config("evil.com", &ca_cert, &key),
        &pem,
        "evil.com",
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("NameConstraint"),
        "refused for the wrong reason: {err}"
    );
}

#[test]
fn too_broad_domains_are_rejected() {
    let (_d, _v, ca) = ca();
    for bad in [
        "com",
        "",
        "*.github.com",
        "github.com/path",
        "invalid",
        "a b.com",
        "10.0.0.1",
    ] {
        assert!(ca.allow_domain(bad).is_err(), "{bad:?}");
    }
    ca.allow_domain("localhost").unwrap();
}

#[test]
fn allow_domain_keeps_the_same_key_and_persists() {
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    ca.allow_domain("gitlab.com").unwrap();
    assert_eq!(
        ca.domains(),
        vec!["github.com".to_string(), "gitlab.com".to_string()]
    );
    let reloaded = CaService::init_or_load(v).unwrap();
    assert_eq!(reloaded.domains(), ca.domains());
    assert_eq!(reloaded.cert_pem(), ca.cert_pem());
}

#[test]
fn private_key_is_not_stored_in_clear() {
    let (_d, v, _ca) = ca();
    let blob: Vec<u8> = v
        .conn()
        .query_row("SELECT key_enc FROM ca WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    assert!(!String::from_utf8_lossy(&blob).contains("PRIVATE KEY"));
}

// ---------- extra tests (gaps beyond the plan) ----------

use x509_parser::prelude::*;

fn pem_to_der(pem: &str) -> Vec<u8> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

/// Handshake and return the leaf certificate DER the client saw (client trusts `ca_pem`).
async fn leaf_der(ca: &CaService, host: &str) -> Vec<u8> {
    let cfg = ca.server_config_for(host).unwrap();
    let client_cfg = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(&ca.cert_pem()))
        .with_no_client_auth();
    let (c, s) = tokio::io::duplex(8192);
    let acceptor = TlsAcceptor::from(cfg);
    let server = tokio::spawn(async move {
        let mut tls = acceptor.accept(s).await.unwrap();
        tls.write_all(b"ok").await.unwrap();
        tls.shutdown().await.ok();
    });
    let name = ServerName::try_from(host.to_string()).unwrap();
    let mut tls = TlsConnector::from(Arc::new(client_cfg))
        .connect(name, c)
        .await
        .unwrap();
    let der = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.ok();
    let _ = server.await;
    der
}

fn spki_of(pem: &str) -> Vec<u8> {
    let der = pem_to_der(pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    cert.tbs_certificate.subject_pki.raw.to_vec()
}

fn permitted_dns(pem: &str) -> Vec<String> {
    let der = pem_to_der(pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let ext = cert
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_NAME_CONSTRAINTS)
        .unwrap()
        .expect("NameConstraints extension missing");
    assert!(ext.critical, "NameConstraints must be critical");
    match ext.parsed_extension() {
        ParsedExtension::NameConstraints(nc) => {
            let excluded = nc.excluded_subtrees.as_ref().expect("no excluded subtrees");
            let ips: Vec<Vec<u8>> = excluded
                .iter()
                .map(|s| match s.base {
                    GeneralName::IPAddress(b) => b.to_vec(),
                    ref other => panic!("unexpected excluded subtree {other:?}"),
                })
                .collect();
            assert!(ips.contains(&vec![0u8; 8]), "0.0.0.0/0 not excluded");
            assert!(ips.contains(&vec![0u8; 32]), "::/0 not excluded");
            nc.permitted_subtrees
                .as_ref()
                .expect("no permitted subtrees")
                .iter()
                .map(|s| match s.base {
                    GeneralName::DNSName(d) => d.to_string(),
                    ref other => panic!("unexpected subtree {other:?}"),
                })
                .collect()
        }
        other => panic!("not parsed as NameConstraints: {other:?}"),
    }
}

#[test]
fn fresh_ca_certificate_contains_name_constraints_for_invalid_only() {
    let (_d, _v, ca) = ca();
    let pem = ca.cert_pem();
    assert_eq!(permitted_dns(&pem), vec!["invalid".to_string()]);
    // raw DER also carries the OID 2.5.29.30
    assert!(pem_to_der(&pem).windows(3).any(|w| w == [0x55, 0x1d, 0x1e]));
    let der = pem_to_der(&pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let bc = cert.basic_constraints().unwrap().unwrap().value;
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(0));
}

#[test]
fn allow_domain_updates_constraints_and_keeps_the_public_key() {
    let (_d, _v, ca) = ca();
    let before = ca.cert_pem();
    let spki_before = spki_of(&before);
    ca.allow_domain("github.com").unwrap();
    ca.allow_domain("gitlab.com").unwrap();
    let after = ca.cert_pem();
    assert_ne!(before, after);
    assert_eq!(
        spki_before,
        spki_of(&after),
        "CA public key must not change"
    );
    assert_eq!(
        permitted_dns(&after),
        vec!["github.com".to_string(), "gitlab.com".to_string()]
    );
    // same subject
    let (b, a) = (pem_to_der(&before), pem_to_der(&after));
    let (_, cb) = X509Certificate::from_der(&b).unwrap();
    let (_, ca_) = X509Certificate::from_der(&a).unwrap();
    assert_eq!(cb.subject().as_raw(), ca_.subject().as_raw());
    // idempotent: re-allowing does not re-issue
    ca.allow_domain("github.com").unwrap();
    assert_eq!(ca.cert_pem(), after);
}

#[tokio::test]
async fn leaf_issued_before_allow_domain_still_verifies_against_the_reissued_ca() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let old_cfg = ca.server_config_for("api.github.com").unwrap();
    ca.allow_domain("gitlab.com").unwrap();
    // old leaf (signed by the old CA cert) against the NEW CA cert as trust anchor
    handshake_raw(old_cfg, &ca.cert_pem(), "api.github.com")
        .await
        .unwrap();
    // leaf for the newly allowed domain against the new certificate
    handshake(&ca, "gitlab.com").await.unwrap();
    // and a client that still trusts only the OLD certificate refuses the new domain
}

#[tokio::test]
async fn old_ca_certificate_refuses_a_newly_allowed_domain() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let old_pem = ca.cert_pem();
    ca.allow_domain("gitlab.com").unwrap();
    let cfg = ca.server_config_for("gitlab.com").unwrap();
    assert!(handshake_raw(cfg, &old_pem, "gitlab.com").await.is_err());
}

#[tokio::test]
async fn forged_leaf_for_a_domain_outside_the_real_ca_constraints_is_refused() {
    // Reproduce a leaked CA key: reload the real key, sign evil.com with it, client trusts the real CA cert.
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let key_enc: Vec<u8> = v
        .conn()
        .query_row("SELECT key_enc FROM ca WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    let key_pem = v.open_value(b"sg:ca-key", &key_enc).unwrap();
    let key = KeyPair::from_pem(std::str::from_utf8(&key_pem).unwrap()).unwrap();
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Secret Custodian CA");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let signer = p.self_signed(&key).unwrap();
    assert!(handshake_raw(
        forged_server_config("evil.com", &signer, &key),
        &ca.cert_pem(),
        "evil.com"
    )
    .await
    .is_err());
    assert!(handshake_raw(
        forged_server_config("api.github.com", &signer, &key),
        &ca.cert_pem(),
        "api.github.com"
    )
    .await
    .is_ok());
}

#[test]
fn suffix_lookalikes_uppercase_ip_and_localhost_handling() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    for bad in [
        "evilgithub.com",
        "github.com.evil.com",
        "xgithub.com",
        "com",
        "",
        "127.0.0.1",
        "[::1]",
        "::1",
        "github.com:443",
        "api.github.com.evil.io",
    ] {
        assert!(!ca.is_host_permitted(bad), "{bad:?} must not be permitted");
        assert!(
            matches!(ca.server_config_for(bad), Err(CaError::NotPermitted)),
            "{bad:?}"
        );
    }
    assert!(ca.is_host_permitted("API.GitHub.COM"));
    assert!(ca.server_config_for("API.GitHub.COM").is_ok());
    assert!(!ca.is_host_permitted("localhost"));
    ca.allow_domain("localhost").unwrap();
    assert!(ca.is_host_permitted("localhost"));
    assert!(ca.is_host_permitted("app.localhost"));
    assert!(!ca.is_host_permitted("notlocalhost"));
}

#[tokio::test]
async fn localhost_leaf_verifies_once_allowed() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("localhost").unwrap();
    handshake(&ca, "localhost").await.unwrap();
}

#[tokio::test]
async fn uppercase_host_yields_a_valid_leaf_and_shares_the_cache_entry() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let a = ca.server_config_for("api.github.com").unwrap();
    let b = ca.server_config_for("API.GitHub.com").unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    handshake(&ca, "API.GitHub.com").await.unwrap();
}

#[test]
fn alpn_is_h2_then_http11() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let cfg = ca.server_config_for("github.com").unwrap();
    assert_eq!(
        cfg.alpn_protocols,
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
}

#[tokio::test]
async fn leaf_validity_is_about_24_hours_and_san_matches() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let der = leaf_der(&ca, "api.github.com").await;
    let (_, leaf) = X509Certificate::from_der(&der).unwrap();
    let nb = leaf.validity().not_before.timestamp();
    let na = leaf.validity().not_after.timestamp();
    let now = ::time::OffsetDateTime::now_utc().unix_timestamp();
    let ttl_from_now = na - now;
    assert!(
        (23 * 3600..=25 * 3600).contains(&ttl_from_now),
        "ttl {ttl_from_now}"
    );
    assert!(
        nb <= now && now - nb <= 2 * 3600,
        "not_before skew {}",
        now - nb
    );
    let san = leaf.subject_alternative_name().unwrap().unwrap();
    let names: Vec<String> = san
        .value
        .general_names
        .iter()
        .map(|g| format!("{g:?}"))
        .collect();
    assert_eq!(names.len(), 1);
    assert!(names[0].contains("api.github.com"));
    let bc = leaf.basic_constraints().unwrap();
    assert!(
        bc.map(|b| !b.value.ca).unwrap_or(true),
        "leaf must not be a CA"
    );
}

#[tokio::test]
async fn leaf_is_cached_and_cache_is_cleared_by_allow_domain() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let a = ca.server_config_for("github.com").unwrap();
    let b = ca.server_config_for("github.com").unwrap();
    assert!(Arc::ptr_eq(&a, &b));
    ca.allow_domain("gitlab.com").unwrap();
    let c = ca.server_config_for("github.com").unwrap();
    assert!(!Arc::ptr_eq(&a, &c));
}

#[test]
fn expired_cache_entry_returns_a_fresh_config() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    ca.set_leaf_cache_ttl(std::time::Duration::from_millis(30));
    let a = ca.server_config_for("github.com").unwrap();
    assert!(Arc::ptr_eq(
        &a,
        &ca.server_config_for("github.com").unwrap()
    ));
    std::thread::sleep(std::time::Duration::from_millis(60));
    let b = ca.server_config_for("github.com").unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
}

#[test]
fn concurrent_requests_for_the_same_host_share_one_config() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let ca = Arc::new(ca);
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let ca = ca.clone();
            std::thread::spawn(move || ca.server_config_for("api.github.com").unwrap())
        })
        .collect();
    let cfgs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(cfgs.iter().all(|c| Arc::ptr_eq(c, &cfgs[0])));
}

#[test]
fn concurrent_allow_domain_and_issuance_do_not_deadlock() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let ca = Arc::new(ca);
    let mut hs = vec![];
    for i in 0..4 {
        let c = ca.clone();
        hs.push(std::thread::spawn(move || {
            for _ in 0..5 {
                c.server_config_for("github.com").unwrap();
            }
            c.allow_domain(&format!("d{i}.example.com")).unwrap();
        }));
    }
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(ca.domains().len(), 5);
}

#[test]
fn more_invalid_domains_are_rejected() {
    let (_d, _v, ca) = ca();
    for bad in [
        ".github.com",
        "github.com.",
        "a..b.com",
        "x.invalid",
        "1.2.3.4",
        "münchen.de",
        "a_b.com",
    ] {
        assert!(ca.allow_domain(bad).is_err(), "{bad:?}");
    }
    assert!(ca.domains().is_empty());
    assert_eq!(permitted_dns(&ca.cert_pem()), vec!["invalid".to_string()]);
}

#[test]
fn private_key_is_not_recoverable_from_the_db_without_the_vault_key() {
    let (dir, v, _ca) = ca();
    let blob: Vec<u8> = v
        .conn()
        .query_row("SELECT key_enc FROM ca WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    // wrong AAD / tampered blob fail to open
    assert!(v.open_value(b"other", &blob).is_err());
    let mut bad = blob.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(v.open_value(b"sg:ca-key", &bad).is_err());
    // a vault opened with a different key cannot decrypt it, and the raw file holds no PEM marker
    drop(v);
    let raw = std::fs::read(dir.path().join("v.db")).unwrap();
    assert!(!raw.windows(11).any(|w| w == b"PRIVATE KEY"));
    assert!(Vault::open(
        &dir.path().join("v.db"),
        KeyInput::Raw(crypto::random_key())
    )
    .is_err());
}

#[test]
fn reload_after_allow_domain_still_signs_valid_leaves() {
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let reloaded = CaService::init_or_load(v).unwrap();
    assert!(reloaded.server_config_for("api.github.com").is_ok());
}

// ---------- review fixes ----------

fn real_signer(v: &Vault) -> (rcgen::Certificate, KeyPair) {
    let key_enc: Vec<u8> = v
        .conn()
        .query_row("SELECT key_enc FROM ca WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    let key_pem = v.open_value(b"sg:ca-key", &key_enc).unwrap();
    let key = KeyPair::from_pem(std::str::from_utf8(&key_pem).unwrap()).unwrap();
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Secret Custodian CA");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    (p.self_signed(&key).unwrap(), key)
}

#[tokio::test]
async fn forged_ip_leaves_are_refused_by_the_real_ca_constraints() {
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let (signer, key) = real_signer(&v);
    for ip in ["192.168.1.1", "::1"] {
        let err = handshake_raw(forged_server_config(ip, &signer, &key), &ca.cert_pem(), ip)
            .await
            .unwrap_err();
        assert!(err.contains("NameConstraint"), "{ip}: wrong reason: {err}");
    }
}

#[test]
fn ca_key_usage_is_exactly_cert_sign_and_crl_sign_with_pathlen_zero() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let der = pem_to_der(&ca.cert_pem());
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let ku = cert.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign() && ku.crl_sign());
    assert!(
        !ku.digital_signature()
            && !ku.non_repudiation()
            && !ku.key_encipherment()
            && !ku.data_encipherment()
            && !ku.key_agreement()
            && !ku.encipher_only()
            && !ku.decipher_only()
    );
    let bc = cert.basic_constraints().unwrap().unwrap().value;
    assert_eq!(bc.path_len_constraint, Some(0));
}

#[tokio::test]
async fn webpki_incompatible_domains_are_rejected_and_the_ca_keeps_working() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let before = ca.cert_pem();
    let long_label = format!("{}.com", "a".repeat(64));
    let too_long = format!("{}.com", vec!["a".repeat(60); 5].join(".") + ".bbbbbbbbbbb");
    assert!(too_long.len() > 253);
    for bad in [
        "example.123",
        "0.1",
        "1.2.3",
        "-a.com",
        "a-.com",
        long_label.as_str(),
        too_long.as_str(),
    ] {
        assert!(ca.allow_domain(bad).is_err(), "{bad:?}");
    }
    assert_eq!(ca.domains(), vec!["github.com".to_string()]);
    assert_eq!(ca.cert_pem(), before);
    handshake(&ca, "api.github.com").await.unwrap();
    for ok in ["a-b.example.co", "localhost"] {
        ca.allow_domain(ok).unwrap();
        handshake(&ca, ok).await.unwrap();
    }
    handshake(&ca, "github.com").await.unwrap();
}

#[test]
fn leaf_cache_is_bounded_and_the_ca_certificate_is_built_once_per_change() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let builds = ca.ca_cert_builds();
    for i in 0..1100 {
        ca.server_config_for(&format!("h{i}.github.com")).unwrap();
        assert!(ca.leaf_cache_len() <= 1024);
    }
    assert_eq!(ca.leaf_cache_len(), 1024);
    assert_eq!(ca.ca_cert_builds(), builds, "misses must reuse the CA cert");
    ca.allow_domain("gitlab.com").unwrap();
    assert_eq!(ca.ca_cert_builds(), builds + 1);
}

#[tokio::test]
async fn reissued_ca_certificates_have_distinct_serials_and_the_same_key() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let old_cfg = ca.server_config_for("api.github.com").unwrap();
    let first = ca.cert_pem();
    ca.allow_domain("gitlab.com").unwrap();
    let second = ca.cert_pem();
    let serial = |pem: &str| {
        let der = pem_to_der(pem);
        let (_, c) = X509Certificate::from_der(&der).unwrap();
        c.tbs_certificate.raw_serial().to_vec()
    };
    let (s1, s2) = (serial(&first), serial(&second));
    assert_ne!(s1, s2);
    assert_eq!(s2.len(), 16);
    assert_eq!(s2[0] & 0x80, 0, "serial must be positive");
    assert_eq!(spki_of(&first), spki_of(&second));
    handshake_raw(old_cfg, &second, "api.github.com")
        .await
        .unwrap();
}

#[test]
fn allow_domain_trims_and_lowercases() {
    let (_d, _v, ca) = ca();
    ca.allow_domain(" GitHub.com ").unwrap();
    assert_eq!(ca.domains(), vec!["github.com".to_string()]);
    assert!(ca.allow_domain("git hub.com").is_err());
    assert!(ca.allow_domain("git\thub.com").is_err());
}

// ---- key identifiers and strict (RFC 5280 / X509_STRICT) verification ----

fn ski_of(pem: &str) -> Vec<u8> {
    let der = pem_to_der(pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    match cert
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .unwrap()
        .expect("CA has no SubjectKeyIdentifier")
        .parsed_extension()
    {
        ParsedExtension::SubjectKeyIdentifier(k) => k.0.to_vec(),
        o => panic!("{o:?}"),
    }
}

fn aki_of(pem: &str) -> Vec<u8> {
    let der = pem_to_der(pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    match cert
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .unwrap()
        .expect("leaf has no AuthorityKeyIdentifier")
        .parsed_extension()
    {
        ParsedExtension::AuthorityKeyIdentifier(a) => a
            .key_identifier
            .as_ref()
            .expect("AKI without keyid")
            .0
            .to_vec(),
        o => panic!("{o:?}"),
    }
}

fn assert_leaf_matches_ca(ca: &CaService, host: &str) {
    let (leaf_pem, _) = ca.issue_leaf_pem_for_test(host).unwrap();
    let ski = ski_of(&ca.cert_pem());
    assert!(!ski.is_empty());
    assert_eq!(aki_of(&leaf_pem), ski, "leaf AKI must equal CA SKI");
}

#[test]
fn leaf_aki_equals_ca_ski_fresh_after_allow_domain_and_after_reload() {
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    assert_leaf_matches_ca(&ca, "api.github.com");
    let ski_before = ski_of(&ca.cert_pem());
    ca.allow_domain("example.org").unwrap();
    assert_eq!(ski_before, ski_of(&ca.cert_pem()), "SKI must be stable");
    assert_leaf_matches_ca(&ca, "api.github.com");
    assert_leaf_matches_ca(&ca, "www.example.org");
    let reloaded = CaService::init_or_load(v).unwrap();
    assert_eq!(ski_before, ski_of(&reloaded.cert_pem()));
    assert_leaf_matches_ca(&reloaded, "api.github.com");
}

#[test]
fn leaf_extensions_are_those_of_a_strict_end_entity_certificate() {
    let (_d, _v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    let (leaf_pem, _) = ca.issue_leaf_pem_for_test("api.github.com").unwrap();
    let der = pem_to_der(&leaf_pem);
    let (_, cert) = X509Certificate::from_der(&der).unwrap();
    let bc = cert
        .basic_constraints()
        .unwrap()
        .expect("no basicConstraints");
    assert!(!bc.value.ca);
    let ku = cert.key_usage().unwrap().expect("no keyUsage").value;
    assert!(ku.digital_signature() && !ku.key_cert_sign() && !ku.crl_sign());
    let eku = cert.extended_key_usage().unwrap().expect("no EKU").value;
    assert!(eku.server_auth && !eku.client_auth && !eku.any);
    assert!(cert.subject_alternative_name().unwrap().is_some());
    let ca_der = pem_to_der(&ca.cert_pem());
    let (_, ca_cert) = X509Certificate::from_der(&ca_der).unwrap();
    let bc = ca_cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca && bc.value.path_len_constraint == Some(0));
}

#[test]
fn issue_leaf_pem_for_test_respects_the_name_constraints_gate() {
    let (_d, _v, ca) = ca();
    assert!(matches!(
        ca.issue_leaf_pem_for_test("github.com"),
        Err(CaError::NotPermitted)
    ));
}

#[test]
fn openssl_strict_verification_accepts_leaves() {
    use std::process::Command;
    if Command::new("openssl").arg("version").output().is_err() {
        eprintln!("SKIP: openssl binary not found on PATH");
        return;
    }
    let (_d, v, ca) = ca();
    ca.allow_domain("github.com").unwrap();
    ca.allow_domain("example.org").unwrap();
    let reloaded = CaService::init_or_load(v).unwrap();
    for svc in [&ca, &reloaded] {
        for host in ["api.github.com", "github.com", "www.example.org"] {
            let dir = tempdir().unwrap();
            let (leaf, _) = svc.issue_leaf_pem_for_test(host).unwrap();
            std::fs::write(dir.path().join("ca.pem"), svc.cert_pem()).unwrap();
            std::fs::write(dir.path().join("leaf.pem"), leaf).unwrap();
            let out = Command::new("openssl")
                .current_dir(dir.path())
                .args([
                    "verify",
                    "-x509_strict",
                    "-CAfile",
                    "ca.pem",
                    "-verify_hostname",
                    host,
                    "leaf.pem",
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "openssl strict verify of {host} failed: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|d| d.to_string()).collect()
}

#[test]
fn prepare_has_no_effect_until_persisted_and_installed() {
    let (_d, v, ca) = ca();
    let p = ca
        .prepare_domains(&s(&["b.com", "a.com", "a.com"]))
        .unwrap()
        .unwrap();
    assert!(
        ca.domains().is_empty(),
        "nothing changes while only prepared"
    );
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    assert_eq!(ca.domains(), s(&["a.com", "b.com"]));
    assert!(ca.is_host_permitted("x.a.com"));
    // the same set again is a no-op
    assert!(ca
        .prepare_domains(&s(&["a.com", "b.com"]))
        .unwrap()
        .is_none());
}

#[test]
fn rejected_domains_leave_the_ca_untouched() {
    let (_d, _v, ca) = ca();
    for bad in ["com", "x.invalid", "1.2.3.4", "UPPER case"] {
        assert!(
            matches!(
                ca.prepare_domains(&s(&["ok.com", bad])),
                Err(CaError::DomainRejected(_))
            ),
            "{bad}"
        );
    }
    assert!(ca.domains().is_empty());
}

#[test]
fn persist_inside_a_rolled_back_transaction_is_not_kept() {
    let (_d, v, ca) = ca();
    let p = ca.prepare_domains(&s(&["a.com"])).unwrap().unwrap();
    let r: Result<(), CaError> = v.in_transaction(|c| {
        ca.persist(c, &p)?;
        Err(CaError::NotPermitted)
    });
    assert!(r.is_err());
    // a restart sees the old (empty) state
    assert!(CaService::init_or_load(v.clone())
        .unwrap()
        .domains()
        .is_empty());
}

#[tokio::test]
async fn domains_can_be_removed_and_the_ca_returns_to_the_placeholder() {
    let (_d, v, ca) = ca();
    let p = ca.prepare_domains(&s(&["a.com"])).unwrap().unwrap();
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    handshake(&ca, "a.com").await.unwrap();
    let p = ca.prepare_domains(&[]).unwrap().unwrap();
    ca.persist(&v.conn(), &p).unwrap();
    ca.install(p);
    assert!(ca.domains().is_empty());
    assert_eq!(permitted_dns(&ca.cert_pem()), vec!["invalid".to_string()]);
    assert!(handshake(&ca, "a.com").await.is_err());
    let reloaded = CaService::init_or_load(v.clone()).unwrap();
    assert!(reloaded.domains().is_empty());
    assert_eq!(
        permitted_dns(&reloaded.cert_pem()),
        vec!["invalid".to_string()]
    );
}
