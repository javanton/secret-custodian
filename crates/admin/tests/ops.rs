use sg_admin::ops::sync_ca;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;
use std::sync::Arc;

#[test]
fn startup_sync_derives_the_ca_from_existing_rules_and_is_stable() {
    let d = tempfile::tempdir().unwrap();
    let v =
        Arc::new(Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let ca = CaService::init_or_load(v.clone()).unwrap();
    ca.allow_domain("stale.example.org").unwrap(); // a manual domain no rule uses
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    let s = v.add_secret("s", "x").unwrap();
    add_rule(
        &v,
        RuleSpec {
            role: "dev".into(),
            host_pattern: "*.habbi.cc".into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "{secret}".into(),
        }
        .with_secret(s.id),
    )
    .unwrap();
    assert!(sync_ca(&v, &ca).unwrap());
    assert_eq!(ca.domains(), vec!["habbi.cc"]);
    assert!(!sync_ca(&v, &ca).unwrap(), "second run changes nothing");
    assert_eq!(
        CaService::init_or_load(v.clone()).unwrap().domains(),
        vec!["habbi.cc"]
    );
}

fn spec(host: &str) -> RuleSpec {
    RuleSpec {
        role: "dev".into(),
        host_pattern: host.into(),
        path_pattern: "*".into(),
        methods: vec![],
        kind: InjectionKind::Header,
        target_name: "Authorization".into(),
        template: "{secret}".into(),
    }
}

fn fresh() -> (tempfile::TempDir, Arc<Vault>, CaService) {
    let d = tempfile::tempdir().unwrap();
    let v =
        Arc::new(Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    let ca = CaService::init_or_load(v.clone()).unwrap();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    (d, v, ca)
}

#[test]
fn policy_never_accepts_a_host_the_ca_rejects() {
    let (_d, v, ca) = fresh();
    let s = v.add_secret("s", "x").unwrap();
    let long_label = format!("{}.example.com", "a".repeat(64));
    let too_long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
    let hosts = [
        "my_svc.example.com",
        "a-.example.com",
        "-a.example.com",
        &long_label,
        &too_long,
        "foo.123",
        "x.invalid",
        "invalid",
        "*.invalid",
        "UPPER.example.com",
        "example.com",
        "*.example.com",
        "localhost",
        "a.b",
    ];
    for h in hosts {
        if add_rule(&v, spec(h).with_secret(s.id)).is_ok() {
            let domain = h.strip_prefix("*.").unwrap_or(h).to_string();
            assert!(
                ca.prepare_domains(&[domain]).is_ok(),
                "policy accepts {h} but the CA rejects it"
            );
            assert!(ca.domain_is_acceptable(h.strip_prefix("*.").unwrap_or(h)));
        }
    }
}

fn insert_legacy_rule(v: &Vault, secret_id: i64, host: &str) {
    v.conn()
        .execute(
            "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id)
             VALUES ('dev', ?1, '*', '[]', 'header', 'Authorization', '{secret}', ?2)",
            rusqlite::params![host, secret_id],
        )
        .unwrap();
}

#[test]
fn startup_sync_skips_legacy_hosts_the_ca_rejects() {
    let (_d, v, ca) = fresh();
    let s = v.add_secret("s", "x").unwrap();
    add_rule(&v, spec("good.example.com").with_secret(s.id)).unwrap();
    insert_legacy_rule(&v, s.id, "x.invalid");
    insert_legacy_rule(&v, s.id, "my_svc.example.com");
    assert!(sync_ca(&v, &ca).unwrap());
    assert_eq!(ca.domains(), vec!["good.example.com"]);
    assert!(!sync_ca(&v, &ca).unwrap(), "second run changes nothing");
}
