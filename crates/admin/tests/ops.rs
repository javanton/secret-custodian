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
