use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;

fn vault() -> (tempfile::TempDir, Vault) {
    let d = tempfile::tempdir().unwrap();
    let v = Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap();
    (d, v)
}

fn spec(role: &str, host: &str) -> RuleSpec {
    RuleSpec {
        role: role.into(),
        host_pattern: host.into(),
        path_pattern: "*".into(),
        methods: vec![],
        kind: InjectionKind::Header,
        target_name: "Authorization".into(),
        template: "Bearer {secret}".into(),
    }
}

#[test]
fn conn_functions_cover_count_owner_and_orphans() {
    let (_d, v) = vault();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    add_role(&v, "rev", Unmatched::Deny).unwrap();
    let only_dev = v.add_secret("only-dev", "x").unwrap();
    let both = v.add_secret("both", "x").unwrap();
    let conn = v.conn();
    let r1 = insert_rule_in(&conn, spec("dev", "a.com").with_secret(only_dev.id)).unwrap();
    insert_rule_in(&conn, spec("dev", "b.com").with_secret(both.id)).unwrap();
    insert_rule_in(&conn, spec("rev", "b.com").with_secret(both.id)).unwrap();
    assert_eq!(rule_count_for_secret_in(&conn, both.id).unwrap(), 2);
    assert_eq!(secret_of_rule_in(&conn, r1.id).unwrap(), only_dev.id);
    assert!(matches!(
        secret_of_rule_in(&conn, 9999),
        Err(PolicyError::NotFound)
    ));
    // removing role `dev` would leave `only-dev` without rules, but not `both`
    assert_eq!(
        secrets_orphaned_by_role_in(&conn, "dev").unwrap(),
        vec!["only-dev".to_string()]
    );
    assert!(secrets_orphaned_by_role_in(&conn, "rev")
        .unwrap()
        .is_empty());
    assert_eq!(list_rules_in(&conn, Some("dev")).unwrap().len(), 2);
    remove_rule_in(&conn, r1.id).unwrap();
    assert!(matches!(
        remove_rule_in(&conn, r1.id),
        Err(PolicyError::NotFound)
    ));
    remove_role_in(&conn, "rev").unwrap();
    assert!(get_role_in(&conn, "rev").unwrap().is_none());
}

#[test]
fn insert_rule_in_still_validates() {
    let (_d, v) = vault();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    let s = v.add_secret("s", "x").unwrap();
    let conn = v.conn();
    assert!(matches!(
        insert_rule_in(&conn, spec("dev", "*.com").with_secret(s.id)),
        Err(PolicyError::Invalid(_))
    ));
    assert!(matches!(
        insert_rule_in(&conn, spec("ghost", "a.com").with_secret(s.id)),
        Err(PolicyError::Invalid("unknown role"))
    ));
}

#[test]
fn an_identical_rule_is_rejected_and_names_the_existing_one() {
    let (_d, v) = vault();
    add_role(&v, "dev", Unmatched::Deny).unwrap();
    add_role(&v, "rev", Unmatched::Deny).unwrap();
    let s = v.add_secret("s", "x").unwrap();
    let other = v.add_secret("o", "x").unwrap();
    let conn = v.conn();
    let mut a = spec("dev", "a.com");
    a.methods = vec!["GET".into(), "head".into()];
    let first = insert_rule_in(&conn, a.clone().with_secret(s.id)).unwrap();

    // the same rule again, and with the methods in another order and case
    assert!(matches!(
        insert_rule_in(&conn, a.clone().with_secret(s.id)),
        Err(PolicyError::DuplicateRule(id)) if id == first.id
    ));
    let mut reordered = a.clone();
    reordered.methods = vec!["HEAD".into(), "get".into()];
    assert!(matches!(
        insert_rule_in(&conn, reordered.with_secret(s.id)),
        Err(PolicyError::DuplicateRule(id)) if id == first.id
    ));

    // differing in any one field is a different rule
    let mut path = a.clone();
    path.path_pattern = "/v1/*".into();
    insert_rule_in(&conn, path.with_secret(s.id)).unwrap();
    let mut methods = a.clone();
    methods.methods = vec!["GET".into()];
    insert_rule_in(&conn, methods.with_secret(s.id)).unwrap();
    let mut template = a.clone();
    template.template = "Token {secret}".into();
    insert_rule_in(&conn, template.with_secret(s.id)).unwrap();
    let mut role = a.clone();
    role.role = "rev".into();
    insert_rule_in(&conn, role.with_secret(s.id)).unwrap();
    insert_rule_in(&conn, a.clone().with_secret(other.id)).unwrap();
    // and the rejections left nothing behind: first + 5 distinct ones
    assert_eq!(list_rules_in(&conn, None).unwrap().len(), 6);
}
