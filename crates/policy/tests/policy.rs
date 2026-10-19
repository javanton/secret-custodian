use sg_core::{crypto, KeyInput, Vault};
use sg_policy::*;
use tempfile::tempdir;

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempdir().unwrap();
    let v = Vault::init(
        &dir.path().join("v.db"),
        KeyInput::Raw(crypto::random_key()),
    )
    .unwrap();
    (dir, v)
}

fn new_rule(secret_id: i64) -> NewRule {
    NewRule {
        role: "developer".into(),
        host_pattern: "api.github.com".into(),
        path_pattern: "*".into(),
        methods: vec!["GET".into()],
        kind: InjectionKind::Header,
        target_name: "Authorization".into(),
        template: "Bearer {secret}".into(),
        secret_id,
    }
}

#[test]
fn role_and_rule_crud() {
    let (_d, v) = vault();
    let s = v.add_secret("gh", "tok").unwrap();
    add_role(&v, "developer", Unmatched::Passthrough).unwrap();
    let rule = add_rule(&v, new_rule(s.id)).unwrap();
    assert_eq!(
        list_rules(&v, Some("developer")).unwrap(),
        vec![rule.clone()]
    );
    assert!(list_rules(&v, Some("reviewer")).unwrap().is_empty());
    assert_eq!(
        get_role(&v, "developer").unwrap().unwrap().unmatched,
        Unmatched::Passthrough
    );
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
    assert!(matches!(
        v.remove_secret("gh"),
        Err(sg_core::CoreError::InUse)
    ));
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

// --- extra tests (gaps not covered by the plan) ---

fn setup() -> (tempfile::TempDir, Vault, i64) {
    let (d, v) = vault();
    let s = v.add_secret("gh", "tok").unwrap();
    add_role(&v, "developer", Unmatched::Deny).unwrap();
    (d, v, s.id)
}

#[test]
fn more_invalid_rules_are_rejected() {
    let (_d, v, sid) = setup();
    let bad = |f: fn(&mut NewRule)| {
        let mut r = new_rule(sid);
        f(&mut r);
        assert!(add_rule(&v, r).is_err());
    };
    bad(|r| r.host_pattern = "API.github.com".into());
    bad(|r| r.host_pattern = "::1".into());
    bad(|r| r.host_pattern = "[::1]".into());
    bad(|r| r.host_pattern = "api.github.com:443".into());
    bad(|r| r.host_pattern = "*.*.com".into());
    bad(|r| r.host_pattern = "*.".into());
    bad(|r| r.host_pattern = "".into());
    bad(|r| r.host_pattern = "api.github.com.".into());
    bad(|r| r.host_pattern = "a..com".into());
    bad(|r| r.host_pattern = "api*.github.com".into());
    bad(|r| r.host_pattern = "1.2.3.4.5".into());
    bad(|r| r.path_pattern = "".into());
    bad(|r| r.methods = vec!["".into()]);
    bad(|r| r.methods = vec!["GET".into(), "PO\r\nST".into()]);
    bad(|r| r.target_name = "".into());
    bad(|r| r.target_name = "X\0Y".into());
    bad(|r| r.template = "Bearer {secret}\r\nX-Evil: 1".into());
    bad(|r| r.template = "Bearer {secret}\n".into());
    bad(|r| r.template = "Bearer {secret}\0".into());
    bad(|r| {
        r.kind = InjectionKind::Query;
        r.target_name = "a b".into();
    });
    bad(|r| {
        r.kind = InjectionKind::Query;
        r.target_name = "a&b=c".into();
    });
}

#[test]
fn valid_edge_rules_are_accepted() {
    let (_d, v, sid) = setup();
    let ok = |f: fn(&mut NewRule)| {
        let mut r = new_rule(sid);
        f(&mut r);
        add_rule(&v, r).unwrap();
    };
    ok(|r| r.host_pattern = "*.example.com".into());
    ok(|r| r.host_pattern = "localhost".into());
    ok(|r| r.host_pattern = "my-api-1.example.co.uk".into());
    ok(|r| r.methods = vec![]);
    ok(|r| r.path_pattern = "/repos/*".into());
    ok(|r| {
        r.kind = InjectionKind::Query;
        r.target_name = "api_key".into();
        r.template = "{secret}".into();
    });
}

#[test]
fn methods_are_uppercased_and_empty_methods_round_trip() {
    let (_d, v, sid) = setup();
    let mut r = new_rule(sid);
    r.methods = vec!["get".into(), "Post".into()];
    let added = add_rule(&v, r).unwrap();
    assert_eq!(added.methods, vec!["GET", "POST"]);
    let mut r2 = new_rule(sid);
    r2.methods = vec![];
    let added2 = add_rule(&v, r2).unwrap();
    let listed = list_rules(&v, None).unwrap();
    assert_eq!(listed, vec![added, added2.clone()]);
    assert!(listed[1].methods.is_empty());
}

#[test]
fn query_kind_round_trips() {
    let (_d, v, sid) = setup();
    let mut r = new_rule(sid);
    r.kind = InjectionKind::Query;
    r.target_name = "api_key".into();
    r.template = "{secret}".into();
    let added = add_rule(&v, r).unwrap();
    assert_eq!(list_rules(&v, None).unwrap(), vec![added.clone()]);
    assert_eq!(added.kind, InjectionKind::Query);
}

#[test]
fn role_names_are_validated_and_unique() {
    let (_d, v) = vault();
    for bad in ["", "Dev", "has space", "a/b", "dev\n", "é", &"x".repeat(65)] {
        assert!(
            matches!(
                add_role(&v, bad, Unmatched::Deny),
                Err(PolicyError::Invalid(_))
            ),
            "{bad:?}"
        );
    }
    add_role(&v, "dev-1_x", Unmatched::Deny).unwrap();
    assert!(matches!(
        add_role(&v, "dev-1_x", Unmatched::Passthrough),
        Err(PolicyError::AlreadyExists)
    ));
    add_role(&v, &"x".repeat(64), Unmatched::Deny).unwrap();
}

#[test]
fn list_roles_is_sorted_and_carries_policy() {
    let (_d, v) = vault();
    add_role(&v, "zeta", Unmatched::Deny).unwrap();
    add_role(&v, "alpha", Unmatched::Passthrough).unwrap();
    assert_eq!(
        list_roles(&v).unwrap(),
        vec![
            Role {
                name: "alpha".into(),
                unmatched: Unmatched::Passthrough
            },
            Role {
                name: "zeta".into(),
                unmatched: Unmatched::Deny
            },
        ]
    );
}

#[test]
fn removing_missing_role_or_rule_is_not_found() {
    let (_d, v) = vault();
    assert!(matches!(
        remove_role(&v, "ghost"),
        Err(PolicyError::NotFound)
    ));
    assert!(matches!(remove_rule(&v, 12345), Err(PolicyError::NotFound)));
}

#[test]
fn removing_a_role_cascades_to_its_rules_and_frees_the_secret() {
    let (_d, v, sid) = setup();
    add_rule(&v, new_rule(sid)).unwrap();
    remove_role(&v, "developer").unwrap();
    assert!(list_rules(&v, None).unwrap().is_empty());
    v.remove_secret("gh").unwrap();
}

#[test]
fn removing_the_rule_frees_the_secret() {
    let (_d, v, sid) = setup();
    let r = add_rule(&v, new_rule(sid)).unwrap();
    remove_rule(&v, r.id).unwrap();
    v.remove_secret("gh").unwrap();
}

#[test]
fn list_rules_without_filter_returns_all_roles_in_id_order() {
    let (_d, v, sid) = setup();
    add_role(&v, "other", Unmatched::Passthrough).unwrap();
    let a = add_rule(&v, new_rule(sid)).unwrap();
    let mut r = new_rule(sid);
    r.role = "other".into();
    let b = add_rule(&v, r).unwrap();
    assert_eq!(list_rules(&v, None).unwrap(), vec![a.clone(), b.clone()]);
    assert_eq!(list_rules(&v, Some("other")).unwrap(), vec![b]);
}

#[test]
fn new_rule_deserializes_with_defaults() {
    let r: NewRule = serde_json::from_str(
        r#"{"role":"developer","host_pattern":"a.com","kind":"header","target_name":"X","template":"{secret}","secret_id":1}"#,
    )
    .unwrap();
    assert_eq!(r.path_pattern, "*");
    assert!(r.methods.is_empty());
}

#[test]
fn unmatched_parses_and_prints() {
    assert_eq!("deny".parse::<Unmatched>(), Ok(Unmatched::Deny));
    assert_eq!(
        "passthrough".parse::<Unmatched>(),
        Ok(Unmatched::Passthrough)
    );
    assert!("other".parse::<Unmatched>().is_err());
    assert_eq!(Unmatched::Deny.as_str(), "deny");
}

// --- review fixes: fail-closed validation ---

#[test]
fn path_pattern_validation_is_strict() {
    let (_d, v, sid) = setup();
    let bad = |p: &str| {
        let mut r = new_rule(sid);
        r.path_pattern = p.into();
        assert!(add_rule(&v, r).is_err(), "{p} should be rejected");
    };
    let ok = |p: &str| {
        let mut r = new_rule(sid);
        r.path_pattern = p.into();
        add_rule(&v, r).unwrap_or_else(|e| panic!("{p} rejected: {e}"));
    };
    for p in [
        "/a/*/b",
        "/a*b",
        "/**",
        "/a/**",
        "/a?x=1",
        "/a#f",
        "/a/../b",
        "/a//b",
        "/a/./b",
        "/a%2fb",
        "/a%2",
        "/a%zz",
        "/%41pi",
        "/a/..%2fb/*",
        "/repos/..%2F*",
        "/repos/%252E%252E%252F*",
        "/a/..%2Fb/*",
        "/a/%2e%2e/b/*",
        "/a/%252e%252e/b/*",
        "/a%3Bx",
        "/a%255Cb",
        "/a/%E2%80%A5/b",
        "/a/%EF%BC%8E/b",
        "/a/\u{2025}/b",
        "/a/\u{2215}b/*",
        "/a/%20../b",
        "/a/.../b",
        "/a/.%20/b",
        "/a%0Ab",
        "/a%7Fb",
        "/a/\u{FF3C}b",
        "/repos/%EF%BC%9F/*",
        "/repos/caf%C3%A9/*",
        "/repos/caf\u{e9}/*",
        "/a/%E6%97%A5/b",
        "/a/\u{FE30}/b",
        "/a/%EF%B8%B0/b",
        "/repos/..+/*",
        "/v1./*",
        "/a /*",
        "/v1.",
        "/a%20/*",
        "/a%2E/*",
    ] {
        bad(p);
    }
    for p in [
        "*",
        "/",
        "/*",
        "/repos/*",
        "/v1/me",
        "/a%2Fb",
        "/a%2Fb/*",
        "/repos/",
        "/api/v4/projects/a%2Fb",
        "/api/v4/*",
        "/v1*",
        "/repos/.github/*",
        "/a.b/*",
    ] {
        ok(p);
    }
}

#[test]
fn host_pattern_rejects_wildcard_over_single_label_and_bare_labels() {
    let (_d, v, sid) = setup();
    let try_host = |h: &str| {
        let mut r = new_rule(sid);
        r.host_pattern = h.into();
        add_rule(&v, r)
    };
    assert!(try_host("*.com").is_err());
    assert!(try_host("*.localhost").is_err());
    assert!(try_host("intranet").is_err());
    assert!(try_host("localhost").is_ok());
    assert!(try_host("*.example.com").is_ok());
}

#[test]
fn framing_and_hop_by_hop_headers_cannot_be_injection_targets() {
    let (_d, v, sid) = setup();
    for h in [
        "host",
        "Host",
        "content-length",
        "Transfer-Encoding",
        "connection",
        "keep-alive",
        "te",
        "TRAILER",
        "upgrade",
        "proxy-authorization",
        "Proxy-Authenticate",
        "proxy-connection",
        "proxy-foo",
        "Proxy-Anything",
    ] {
        let mut r = new_rule(sid);
        r.target_name = h.into();
        assert!(add_rule(&v, r).is_err(), "{h} should be rejected");
    }
    let mut r = new_rule(sid);
    r.target_name = "X-Api-Key".into();
    assert!(add_rule(&v, r).is_ok());
}

#[test]
fn query_template_must_be_exactly_secret() {
    let (_d, v, sid) = setup();
    for t in [
        "Bearer {secret}",
        "{secret}x",
        " {secret}",
        "{secret}{secret}",
    ] {
        let mut r = new_rule(sid);
        r.kind = InjectionKind::Query;
        r.target_name = "api_key".into();
        r.template = t.into();
        assert!(add_rule(&v, r).is_err(), "{t:?} should be rejected");
    }
    let mut r = new_rule(sid);
    r.kind = InjectionKind::Query;
    r.target_name = "api_key".into();
    r.template = "{secret}".into();
    assert!(add_rule(&v, r).is_ok());
}

#[test]
fn hosts_the_ca_would_reject_are_rejected_by_the_rule_validation() {
    let (_d, v, sid) = setup();
    let long_label = format!("{}.example.com", "a".repeat(64));
    let too_long = format!("{}.com", vec!["a".repeat(60); 5].join("."));
    for host in [
        "my_svc.example.com",
        "a-.example.com",
        "-a.example.com",
        "foo.123",
        "x.invalid",
        "*.invalid",
        "invalid",
        &long_label,
        &too_long,
    ] {
        let mut r = new_rule(sid);
        r.host_pattern = host.into();
        assert!(add_rule(&v, r).is_err(), "{host} should be rejected");
    }
    let mut r = new_rule(sid);
    r.host_pattern = format!("{}.example.com", "a".repeat(63));
    add_rule(&v, r).unwrap();
}
