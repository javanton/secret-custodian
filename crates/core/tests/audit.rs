use sg_core::audit::{AuditEntry, AuditFilter};
use sg_core::{crypto, KeyInput, Vault};
use tempfile::tempdir;

fn vault() -> (tempfile::TempDir, Vault) {
    let d = tempdir().unwrap();
    let v = Vault::init(&d.path().join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap();
    (d, v)
}

fn list(v: &Vault, f: AuditFilter) -> Vec<AuditEntry> {
    v.list_audit(&f).unwrap()
}

#[test]
fn query_string_is_never_stored() {
    let e = AuditEntry::new(
        "api.x.com",
        "GET",
        "/v1/items?api_key=SHOULD-NOT-LEAK&x=1",
        "inject",
    );
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
    assert_eq!(
        v.list_audit(&AuditFilter {
            limit: 10,
            ..Default::default()
        })
        .unwrap()
        .len(),
        2
    );
    let only_dev = v
        .list_audit(&AuditFilter {
            role: Some("developer".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(only_dev.len(), 1);
    assert_eq!(only_dev[0].host, "api.github.com");
    let by_host = v
        .list_audit(&AuditFilter {
            host: Some("example.com".into()),
            limit: 10,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(by_host[0].decision, "forbidden");
}

#[test]
fn query_and_fragment_stripping_shapes() {
    let cases = [
        ("/a?x", "/a"),
        ("/a#y", "/a"),
        ("/a?x#y", "/a"),
        ("/a#y?x", "/a"),
        ("?", "/"),
        ("?secret=1", "/"),
        ("#frag", "/"),
        ("", "/"),
        ("/a/b/c", "/a/b/c"),
    ];
    for (raw, want) in cases {
        assert_eq!(
            AuditEntry::new("h", "GET", raw, "d").path,
            want,
            "raw={raw:?}"
        );
    }
}

#[test]
fn record_strips_query_even_if_path_was_set_directly() {
    let (_d, v) = vault();
    let mut e = AuditEntry::new("h", "GET", "/ok", "inject");
    e.path = "/p?token=LEAK#f".into();
    v.record_audit(&e).unwrap();
    let got = list(&v, AuditFilter::default());
    assert_eq!(got[0].path, "/p");
}

#[test]
fn oversized_and_multibyte_fields_are_truncated_on_char_boundaries() {
    let (_d, v) = vault();
    // "é" is 2 bytes: "/" + 1024*"é" = 2049 bytes, so byte 2048 splits a char.
    let path = format!("/{}", "é".repeat(1024));
    let host = "ñ".repeat(200); // 400 bytes
    let method = "€".repeat(10); // 30 bytes
    let decision = "😀".repeat(30); // 120 bytes
    let mut e = AuditEntry::new(&host, &method, &path, &decision);
    e.path = path.clone();
    v.record_audit(&e).unwrap();
    let got = &list(&v, AuditFilter::default())[0];
    assert!(got.path.len() <= 2048 && got.path.len() >= 2046);
    assert!(path.starts_with(&got.path));
    assert!(got.host.len() <= 253 && host.starts_with(&got.host) && got.host.len() >= 252);
    assert!(got.method.len() <= 16 && method.starts_with(&got.method) && got.method.len() >= 15);
    assert!(
        got.decision.len() <= 64 && decision.starts_with(&got.decision) && got.decision.len() >= 60
    );

    // Plain ASCII over the limit too.
    let e = AuditEntry::new(
        &"a".repeat(1000),
        "GET",
        &format!("/{}", "b".repeat(5000)),
        "d",
    );
    v.record_audit(&e).unwrap();
    let got = &list(&v, AuditFilter::default())[0];
    assert_eq!(got.path.len(), 2048);
    assert_eq!(got.host.len(), 253);
}

#[test]
fn sqlish_strings_are_stored_and_matched_literally() {
    let (_d, v) = vault();
    let evil_host = "x'; DROP TABLE audit; --";
    let evil_role = "r' OR '1'='1";
    let mut a = AuditEntry::new(evil_host, "GET", "/", "inject");
    a.role = Some(evil_role.into());
    let mut b = AuditEntry::new("good.com", "GET", "/", "inject");
    b.role = Some("developer".into());
    v.record_audit(&a).unwrap();
    v.record_audit(&b).unwrap();

    let by_role = list(
        &v,
        AuditFilter {
            role: Some(evil_role.into()),
            ..Default::default()
        },
    );
    assert_eq!(by_role.len(), 1);
    assert_eq!(by_role[0].host, evil_host);

    let by_host = list(
        &v,
        AuditFilter {
            host: Some(evil_host.into()),
            ..Default::default()
        },
    );
    assert_eq!(by_host.len(), 1);
    assert_eq!(by_host[0].role.as_deref(), Some(evil_role));

    // A wildcard-looking or tautology filter must not match everything.
    for s in ["%", "' OR '1'='1", "_"] {
        let r = list(
            &v,
            AuditFilter {
                role: Some(s.into()),
                ..Default::default()
            },
        );
        assert!(r.is_empty(), "filter {s:?} matched rows");
    }
    assert_eq!(list(&v, AuditFilter::default()).len(), 2);
}

#[test]
fn since_filter_and_newest_first_ordering() {
    let (_d, v) = vault();
    for (i, ts) in [100i64, 200, 300].into_iter().enumerate() {
        let mut e = AuditEntry::new("h", "GET", &format!("/{i}"), "inject");
        e.ts = ts;
        v.record_audit(&e).unwrap();
    }
    let all = list(&v, AuditFilter::default());
    assert_eq!(
        all.iter().map(|e| e.ts).collect::<Vec<_>>(),
        vec![300, 200, 100]
    );
    let since = list(
        &v,
        AuditFilter {
            since: Some(200),
            ..Default::default()
        },
    );
    assert_eq!(
        since.iter().map(|e| e.ts).collect::<Vec<_>>(),
        vec![300, 200]
    );
    let none = list(
        &v,
        AuditFilter {
            since: Some(301),
            ..Default::default()
        },
    );
    assert!(none.is_empty());
}

#[test]
fn limit_is_clamped() {
    let (_d, v) = vault();
    for _ in 0..1005 {
        v.record_audit(&AuditEntry::new("h", "GET", "/", "inject"))
            .unwrap();
    }
    let n = |limit| {
        list(
            &v,
            AuditFilter {
                limit,
                ..Default::default()
            },
        )
        .len()
    };
    assert_eq!(n(0), 100);
    assert_eq!(n(1), 1);
    assert_eq!(n(5), 5);
    assert_eq!(n(5000), 1000);
    assert_eq!(n(usize::MAX), 1000);
}

#[test]
fn status_round_trips_as_u16_including_none() {
    let (_d, v) = vault();
    let mut a = AuditEntry::new("h", "GET", "/a", "inject");
    a.status = Some(65535);
    let mut b = AuditEntry::new("h", "GET", "/b", "inject");
    b.status = None;
    let mut c = AuditEntry::new("h", "GET", "/c", "inject");
    c.status = Some(404);
    c.rule_id = Some(7);
    c.jti = Some("jti-1".into());
    c.machine = Some("m1".into());
    for e in [&a, &b, &c] {
        v.record_audit(e).unwrap();
    }
    let got = list(&v, AuditFilter::default());
    assert_eq!(got[0].status, Some(404));
    assert_eq!(got[0].rule_id, Some(7));
    assert_eq!(got[0].jti.as_deref(), Some("jti-1"));
    assert_eq!(got[0].machine.as_deref(), Some("m1"));
    assert_eq!(got[1].status, None);
    assert_eq!(got[2].status, Some(65535));
}

#[test]
fn listing_empty_table_returns_empty_vec() {
    let (_d, v) = vault();
    assert!(list(&v, AuditFilter::default()).is_empty());
}
