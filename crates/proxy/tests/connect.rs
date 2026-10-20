mod common;
use common::*;
use sg_policy::{add_role, Unmatched};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn missing_or_garbage_credentials_get_407() {
    let env = Env::new(no_extra_roots()).await;
    for auth in [
        None,
        Some("Basic !!!"),
        Some("Bearer not.a.token"),
        Some("Digest x"),
    ] {
        let (line, _) = raw_connect(env.proxy_addr, "example.com:443", auth).await;
        assert!(line.contains("407"), "{auth:?} -> {line}");
    }
}

#[tokio::test]
async fn revoked_token_gets_407() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let issued = env.tokens.issue("m", "developer", None).unwrap();
    env.tokens.revoke(&issued.jti).unwrap();
    let (line, _) = raw_connect(
        env.proxy_addr,
        "example.com:443",
        Some(&basic(&issued.token)),
    )
    .await;
    assert!(line.contains("407"));
}

#[tokio::test]
async fn unknown_role_in_a_valid_token_gets_403() {
    let env = Env::new(no_extra_roots()).await;
    let t = env.token("m", "ghost");
    let (line, _) = raw_connect(env.proxy_addr, "example.com:443", Some(&basic(&t))).await;
    assert!(line.contains("403"));
}

#[tokio::test]
async fn passthrough_tunnels_hosts_without_rules() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, mut s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn deny_policy_blocks_hosts_without_rules_and_audits_it() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "reviewer", Unmatched::Deny).unwrap();
    let t = env.token("laptop", "reviewer");
    let (line, _) = raw_connect(env.proxy_addr, "example.com:443", Some(&basic(&t))).await;
    assert!(line.contains("403"));
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].host, "example.com");
    assert_eq!(rows[0].decision, "unmatched-denied");
    assert_eq!(rows[0].machine.as_deref(), Some("laptop"));
}

#[tokio::test]
async fn host_with_rule_but_not_permitted_by_ca_gets_502_with_hint() {
    use sg_policy::*;
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "v").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: "api.github.com".into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "Bearer {secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    let t = env.token("m", "developer");
    let (line, _) = raw_connect(env.proxy_addr, "api.github.com:443", Some(&basic(&t))).await;
    assert!(line.contains("502"), "{line}");
}

// ---- Hardening and extra coverage (beyond the plan's six tests) ----

use sg_auth::{AuthError, Identity, TokenVerifier};
use sg_proxy::ServeOptions;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn proxy_407_carries_proxy_authenticate() {
    let env = Env::new(no_extra_roots()).await;
    let (head, _) = raw_connect_head(env.proxy_addr, "example.com:443", None).await;
    assert!(head.contains("407"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("proxy-authenticate: basic"),
        "{head}"
    );
}

#[tokio::test]
async fn token_for_a_deleted_role_gets_403_unknown_role_and_audits_it() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "temp", Unmatched::Passthrough).unwrap();
    let issued = env.tokens.issue("laptop", "temp", None).unwrap();
    sg_policy::remove_role(&env.vault, "temp").unwrap();
    let (line, _) = raw_connect(
        env.proxy_addr,
        "example.com:443",
        Some(&basic(&issued.token)),
    )
    .await;
    assert!(line.contains("403"), "{line}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].decision, "unknown-role");
    assert_eq!(rows[0].jti.as_deref(), Some(issued.jti.as_str()));
    assert_eq!(rows[0].role.as_deref(), Some("temp"));
    assert_eq!(rows[0].machine.as_deref(), Some("laptop"));
}

#[tokio::test]
async fn bearer_scheme_works_like_basic() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, mut s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&bearer(&t))).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"hi").await.unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hi");
}

#[tokio::test]
async fn ipv6_literal_authority_is_tunnelled() {
    let Ok(l) = tokio::net::TcpListener::bind("[::1]:0").await else {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    };
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "developer");
    let (line, mut s) =
        raw_connect(env.proxy_addr, &format!("[::1]:{port}"), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"v6").await.unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"v6");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].host, "::1");
}

#[tokio::test]
async fn two_concurrent_tunnels_work() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (l1, mut a) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    let (l2, mut b) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(l1.contains("200") && l2.contains("200"));
    a.write_all(b"aaaa").await.unwrap();
    b.write_all(b"bbbb").await.unwrap();
    let (mut ra, mut rb) = ([0u8; 4], [0u8; 4]);
    b.read_exact(&mut rb).await.unwrap();
    a.read_exact(&mut ra).await.unwrap();
    assert_eq!((&ra, &rb), (b"aaaa", b"bbbb"));
}

#[tokio::test]
async fn audit_rows_exist_before_the_response_for_deny_ca_and_passthrough() {
    use sg_policy::*;
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "strict", Unmatched::Deny).unwrap();
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "v").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "open".into(),
            host_pattern: "api.github.com".into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "Bearer {secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    let echo = echo_server().await;

    // Each audit lookup happens right after the status line is read: the row must already exist.
    let strict = env.tokens.issue("m1", "strict", None).unwrap();
    let (line, _) = raw_connect(
        env.proxy_addr,
        "example.com:443",
        Some(&basic(&strict.token)),
    )
    .await;
    assert!(line.contains("403"));
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].decision.as_str(), rows[0].status),
        ("unmatched-denied", Some(403))
    );
    assert_eq!(rows[0].jti.as_deref(), Some(strict.jti.as_str()));
    assert_eq!(rows[0].role.as_deref(), Some("strict"));
    assert_eq!(rows[0].machine.as_deref(), Some("m1"));

    let open = env.tokens.issue("m2", "open", None).unwrap();
    let (line, mut refused) = raw_connect(
        env.proxy_addr,
        "api.github.com:443",
        Some(&basic(&open.token)),
    )
    .await;
    assert!(line.contains("502"));
    // The hint must not point at a command that no longer exists.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut refused, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let body = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(
        body.contains("the CA does not permit api.github.com"),
        "{body}"
    );
    assert!(!body.contains("allow-domain"), "{body}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].decision.as_str(), rows[0].status),
        ("ca-not-permitted", Some(502))
    );
    assert_eq!(rows[0].host, "api.github.com");
    assert_eq!(rows[0].jti.as_deref(), Some(open.jti.as_str()));
    assert_eq!(rows[0].machine.as_deref(), Some("m2"));

    let (line, _s) =
        raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&open.token))).await;
    assert!(line.contains("200"));
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        (rows[0].decision.as_str(), rows[0].status),
        ("passthrough", Some(200))
    );
    assert_eq!(rows[0].role.as_deref(), Some("open"));
}

#[tokio::test]
async fn unreachable_destination_gets_502_and_audit_without_opening_a_tunnel() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    // Grab a free port and close it so the connect is refused.
    let port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let t = env.token("m", "developer");
    let (line, _) = raw_connect(
        env.proxy_addr,
        &format!("127.0.0.1:{port}"),
        Some(&basic(&t)),
    )
    .await;
    assert!(line.contains("502"), "{line}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].decision, "tunnel-connect-failed");
}

#[tokio::test]
async fn bad_connect_targets_get_400() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "developer");
    for target in [
        "example.com:0",
        "user:pw@example.com:443",
        "user@example.com:443",
        "bad!host:443",
    ] {
        let (line, _) = raw_connect(env.proxy_addr, target, Some(&basic(&t))).await;
        assert!(line.contains("400"), "{target} -> {line}");
    }
    // Authenticated 400s are audited with the identity (a 407 would write nothing).
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 4, "{rows:?}");
    for r in &rows {
        assert_eq!(r.decision, "bad-request");
        assert_eq!(r.method, "CONNECT");
        assert_eq!(r.status, Some(400));
        assert_eq!(r.role.as_deref(), Some("developer"));
        assert!(r.jti.is_some());
    }
}

#[tokio::test]
async fn connect_without_port_defaults_to_443() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "strict", Unmatched::Deny).unwrap();
    let t = env.token("m", "strict");
    let (line, _) = raw_connect(env.proxy_addr, "example.com", Some(&basic(&t))).await;
    assert!(line.contains("403"), "{line}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows[0].host, "example.com");
}

#[tokio::test]
async fn error_bodies_do_not_echo_tokens_or_secret_names() {
    use sg_policy::*;
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env
        .vault
        .add_secret("super-secret-name", "super-secret-value")
        .unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: "api.github.com".into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "Bearer {secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    let t = env.token("m", "developer");
    for (auth, authority) in [
        (Some(bearer("junk.junk.junk")), "example.com:443"),
        (Some(basic(&t)), "api.github.com:443"),
    ] {
        let (_, mut s) = raw_connect(env.proxy_addr, authority, auth.as_deref()).await;
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(300), s.read_to_end(&mut rest)).await;
        let body = String::from_utf8_lossy(&rest);
        for needle in [
            "junk.junk.junk",
            t.as_str(),
            "super-secret",
            "Authorization",
        ] {
            assert!(!body.contains(needle), "body leaked {needle}: {body}");
        }
    }
}

struct CountingVerifier(AtomicUsize);
impl TokenVerifier for CountingVerifier {
    fn verify(&self, _token: &str) -> Result<Identity, AuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::Revoked(Identity {
            jti: "j".into(),
            machine: "m".into(),
            role: "r".into(),
        }))
    }
}

#[tokio::test]
async fn oversized_proxy_authorization_gets_407_without_verification() {
    let counter = Arc::new(CountingVerifier(AtomicUsize::new(0)));
    let env = Env::custom(
        no_extra_roots(),
        ServeOptions::default(),
        Some(counter.clone()),
    )
    .await;
    let (line, _) = raw_connect(
        env.proxy_addr,
        "example.com:443",
        Some(&bearer(&"a".repeat(8 * 1024 + 1))),
    )
    .await;
    assert!(line.contains("407"), "{line}");
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "oversized value must not reach the verifier"
    );
    // Control: a normal-sized value does reach the verifier.
    let (line, _) = raw_connect(
        env.proxy_addr,
        "example.com:443",
        Some(&bearer("abc.def.ghi")),
    )
    .await;
    assert!(line.contains("407"));
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn duplicate_proxy_authorization_headers_get_407() {
    let env = Env::new(no_extra_roots()).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "developer");
    let raw = format!(
        "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: {}\r\nProxy-Authorization: {}\r\n\r\n",
        basic(&t),
        basic(&t)
    );
    let (head, _) = raw_head(env.proxy_addr, raw.as_bytes()).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
}

#[tokio::test]
async fn slow_header_connection_is_closed_after_the_header_read_timeout() {
    let opts = ServeOptions {
        header_read_timeout: Duration::from_millis(500),
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    let mut s = tokio::net::TcpStream::connect(env.proxy_addr)
        .await
        .unwrap();
    s.write_all(b"CONNECT example.com:443 HTT").await.unwrap();
    let mut buf = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(
        r.is_ok(),
        "server kept the half-open connection past the timeout"
    );
}

#[tokio::test]
async fn connection_cap_makes_excess_connections_wait_until_a_slot_frees() {
    let opts = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    // First connection occupies the only slot (idle, no request sent).
    let first = tokio::net::TcpStream::connect(env.proxy_addr)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = tokio::net::TcpStream::connect(env.proxy_addr)
        .await
        .unwrap();
    second
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 12];
    let waited =
        tokio::time::timeout(Duration::from_millis(500), second.read_exact(&mut buf)).await;
    assert!(
        waited.is_err(),
        "second connection was served while the cap was full"
    );
    drop(first);
    tokio::time::timeout(Duration::from_secs(5), second.read_exact(&mut buf))
        .await
        .expect("second connection must be served after the slot frees")
        .unwrap();
    assert_eq!(&buf, b"HTTP/1.1 407");
}
