//! Authentication failures at the proxy: a token validly signed by this vault but revoked or
//! expired is audited (rate limited, `token-invalid`, 407); every other failure writes nothing,
//! and the client sees the same 407 either way.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use sg_core::audit::AuditEntry;
use sg_proxy::ServeOptions;
use std::time::Duration;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

fn rows(env: &Env) -> Vec<AuditEntry> {
    env.vault.list_audit(&Default::default()).unwrap()
}

/// Sends raw bytes (the request must say `Connection: close`) and returns the whole response,
/// minus the `date` header, which legitimately differs between two responses.
async fn exchange(env: &Env, raw: &[u8]) -> String {
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out)
        .lines()
        .filter(|l| !l.to_ascii_lowercase().starts_with("date:"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn connect_req(authority: &str, proxy_auth: &[String]) -> Vec<u8> {
    let mut r = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    for v in proxy_auth {
        r.push_str(&format!("Proxy-Authorization: {v}\r\n"));
    }
    r.push_str("Connection: close\r\n\r\n");
    r.into_bytes()
}

fn signing_key(env: &Env) -> SigningKey {
    let blob: Vec<u8> = env
        .vault
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'token_signing_key'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let raw = env
        .vault
        .open_value(b"sg:token-signing-key", &blob)
        .unwrap();
    SigningKey::from_bytes(raw.as_slice().try_into().unwrap())
}

/// A token signed with the vault's real key from arbitrary header/payload.
fn forge(env: &Env, header: &str, payload: &str) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    let sig = signing_key(env).sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

const GOOD_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

fn opts(interval_ms: u64) -> ServeOptions {
    ServeOptions {
        auth_audit_interval: Duration::from_millis(interval_ms),
        ..ServeOptions::default()
    }
}

async fn env(interval_ms: u64) -> Env {
    Env::custom(no_extra_roots(), opts(interval_ms), None).await
}

fn revoked_token(env: &Env, machine: &str, role: &str) -> (String, String) {
    let t = env.tokens.issue(machine, role, None).unwrap();
    env.tokens.revoke(&t.jti).unwrap();
    (t.token, t.jti)
}

#[tokio::test]
async fn revoked_token_at_connect_is_audited_once_with_its_identity() {
    let env = env(60_000).await;
    let (tok, jti) = revoked_token(&env, "laptop", "developer");
    let (head, _) =
        raw_connect_head(env.proxy_addr, "Evil.Example.test:443", Some(&basic(&tok))).await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    let rows = rows(&env);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let r = &rows[0];
    assert_eq!(r.decision, "token-invalid");
    assert_eq!(r.status, Some(407));
    assert_eq!(r.method, "CONNECT");
    assert_eq!(r.jti.as_deref(), Some(jti.as_str()));
    assert_eq!(r.machine.as_deref(), Some("laptop"));
    assert_eq!(r.role.as_deref(), Some("developer"));
    assert_eq!(r.host, "Evil.Example.test");
    assert_eq!(r.path, "/");
    assert_eq!(r.rule_id, None);
    let dump = format!("{r:?}");
    assert!(!dump.contains(&tok), "token leaked into the audit row");
}

#[tokio::test]
async fn expired_token_is_audited_the_same_way() {
    let env = env(60_000).await;
    let t = env
        .tokens
        .issue("ci", "reviewer", Some(Duration::ZERO))
        .unwrap();
    let (head, _) = raw_connect_head(
        env.proxy_addr,
        "api.example.test:443",
        Some(&basic(&t.token)),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    let rows = rows(&env);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let r = &rows[0];
    assert_eq!(
        (r.decision.as_str(), r.status, r.method.as_str()),
        ("token-invalid", Some(407), "CONNECT")
    );
    assert_eq!(r.jti.as_deref(), Some(t.jti.as_str()));
    assert_eq!(r.machine.as_deref(), Some("ci"));
    assert_eq!(r.role.as_deref(), Some("reviewer"));
    assert_eq!(r.host, "api.example.test");
}

#[tokio::test]
async fn host_declared_by_a_rejected_client_is_truncated() {
    let env = env(60_000).await;
    let (tok, _) = revoked_token(&env, "m", "r");
    let long = "a".repeat(600);
    let (head, _) = raw_connect_head(
        env.proxy_addr,
        &format!("{long}.test:443"),
        Some(&basic(&tok)),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    let rows = rows(&env);
    assert_eq!(rows.len(), 1);
    assert!(rows[0].host.len() <= 255, "{}", rows[0].host.len());
}

#[tokio::test]
async fn anonymous_and_invalid_credentials_write_no_audit_row() {
    let env = env(60_000).await;
    let good = env.token("laptop", "developer");
    let other = Env::new(no_extra_roots()).await;
    let foreign = other.token("laptop", "developer"); // signed by another vault's key
    let (h, p, s) = {
        let mut it = good.split('.');
        (
            it.next().unwrap().to_string(),
            it.next().unwrap().to_string(),
            it.next().unwrap().to_string(),
        )
    };
    let mut flipped = s.clone().into_bytes();
    flipped[0] = if flipped[0] == b'A' { b'B' } else { b'A' };
    let bad_sig = format!("{h}.{p}.{}", String::from_utf8(flipped).unwrap());
    let payload = |iss: &str, jti: &str| {
        format!(r#"{{"iss":"{iss}","jti":"{jti}","sub":"m","role":"r","iat":1}}"#)
    };
    let none_alg = format!(
        "{}.{}.",
        B64.encode(r#"{"alg":"none","typ":"JWT"}"#),
        B64.encode(payload("secret-guardian", "j1"))
    );
    // Signed with the real key, but by another issuer / for a jti the vault never issued.
    env.vault
        .conn()
        .execute(
            "INSERT INTO tokens (jti, machine, role, created_at, token_hash) VALUES ('reg', 'm', 'r', 1, 'x')",
            [],
        )
        .unwrap();
    let wrong_iss = forge(&env, GOOD_HEADER, &payload("someone-else", "reg"));
    let unknown_jti = forge(
        &env,
        GOOD_HEADER,
        &payload("secret-guardian", "never-issued"),
    );

    let single = |tok: &str| connect_req("api.example.test:443", &[basic(tok)]);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("garbage", single("junk.junk.junk")),
        ("not a token", single("notatoken")),
        ("foreign key", single(&foreign)),
        ("bad signature", single(&bad_sig)),
        ("alg none", single(&none_alg)),
        ("wrong issuer", single(&wrong_iss)),
        ("unknown jti", single(&unknown_jti)),
        ("missing header", connect_req("api.example.test:443", &[])),
        (
            "duplicate header",
            connect_req("api.example.test:443", &[basic(&good), basic(&good)]),
        ),
        (
            "oversized header",
            connect_req(
                "api.example.test:443",
                &[format!("Basic {}", "A".repeat(9 * 1024))],
            ),
        ),
    ];
    for (name, raw) in cases {
        let resp = exchange(&env, &raw).await;
        assert!(resp.starts_with("HTTP/1.1 407"), "{name}: {resp}");
    }
    assert!(rows(&env).is_empty(), "{:?}", rows(&env));

    // Control: the forged-token helper does produce a token the proxy accepts as authentic
    // (so the rejections above are due to the property under test).
    let ok = forge(&env, GOOD_HEADER, &payload("secret-guardian", "reg"));
    let resp = exchange(&env, &single(&ok)).await;
    assert!(!resp.starts_with("HTTP/1.1 407"), "{resp}");
}

#[tokio::test]
async fn rejection_of_a_revoked_token_is_byte_identical_to_any_other_407() {
    let env = env(60_000).await;
    let (revoked, _) = revoked_token(&env, "laptop", "developer");
    let expired = env
        .tokens
        .issue("laptop", "developer", Some(Duration::ZERO))
        .unwrap()
        .token;
    let req = |tok: &str| connect_req("api.example.test:443", &[basic(tok)]);
    let garbage = exchange(&env, &req("junk.junk.junk")).await;
    let missing = exchange(&env, &connect_req("api.example.test:443", &[])).await;
    assert!(garbage.starts_with("HTTP/1.1 407"), "{garbage}");
    assert!(garbage.contains("proxy-authenticate"), "{garbage}");
    assert!(
        garbage.contains("proxy authentication required"),
        "{garbage}"
    );
    assert_eq!(garbage, missing);
    assert_eq!(exchange(&env, &req(&revoked)).await, garbage);
    assert_eq!(exchange(&env, &req(&expired)).await, garbage);
    assert_eq!(rows(&env).len(), 2, "the revoked and the expired one");
}

#[tokio::test]
async fn at_most_one_row_per_jti_per_interval() {
    let env = env(400).await;
    let (a, ja) = revoked_token(&env, "laptop", "developer");
    let (b, jb) = revoked_token(&env, "laptop", "developer");
    for _ in 0..5 {
        let (head, _) =
            raw_connect_head(env.proxy_addr, "api.example.test:443", Some(&basic(&a))).await;
        assert!(head.starts_with("HTTP/1.1 407"), "{head}");
    }
    let r = rows(&env);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0].jti.as_deref(), Some(ja.as_str()));

    // A different revoked token of the same machine has its own budget.
    let (head, _) =
        raw_connect_head(env.proxy_addr, "api.example.test:443", Some(&basic(&b))).await;
    assert!(head.starts_with("HTTP/1.1 407"));
    let r = rows(&env);
    assert_eq!(r.len(), 2);
    assert_eq!(
        r.iter()
            .filter(|e| e.jti.as_deref() == Some(jb.as_str()))
            .count(),
        1
    );

    // Once the interval has elapsed the same token is audited again.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (head, _) =
        raw_connect_head(env.proxy_addr, "api.example.test:443", Some(&basic(&a))).await;
    assert!(head.starts_with("HTTP/1.1 407"));
    let r = rows(&env);
    assert_eq!(r.len(), 3, "{r:?}");
    assert_eq!(
        r.iter()
            .filter(|e| e.jti.as_deref() == Some(ja.as_str()))
            .count(),
        2
    );
}

#[tokio::test]
async fn plain_http_request_with_a_revoked_token_is_audited_and_not_forwarded() {
    let env = env(60_000).await;
    let up = spawn_plain_upstream().await;
    let (tok, jti) = revoked_token(&env, "laptop", "developer");
    let raw = format!(
        "POST http://127.0.0.1:{}/v1/x?api_key=SECRET HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        up.addr.port(),
        up.addr.port(),
        basic(&tok)
    );
    let resp = exchange(&env, raw.as_bytes()).await;
    assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");
    assert_eq!(up.count(), 0, "nothing may be forwarded");
    let r = rows(&env);
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(
        (r[0].decision.as_str(), r[0].status, r[0].method.as_str()),
        ("token-invalid", Some(407), "POST")
    );
    assert_eq!(r[0].jti.as_deref(), Some(jti.as_str()));
    assert_eq!(r[0].host, "127.0.0.1");
    assert_eq!(r[0].path, "/");
    assert!(!format!("{:?}", r[0]).contains("SECRET"));
}
