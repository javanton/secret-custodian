//! Audit on cancellation, fail-closed rule loading, original-path forwarding and header
//! injection look-alikes.
mod common;
use common::*;
use sg_policy::*;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const HOST: &str = "api.example.test";

fn rule(host: &str, path: &str, kind: InjectionKind, target: &str, secret_id: i64) -> NewRule {
    NewRule {
        role: "developer".into(),
        host_pattern: host.into(),
        path_pattern: path.into(),
        methods: vec![],
        kind,
        target_name: target.into(),
        template: if kind == InjectionKind::Header {
            "Bearer {secret}".into()
        } else {
            "{secret}".into()
        },
        secret_id,
    }
}

/// Role `developer` (passthrough) with one header rule on `HOST` for `path`.
fn setup_rule(env: &Env, path: &str, target: &str) -> String {
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(
        &env.vault,
        rule(HOST, path, InjectionKind::Header, target, s.id),
    )
    .unwrap();
    env.token("laptop", "developer")
}

fn rows_for(env: &Env, method: &str) -> Vec<sg_core::audit::AuditEntry> {
    env.vault
        .list_audit(&Default::default())
        .unwrap()
        .into_iter()
        .filter(|r| r.method == method)
        .collect()
}

async fn until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

// ---- 1. audit on cancellation -------------------------------------------------------------

#[tokio::test]
async fn a_request_cancelled_while_in_flight_is_audited_once_as_client_aborted() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    let mut tls = tunnel_tls(&env, &t, HOST, false).await.ok().unwrap();
    tls.write_all(&raw_get(HOST, b"/slow")).await.unwrap();
    // The upstream has the request (so the credential was sent) and now stalls.
    assert!(until(|| up.count() == 1).await, "upstream never got it");
    assert!(rows_for(&env, "GET").is_empty(), "nothing audited yet");
    drop(tls);
    assert!(
        until(|| !rows_for(&env, "GET").is_empty()).await,
        "no audit row after the client went away"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let rows = rows_for(&env, "GET");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let r = &rows[0];
    assert_eq!(r.decision, "client-aborted");
    assert_eq!(r.status, None);
    assert_eq!(r.host, HOST);
    assert_eq!(r.path, "/slow");
    assert_eq!(r.machine.as_deref(), Some("laptop"));
    assert_eq!(r.role.as_deref(), Some("developer"));
    assert!(r.jti.is_some());
    assert!(r.rule_id.is_some());
    assert_eq!(
        up.header(0, "authorization"),
        vec!["Bearer REAL-SECRET".to_string()]
    );
}

#[tokio::test]
async fn a_cancelled_h2_request_is_audited_once_as_client_aborted() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    let tls = tunnel_tls(&env, &t, HOST, true).await.ok().unwrap();
    let (mut s, c) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    let conn = tokio::spawn(c);
    let req = hyper::Request::builder()
        .uri(format!("https://{HOST}/slow"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let pending = tokio::spawn(async move { s.send_request(req).await });
    assert!(until(|| up.count() == 1).await);
    pending.abort();
    conn.abort();
    assert!(until(|| !rows_for(&env, "GET").is_empty()).await);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let rows = rows_for(&env, "GET");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].decision, "client-aborted");
}

#[tokio::test]
async fn completed_and_failed_forwards_write_exactly_one_row() {
    let (env, _up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    let r = proxy_request(&env, &t, HOST, "GET", "/ok", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    let rows = rows_for(&env, "GET");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].decision.as_str(), rows[0].status),
        ("inject", Some(200))
    );

    // Upstream error: the origin address refuses connections.
    let dead = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let (env2, _up2) = env_with_upstream_cfg(HOST, |c| {
        c.resolve_override.insert(HOST.to_string(), dead);
    })
    .await;
    let t2 = setup_rule(&env2, "*", "Authorization");
    let r = proxy_request(&env2, &t2, HOST, "GET", "/x", &[], vec![], false).await;
    assert_eq!(r.status, 502);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rows = rows_for(&env2, "GET");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].decision.as_str(), rows[0].status),
        ("upstream-error", Some(502))
    );
}

// ---- 2. fail closed on rule-load errors ---------------------------------------------------

fn break_table(env: &Env, table: &str) {
    env.vault
        .conn()
        .execute_batch(&format!("DROP TABLE {table}"))
        .unwrap();
}

async fn plain_raw(env: &Env, token: &str, target: &str) -> String {
    let host = target
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap();
    let req = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
        basic(token)
    );
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out).to_string()
}

#[tokio::test]
async fn connect_and_plain_fail_closed_when_rules_cannot_be_loaded() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "/v1/*", "Authorization");
    let (echo, hits) = counting_listener().await;
    break_table(&env, "rules");

    // Passthrough role: a vault failure must not turn into "no rules, tunnel it".
    for authority in [format!("{HOST}:443"), echo.to_string()] {
        let (line, _s) = raw_connect(env.proxy_addr, &authority, Some(&basic(&t))).await;
        assert!(line.contains("503"), "{authority}: {line}");
    }
    let resp = plain_raw(&env, &t, &format!("http://{HOST}/x")).await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
    assert!(resp.contains("service unavailable"));
    let resp = plain_raw(&env, &t, &format!("http://{echo}/x")).await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(up.count(), 0);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 4, "{rows:?}");
    assert!(rows.iter().all(|r| r.decision == "internal-error"));
    assert!(rows.iter().all(|r| r.status == Some(503)));
    assert!(rows.iter().all(|r| r.machine.as_deref() == Some("laptop")));
}

#[tokio::test]
async fn connect_and_plain_fail_closed_when_the_role_cannot_be_loaded() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    break_table(&env, "roles");
    let (line, _s) = raw_connect(env.proxy_addr, &format!("{HOST}:443"), Some(&basic(&t))).await;
    assert!(line.contains("503"), "{line}");
    let resp = plain_raw(&env, &t, &format!("http://{HOST}/x")).await;
    assert!(resp.starts_with("HTTP/1.1 503"), "{resp}");
    assert_eq!(up.count(), 0);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(
        rows.iter().all(|r| r.decision == "internal-error"),
        "{rows:?}"
    );
}

#[tokio::test]
async fn an_open_tunnel_fails_closed_when_rules_stop_loading() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    let mut tun = open_tunnel(&env, &t, HOST).await;
    assert_eq!(tun.request("GET", "/ok", &[]).await.status, 200);
    break_table(&env, "rules");
    let r = tun.request("GET", "/after", &[]).await;
    assert_eq!(r.status, 503);
    assert!(r.body.contains("service unavailable"));
    assert_eq!(up.count(), 1);
    let rows = rows_for(&env, "GET");
    assert_eq!(rows.first().unwrap().decision, "internal-error");
    assert_eq!(rows.first().unwrap().status, Some(503));
}

// ---- 5. forwarded path --------------------------------------------------------------------

#[tokio::test]
async fn star_rule_forwards_the_original_path_untouched() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "Authorization");
    for (i, (sent, want)) in [
        ("//a/./b//c", "//a/./b//c"),
        ("/fetch/https://other.site/x", "/fetch/https://other.site/x"),
        ("/k/%7Eb/%2e/c?x=%7E&y=//", "/k/%7Eb/%2e/c?x=%7E&y=//&_"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, sent.as_bytes())).await;
        assert_eq!(r.status, 200, "{sent}: {}", r.body);
        let got = up.received.lock().unwrap()[i].uri.clone();
        let want = want.trim_end_matches("&_");
        assert_eq!(got, want, "sent {sent}");
    }
    // A `//host`-looking path stays a path: the Host is untouched.
    let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"//evil.test/x")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let rec = up.received.lock().unwrap().last().unwrap().clone();
    assert_eq!(rec.uri, "//evil.test/x");
    assert!(rec.headers.iter().any(|(k, v)| k == "host" && v == HOST));
}

#[tokio::test]
async fn restricted_rule_forwards_the_judged_path() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "/a/*", "Authorization");
    let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"//a/./b//c?q=1")).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(up.received.lock().unwrap()[0].uri, "/a/b/c?q=1");
    // Witnesses stay forbidden and never reach the origin.
    for p in ["/a/../admin", "/a/%2e%2e/admin", "/a/%EF%B8%B0/x", "/b/x"] {
        let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, p.as_bytes())).await;
        assert_eq!(r.status, 403, "{p}");
    }
    assert_eq!(up.count(), 1);
}

#[tokio::test]
async fn unruled_host_under_a_passthrough_role_keeps_its_original_path() {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override
        .insert("plain.example.test".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("laptop", "developer");
    let resp = plain_raw(&env, &t, "http://plain.example.test//a/./b//c?z=%7E").await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert_eq!(up.received.lock().unwrap()[0].uri, "//a/./b//c?z=%7E");
}

// ---- 6. header injection look-alikes ------------------------------------------------------

#[tokio::test]
async fn lookalike_header_names_of_the_injected_header_never_reach_the_origin() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = setup_rule(&env, "*", "X-Api-Key");
    let raw = format!(
        "GET /x HTTP/1.1\r\nHost: {HOST}\r\nX_Api_Key: agent1\r\nx_api_key: agent2\r\nX-API-KEY: agent3\r\nx-api_KEY: agent4\r\nX-Other: keep\r\nConnection: close\r\n\r\n"
    );
    let r = proxy_raw_request(&env, &t, HOST, raw.as_bytes()).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let rec = up.received.lock().unwrap()[0].clone();
    let keys: Vec<_> = rec
        .headers
        .iter()
        .filter(|(k, _)| k.to_ascii_lowercase().replace('_', "-") == "x-api-key")
        .collect();
    assert_eq!(keys.len(), 1, "{:?}", rec.headers);
    assert_eq!(keys[0].1, "Bearer REAL-SECRET");
    assert!(rec
        .headers
        .iter()
        .any(|(k, v)| k == "x-other" && v == "keep"));
}
