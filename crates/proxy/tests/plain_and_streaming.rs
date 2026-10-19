//! Plain `http://` proxying, body streaming and robustness (Task 9).
mod common;
use common::*;
use sg_policy::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const HOST: &str = "api.example.test";

/// Sends `raw` to the proxy port and reads until the connection closes (a reset is tolerated).
async fn raw_exchange(env: &Env, raw: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    out
}

fn text_of(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_string()
}

fn status(raw: &str) -> &str {
    raw.lines().next().unwrap_or("")
}

fn body_of(raw: &str) -> &str {
    raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
}

/// `GET` in absolute form with `Connection: close`.
async fn plain_get(env: &Env, token: &str, target: &str, host_hdr: &str) -> String {
    plain_req(env, Some(token), "GET", target, host_hdr, &[]).await
}

async fn plain_req(
    env: &Env,
    token: Option<&str>,
    method: &str,
    target: &str,
    host_hdr: &str,
    extra: &[(&str, &str)],
) -> String {
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: {host_hdr}\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Proxy-Authorization: {}\r\n", basic(t)));
    }
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    text_of(&raw_exchange(env, req.as_bytes()).await)
}

fn header_rule(env: &Env, role: &str, host: &str, name: &str, template: &str, secret: &str) {
    let s = env.vault.add_secret(&format!("k-{host}"), secret).unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: role.into(),
            host_pattern: host.into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: name.into(),
            template: template.into(),
            secret_id: s.id,
        },
    )
    .unwrap();
}

fn decisions(env: &Env) -> Vec<(String, Option<u16>)> {
    let mut rows = env.vault.list_audit(&Default::default()).unwrap();
    rows.reverse();
    rows.into_iter().map(|r| (r.decision, r.status)).collect()
}

async fn plain_env(host: &str) -> (Env, TestUpstream) {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert(host.into(), up.addr);
    (Env::new(cfg).await, up)
}

// --- plaintext refusal and localhost exception ---------------------------------------------

#[tokio::test]
async fn plain_http_to_a_host_with_rules_never_gets_the_secret() {
    let (env, up) = plain_env(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "REAL-SECRET",
    );
    let t = env.token("m", "developer");
    let raw = plain_get(&env, &t, &format!("http://{HOST}/x"), HOST).await;
    assert!(status(&raw).contains("403"), "{raw}");
    assert!(!raw.contains("REAL-SECRET"));
    assert_eq!(up.count(), 0, "nothing may reach the upstream");
    assert_eq!(
        decisions(&env),
        vec![("plaintext-refused".into(), Some(403))]
    );
}

#[tokio::test]
async fn plain_http_with_a_rule_is_refused_even_for_other_methods_and_ports() {
    let (env, up) = plain_env(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "REAL-SECRET",
    );
    let t = env.token("m", "developer");
    for (m, target, host) in [
        (
            "POST",
            format!("http://{HOST}:8080/x"),
            format!("{HOST}:8080"),
        ),
        ("DELETE", format!("http://{HOST}./x"), format!("{HOST}.")),
        (
            "GET",
            "http://API.Example.TEST/x?a=1".to_string(),
            "api.example.test".into(),
        ),
    ] {
        let raw = plain_req(&env, Some(&t), m, &target, &host, &[]).await;
        assert!(status(&raw).contains("403"), "{m} {target}: {raw}");
    }
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn plain_http_to_localhost_with_a_rule_is_refused_never_injected() {
    let up = spawn_plain_upstream().await;
    let mut cfg = strict_upstream();
    cfg.resolve_override.insert("localhost".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Deny).unwrap();
    header_rule(
        &env,
        "developer",
        "localhost",
        "X-Api-Key",
        "{secret}",
        "LOCAL-SECRET",
    );
    let t = env.token("m", "developer");
    for (m, target, host) in [
        (
            "GET",
            "http://localhost/ping".to_string(),
            "localhost".to_string(),
        ),
        (
            "POST",
            "http://localhost/ping".to_string(),
            "localhost".to_string(),
        ),
        (
            "GET",
            format!("http://localhost:{}/ping", up.addr.port()),
            format!("localhost:{}", up.addr.port()),
        ),
        (
            "GET",
            "http://LOCALHOST/ping".to_string(),
            "localhost".to_string(),
        ),
        (
            "GET",
            "http://localhost./ping".to_string(),
            "localhost.".to_string(),
        ),
    ] {
        let raw = plain_req(&env, Some(&t), m, &target, &host, &[]).await;
        assert!(status(&raw).contains("403"), "{m} {target}: {raw}");
        assert!(!raw.contains("LOCAL-SECRET"));
    }
    assert_eq!(up.count(), 0, "nothing may reach the local service");
    assert!(decisions(&env)
        .iter()
        .all(|d| *d == ("plaintext-refused".to_string(), Some(403))));
    assert_eq!(decisions(&env).len(), 5);
}

#[tokio::test]
async fn an_agent_listener_on_an_arbitrary_port_receives_nothing_and_no_secret() {
    // The agent opens its own loopback listener and asks for http://localhost:PORT/.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let (received, accepted) = (received.clone(), accepted.clone());
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let received = received.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        received.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                });
            }
        });
    }
    // The override supplies only the IP (port 0): the requested port is kept, so without the
    // refusal the secret WOULD reach the listener.
    let mut cfg = strict_upstream();
    cfg.resolve_override
        .insert("localhost".into(), "127.0.0.1:0".parse().unwrap());
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        "localhost",
        "X-Api-Key",
        "{secret}",
        "LOCAL-SECRET",
    );
    let t = env.token("m", "developer");
    let raw = plain_get(
        &env,
        &t,
        &format!("http://localhost:{port}/"),
        &format!("localhost:{port}"),
    )
    .await;
    assert!(status(&raw).contains("403"), "{raw}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(received.lock().unwrap().is_empty());
    assert_eq!(
        decisions(&env),
        vec![("plaintext-refused".into(), Some(403))]
    );
}

#[tokio::test]
async fn resolve_override_with_port_zero_keeps_the_requested_port() {
    // Sanity check of the test helper behaviour used above: a role with no rules for the host
    // and allow_loopback reaches the listener on the REQUESTED port.
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override
        .insert("free.example.test".into(), "127.0.0.1:0".parse().unwrap());
    let env = Env::new(cfg).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let port = up.addr.port();
    let raw = plain_get(
        &env,
        &t,
        &format!("http://free.example.test:{port}/a"),
        &format!("free.example.test:{port}"),
    )
    .await;
    assert!(status(&raw).contains("200"), "{raw}");
    assert_eq!(up.count(), 1);
}

#[tokio::test]
async fn plain_localhost_without_a_rule_does_not_reach_loopback() {
    let up = spawn_plain_upstream().await;
    let mut cfg = strict_upstream();
    cfg.resolve_override.insert("localhost".into(), up.addr);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_get(&env, &t, "http://localhost/ping", "localhost").await;
    assert!(status(&raw).contains("403"), "{raw}");
    assert_eq!(up.count(), 0);
}

// --- unmatched policy ----------------------------------------------------------------------

#[tokio::test]
async fn plain_http_without_rules_follows_the_unmatched_policy_and_is_audited() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    add_role(&env.vault, "closed", Unmatched::Deny).unwrap();
    let open = env.token("m", "open");
    let closed = env.token("m", "closed");
    let url = "http://free.example.test/a";
    assert!(status(&plain_get(&env, &open, url, "free.example.test").await).contains("200"));
    assert!(status(&plain_get(&env, &closed, url, "free.example.test").await).contains("403"));
    assert_eq!(up.count(), 1);
    assert!(up.header(0, "authorization").is_empty());
    assert_eq!(
        decisions(&env),
        vec![
            ("passthrough".into(), Some(200)),
            ("unmatched-denied".into(), Some(403))
        ]
    );
}

#[tokio::test]
async fn a_token_for_a_deleted_role_gets_403_on_plain_requests() {
    let (env, up) = plain_env("free.example.test").await;
    let t = env.token("m", "ghost");
    let raw = plain_get(&env, &t, "http://free.example.test/a", "free.example.test").await;
    assert!(status(&raw).contains("403"), "{raw}");
    assert_eq!(up.count(), 0);
    assert_eq!(decisions(&env), vec![("unknown-role".into(), Some(403))]);
}

// --- request shape --------------------------------------------------------------------------

#[tokio::test]
async fn non_absolute_form_and_non_http_schemes_get_400() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    for target in [
        "/x",
        "https://free.example.test/x",
        "ftp://free.example.test/x",
        "*",
    ] {
        let raw = plain_get(&env, &t, target, "free.example.test").await;
        assert!(status(&raw).contains("400"), "{target}: {raw}");
    }
    // userinfo in the authority is never legitimate.
    let raw = plain_get(
        &env,
        &t,
        "http://user:pw@free.example.test/x",
        "free.example.test",
    )
    .await;
    assert!(status(&raw).contains("400"), "{raw}");
    assert_eq!(up.count(), 0);
    // Authenticated 400s are audited with the identity.
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert_eq!(rows.len(), 5, "{rows:?}");
    for r in &rows {
        assert_eq!(r.decision, "bad-request");
        assert_eq!(r.status, Some(400));
        assert_eq!(r.machine.as_deref(), Some("m"));
        assert_eq!(r.role.as_deref(), Some("open"));
        assert!(r.jti.is_some());
    }
}

#[tokio::test]
async fn proxy_authorization_is_required_and_stripped() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let url = "http://free.example.test/a";
    let raw = plain_req(&env, None, "GET", url, "free.example.test", &[]).await;
    assert!(status(&raw).contains("407"), "{raw}");
    assert!(raw.to_lowercase().contains("proxy-authenticate"));
    let raw = plain_req(&env, Some("garbage"), "GET", url, "free.example.test", &[]).await;
    assert!(status(&raw).contains("407"), "{raw}");
    assert_eq!(up.count(), 0);
    assert!(
        decisions(&env).is_empty(),
        "unauthenticated requests are not role-audited"
    );

    assert!(status(&plain_get(&env, &t, url, "free.example.test").await).contains("200"));
    assert!(up.header(0, "proxy-authorization").is_empty());
    assert!(!up.received.lock().unwrap()[0]
        .headers
        .iter()
        .any(|(_, v)| v.contains(&t)));
}

#[tokio::test]
async fn host_header_that_disagrees_with_the_authority_gets_421() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_get(&env, &t, "http://free.example.test/a", "other.example.test").await;
    assert!(status(&raw).contains("421"), "{raw}");
    assert_eq!(up.count(), 0);
    assert_eq!(decisions(&env), vec![("host-mismatch".into(), Some(421))]);
}

#[tokio::test]
async fn plain_requests_strip_hop_by_hop_and_routing_headers() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_req(
        &env,
        Some(&t),
        "GET",
        "http://free.example.test/a",
        "free.example.test",
        &[
            ("Keep-Alive", "timeout=5"),
            ("Proxy-Foo", "1"),
            ("TE", "trailers"),
            ("Upgrade", "websocket"),
            ("X-Nominated", "1"),
            ("Connection", "x-nominated"),
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-Forwarded-For", "6.6.6.6"),
            ("X-Original-URL", "/admin"),
            ("Forwarded", "for=evil"),
            ("X-Keep", "yes"),
        ],
    )
    .await;
    assert!(status(&raw).contains("200"), "{raw}");
    for h in [
        "keep-alive",
        "proxy-foo",
        "te",
        "upgrade",
        "x-nominated",
        "x-http-method-override",
        "x-forwarded-for",
        "x-original-url",
        "forwarded",
        "proxy-authorization",
    ] {
        assert!(up.header(0, h).is_empty(), "{h} reached the upstream");
    }
    assert_eq!(up.header(0, "x-keep"), vec!["yes".to_string()]);
    // The upstream sent hop-by-hop headers back; they must not reach the agent.
    let lower = raw.to_lowercase();
    assert!(lower.contains("x-up: 1"));
    assert!(!lower.contains("keep-alive: timeout=5"), "{raw}");
    assert!(!lower.contains("proxy-foo"), "{raw}");
}

#[tokio::test]
async fn trace_and_connect_style_methods_are_refused_on_plain_requests() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_req(
        &env,
        Some(&t),
        "TRACE",
        "http://free.example.test/a",
        "free.example.test",
        &[],
    )
    .await;
    assert!(status(&raw).contains("405"), "{raw}");
    assert_eq!(up.count(), 0);
    assert_eq!(decisions(&env), vec![("method-refused".into(), Some(405))]);
}

#[tokio::test]
async fn head_and_responses_without_body_work() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_req(
        &env,
        Some(&t),
        "HEAD",
        "http://free.example.test/a",
        "free.example.test",
        &[],
    )
    .await;
    assert!(status(&raw).contains("200"), "{raw}");
    assert_eq!(body_of(&raw), "", "HEAD must not carry a body: {raw}");
    assert_eq!(up.received.lock().unwrap()[0].method, "HEAD");
}

#[tokio::test]
async fn head_through_the_mitm_works() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");
    let r = proxy_request(&env, &t, HOST, "HEAD", "/a", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "");
    assert_eq!(up.received.lock().unwrap()[0].method, "HEAD");
}

#[tokio::test]
async fn expect_100_continue_does_not_hang() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let head = format!(
        "POST http://free.example.test/up HTTP/1.1\r\nHost: free.example.test\r\nProxy-Authorization: {}\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        basic(&t)
    );
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    s.write_all(head.as_bytes()).await.unwrap();
    // The interim response (or the final one) must arrive without us sending the body first.
    let mut first = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut first))
        .await
        .expect("proxy must answer Expect: 100-continue")
        .unwrap();
    assert!(
        text_of(&first[..n]).starts_with("HTTP/1.1 100"),
        "{}",
        text_of(&first[..n])
    );
    s.write_all(b"hello").await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_to_end(&mut rest))
        .await
        .expect("final response")
        .ok();
    assert!(text_of(&rest).contains("200"), "{}", text_of(&rest));
    assert_eq!(up.received.lock().unwrap()[0].body_len, 5);
}

#[tokio::test]
async fn chunked_request_bodies_work_on_plain_requests() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let req = format!(
        "POST http://free.example.test/up HTTP/1.1\r\nHost: free.example.test\r\nProxy-Authorization: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        basic(&t)
    );
    let raw = text_of(&raw_exchange(&env, req.as_bytes()).await);
    assert!(status(&raw).contains("200"), "{raw}");
    assert_eq!(up.received.lock().unwrap()[0].body_len, 11);
}

#[tokio::test]
async fn chunked_request_bodies_work_through_the_mitm() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");
    let raw = format!(
        "POST /up HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    );
    let r = proxy_raw_request(&env, &t, HOST, raw.as_bytes()).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap()[0].body_len, 11);
    assert_eq!(up.header(0, "authorization"), vec!["Bearer v".to_string()]);
}

// --- streaming ------------------------------------------------------------------------------

#[tokio::test]
async fn large_request_body_streams_through_the_mitm() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");
    let body = vec![7u8; 8 * 1024 * 1024];
    let r = proxy_request(&env, &t, HOST, "POST", "/upload", &[], body, false).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap()[0].body_len, 8 * 1024 * 1024);
}

#[tokio::test]
async fn large_response_body_streams_back_through_the_mitm() {
    let (env, _up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");
    let r = proxy_request(&env, &t, HOST, "GET", "/big", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), 8 * 1024 * 1024);
}

#[tokio::test]
async fn large_bodies_stream_through_plain_requests() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let mut req = format!(
        "POST http://free.example.test/up HTTP/1.1\r\nHost: free.example.test\r\nProxy-Authorization: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        basic(&t),
        8 * 1024 * 1024
    )
    .into_bytes();
    req.extend(vec![7u8; 8 * 1024 * 1024]);
    let raw = text_of(&raw_exchange(&env, &req).await);
    assert!(status(&raw).contains("200"), "{}", status(&raw));
    assert_eq!(up.received.lock().unwrap()[0].body_len, 8 * 1024 * 1024);

    let raw = plain_get(
        &env,
        &t,
        "http://free.example.test/big",
        "free.example.test",
    )
    .await;
    assert!(status(&raw).contains("200"));
    // chunked framing adds overhead; the payload itself must be complete
    assert!(raw.matches('b').count() >= 8 * 1024 * 1024);
}

// --- robustness -----------------------------------------------------------------------------

#[tokio::test]
async fn fifty_concurrent_requests_over_tunnels_and_plain_all_succeed() {
    let up_tls = spawn_tls_upstream(HOST).await;
    let up_plain = spawn_plain_upstream().await;
    let mut cfg = sg_proxy::UpstreamConfig::new(vec![up_tls.ca_der.clone()]);
    cfg.net_policy.allow_loopback = true;
    cfg.resolve_override.insert(HOST.into(), up_tls.addr);
    cfg.resolve_override
        .insert("free.example.test".into(), up_plain.addr);
    let env = std::sync::Arc::new(Env::new(cfg).await);
    env.ca.allow_domain(HOST).unwrap();
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");

    let mut tasks = Vec::new();
    for i in 0..50 {
        let (env, t) = (env.clone(), t.clone());
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let r = proxy_request(&env, &t, HOST, "GET", &format!("/m{i}"), &[], vec![], false)
                    .await;
                r.status
            } else {
                let raw = plain_get(
                    &env,
                    &t,
                    &format!("http://free.example.test/p{i}"),
                    "free.example.test",
                )
                .await;
                status(&raw)
                    .split(' ')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
            }
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }
    let rows = env
        .vault
        .list_audit(&sg_core::audit::AuditFilter {
            limit: 500,
            ..Default::default()
        })
        .unwrap();
    let mitm: Vec<_> = rows.iter().filter(|r| r.decision == "inject").collect();
    let plain: Vec<_> = rows
        .iter()
        .filter(|r| r.decision == "passthrough" && r.method == "GET")
        .collect();
    assert_eq!(mitm.len(), 25);
    assert_eq!(plain.len(), 25);
    for r in mitm.iter().chain(plain.iter()) {
        assert_eq!(r.status, Some(200));
        assert_eq!(r.role.as_deref(), Some("developer"));
        assert_eq!(r.machine.as_deref(), Some("m"));
        assert!(r.jti.is_some());
    }
    assert_eq!(up_tls.count(), 25);
    assert_eq!(up_plain.count(), 25);
}

#[tokio::test]
async fn upstream_dying_mid_response_truncates_without_killing_the_proxy() {
    let (env, up) = plain_env("free.example.test").await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_get(
        &env,
        &t,
        "http://free.example.test/abort",
        "free.example.test",
    )
    .await;
    assert!(status(&raw).contains("200"), "{raw}");
    // the agent must see an incomplete chunked body, never a clean terminator
    assert!(
        !raw.ends_with("0\r\n\r\n"),
        "response must not look complete: {raw:?}"
    );
    // the status that was actually sent is what is audited
    assert_eq!(decisions(&env), vec![("passthrough".into(), Some(200))]);
    assert_eq!(up.count(), 1);
    // the proxy keeps serving
    let raw = plain_get(&env, &t, "http://free.example.test/ok", "free.example.test").await;
    assert!(raw.ends_with("ok") || raw.contains("\r\nok"), "{raw}");
}

#[tokio::test]
async fn upstream_dying_mid_response_through_the_mitm_is_aborted() {
    let (env, _up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    header_rule(
        &env,
        "developer",
        HOST,
        "Authorization",
        "Bearer {secret}",
        "v",
    );
    let t = env.token("m", "developer");
    let raw = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"/abort")).await;
    assert_eq!(raw.status, 200);
    assert!(!raw.body.ends_with("0\r\n\r\n"), "{:?}", raw.body);
    assert_eq!(
        decisions(&env).last().unwrap(),
        &("inject".into(), Some(200))
    );
    let r = proxy_request(&env, &t, HOST, "GET", "/ok", &[], vec![], false).await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn unreachable_plain_upstream_is_502_and_audited() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let mut cfg = no_extra_roots();
    cfg.resolve_override
        .insert("free.example.test".into(), dead);
    let env = Env::new(cfg).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = plain_get(&env, &t, "http://free.example.test/a", "free.example.test").await;
    assert!(status(&raw).contains("502"), "{raw}");
    assert_eq!(decisions(&env), vec![("upstream-error".into(), Some(502))]);
}

// --- plain and MITM agree --------------------------------------------------------------------

#[tokio::test]
async fn plain_and_mitm_paths_produce_the_same_decisions() {
    // Situation 1: unruled host, passthrough role. Situation 2: unruled host, deny role is a
    // CONNECT-time decision on both paths ("unmatched-denied"). Situation 3: TRACE.
    let (up_tls, up_plain) = (spawn_tls_upstream(HOST).await, spawn_plain_upstream().await);
    let mut cfg = sg_proxy::UpstreamConfig::new(vec![up_tls.ca_der.clone()]);
    cfg.net_policy.allow_loopback = true;
    cfg.resolve_override
        .insert("free.example.test".into(), up_plain.addr);
    cfg.resolve_override.insert(HOST.into(), up_tls.addr);
    let env = Env::new(cfg).await;
    env.ca.allow_domain(HOST).unwrap();
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    add_role(&env.vault, "closed", Unmatched::Deny).unwrap();
    add_role(&env.vault, "ruled", Unmatched::Passthrough).unwrap();
    header_rule(&env, "ruled", HOST, "Authorization", "Bearer {secret}", "v");
    let (open, closed, ruled) = (
        env.token("m", "open"),
        env.token("m", "closed"),
        env.token("m", "ruled"),
    );

    // deny role, unruled host
    let plain = plain_get(
        &env,
        &closed,
        "http://free.example.test/a",
        "free.example.test",
    )
    .await;
    assert!(status(&plain).contains("403"));
    assert!(tunnel_tls(&env, &closed, "free.example.test", false)
        .await
        .is_err());
    // passthrough role, unruled host: plain forwards, CONNECT tunnels
    assert!(status(
        &plain_get(
            &env,
            &open,
            "http://free.example.test/a",
            "free.example.test"
        )
        .await
    )
    .contains("200"));
    // ruled host: the secret is injected over MITM, refused over plain
    let plain = plain_get(&env, &ruled, &format!("http://{HOST}/a"), HOST).await;
    assert!(status(&plain).contains("403"));
    assert_eq!(
        proxy_request(&env, &ruled, HOST, "GET", "/a", &[], vec![], false)
            .await
            .status,
        200
    );
    // TRACE refused on both
    let plain = plain_req(
        &env,
        Some(&open),
        "TRACE",
        "http://free.example.test/a",
        "free.example.test",
        &[],
    )
    .await;
    assert!(status(&plain).contains("405"));

    let d: Vec<String> = decisions(&env).into_iter().map(|(d, _)| d).collect();
    assert_eq!(
        d,
        vec![
            "unmatched-denied",  // plain, deny role
            "unmatched-denied",  // CONNECT, deny role
            "passthrough",       // plain, open role
            "plaintext-refused", // plain, ruled host
            "mitm",              // CONNECT to the ruled host
            "inject",            // request inside the tunnel
            "method-refused",    // TRACE
        ]
    );
}

// --- body progress timeout on plain requests -----------------------------------------------

async fn plain_env_opts(
    host: &str,
    opts: sg_proxy::ServeOptions,
    tweak: impl FnOnce(&mut sg_proxy::UpstreamConfig),
) -> (Env, TestUpstream) {
    let up = spawn_plain_upstream().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert(host.into(), up.addr);
    tweak(&mut cfg);
    (Env::custom(cfg, opts, None).await, up)
}

/// Writes `raw` and reads only until the end of the response head.
async fn send_and_read_head(env: &Env, raw: &[u8]) -> (String, TcpStream) {
    raw_head(env.proxy_addr, raw).await
}

#[tokio::test]
async fn a_plain_client_that_never_reads_the_body_is_cut_off_and_frees_the_slot() {
    let opts = sg_proxy::ServeOptions {
        body_idle_timeout: std::time::Duration::from_millis(700),
        ..Default::default()
    };
    let (env, _up) = plain_env_opts("free.example.test", opts, |c| {
        c.max_upstream_connections = 1;
        c.connect_timeout = std::time::Duration::from_millis(500);
    })
    .await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = format!(
        "GET http://free.example.test/endless HTTP/1.1\r\nHost: free.example.test\r\nProxy-Authorization: {}\r\n\r\n",
        basic(&t)
    );
    let (head, mut stalled) = send_and_read_head(&env, raw.as_bytes()).await;
    assert!(head.contains("200"), "{head}");
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let r = plain_get(&env, &t, "http://free.example.test/x", "free.example.test").await;
    assert!(status(&r).contains("200"), "{r}");
    // Draining what is buffered ends with the connection closed, not with an endless body.
    let drained = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stalled.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "the stalled plain body was never aborted");
}

#[tokio::test]
async fn a_slow_but_progressing_plain_body_is_not_cut() {
    let opts = sg_proxy::ServeOptions {
        body_idle_timeout: std::time::Duration::from_millis(1000),
        ..Default::default()
    };
    let (env, _up) = plain_env_opts("free.example.test", opts, |_| {}).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let started = std::time::Instant::now();
    let raw = plain_get(
        &env,
        &t,
        "http://free.example.test/drip",
        "free.example.test",
    )
    .await;
    assert!(status(&raw).contains("200"), "{raw}");
    assert!(
        started.elapsed() > std::time::Duration::from_millis(1500),
        "the body must outlive the idle timeout"
    );
    assert_eq!(raw.matches("chunk\n").count(), 6, "{raw}");
}

#[tokio::test]
async fn a_request_body_that_stops_moving_is_aborted_with_502() {
    let opts = sg_proxy::ServeOptions {
        body_idle_timeout: std::time::Duration::from_millis(700),
        ..Default::default()
    };
    let (env, up) = plain_env_opts("free.example.test", opts, |_| {}).await;
    add_role(&env.vault, "open", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "open");
    let raw = format!(
        "POST http://free.example.test/up HTTP/1.1\r\nHost: free.example.test\r\nProxy-Authorization: {}\r\nContent-Length: 1000\r\n\r\nabc",
        basic(&t)
    );
    let mut s = TcpStream::connect(env.proxy_addr).await.unwrap();
    s.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut buf = [0u8; 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
    })
    .await;
    assert!(
        res.is_ok(),
        "the stalled request body held the request forever"
    );
    let head = text_of(&out);
    assert!(status(&head).contains("502"), "{head}");
    assert_eq!(
        up.count(),
        0,
        "an incomplete body must never complete upstream"
    );
    assert!(decisions(&env).contains(&("upstream-error".into(), Some(502))));
}
