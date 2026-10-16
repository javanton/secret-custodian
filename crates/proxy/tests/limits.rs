//! Connection cap, tunnel timeouts and the upstream connection cap.
mod common;
use common::*;
use sg_policy::*;
use sg_proxy::ServeOptions;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HOST: &str = "api.example.test";

fn add_header_rule(env: &Env) -> String {
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: HOST.into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "Authorization".into(),
            template: "Bearer {secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    env.token("laptop", "developer")
}

#[tokio::test]
async fn an_open_mitm_tunnel_keeps_its_connection_slot() {
    let opts = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let tunnel = open_tunnel(&env, &t, HOST).await; // authenticated, idle, holds the only slot

    let addr = env.proxy_addr;
    let auth = basic(&t);
    let mut second =
        tokio::spawn(async move { raw_connect(addr, &format!("{HOST}:443"), Some(&auth)).await });
    let waited = tokio::time::timeout(Duration::from_millis(600), &mut second).await;
    assert!(
        waited.is_err(),
        "second client was served while the tunnel held the slot"
    );
    drop(tunnel);
    let (line, _s) = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .expect("second client must be served after the first tunnel closes")
        .unwrap();
    assert!(line.contains("200"), "{line}");
}

#[tokio::test]
async fn a_passthrough_tunnel_keeps_its_connection_slot() {
    let opts = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, tunnel) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"));
    let addr = env.proxy_addr;
    let auth = basic(&t);
    let target = echo.to_string();
    let mut second = tokio::spawn(async move { raw_connect(addr, &target, Some(&auth)).await });
    assert!(
        tokio::time::timeout(Duration::from_millis(600), &mut second)
            .await
            .is_err()
    );
    drop(tunnel);
    let (line, _s) = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .unwrap()
        .unwrap();
    assert!(line.contains("200"), "{line}");
}

#[tokio::test]
async fn a_tunnel_that_never_sends_a_client_hello_is_closed() {
    let opts = ServeOptions {
        header_read_timeout: Duration::from_millis(500),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let (line, mut s) = raw_connect(env.proxy_addr, &format!("{HOST}:443"), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    let started = Instant::now();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .expect("proxy kept a TLS-less tunnel open")
        .ok();
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn an_idle_passthrough_tunnel_is_closed_after_the_idle_timeout() {
    let opts = ServeOptions {
        tunnel_idle_timeout: Duration::from_millis(500),
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, mut s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"));
    s.write_all(b"ping").await.unwrap();
    let mut b = [0u8; 4];
    s.read_exact(&mut b).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut rest))
        .await
        .expect("idle passthrough tunnel was not closed")
        .ok();
}

#[tokio::test]
async fn max_lifetime_closes_a_busy_passthrough_tunnel() {
    let opts = ServeOptions {
        tunnel_max_lifetime: Duration::from_millis(800),
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let echo = echo_server().await;
    let t = env.token("m", "developer");
    let (line, s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"));
    let (mut r, mut w) = s.into_split();
    tokio::spawn(async move {
        while w.write_all(b"busy").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let started = Instant::now();
    let mut sink = [0u8; 256];
    let closed = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match r.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "busy tunnel outlived its max lifetime");
    assert!(
        started.elapsed() >= Duration::from_millis(600),
        "closed too early"
    );
}

#[tokio::test]
async fn an_idle_mitm_connection_is_closed_after_the_idle_timeout() {
    let opts = ServeOptions {
        tunnel_idle_timeout: Duration::from_millis(500),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let mut tun = open_tunnel(&env, &t, HOST).await;
    assert_eq!(tun.request("GET", "/a", &[]).await.status, 200);
    tokio::time::sleep(Duration::from_millis(1800)).await;
    assert!(tun.try_request("GET", "/b", &[]).await.is_none());
}

async fn h2_get_all(env: &Env, token: &str, paths: &[&'static str]) -> Vec<(u16, Duration)> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let tls = tunnel_tls(env, token, HOST, true).await.ok().unwrap();
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let started = Instant::now();
    let mut tasks = Vec::new();
    for p in paths {
        let mut s = sender.clone();
        let p = *p;
        tasks.push(tokio::spawn(async move {
            let req = hyper::Request::builder()
                .uri(format!("https://{HOST}{p}"))
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            let r = s.send_request(req).await.unwrap();
            let status = r.status().as_u16();
            let _ = http_body_util::BodyExt::collect(r.into_body()).await;
            (status, started.elapsed())
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

#[tokio::test]
async fn the_upstream_connection_cap_makes_a_burst_wait_and_then_succeed() {
    let (env, up) = env_with_upstream_cfg(HOST, |c| c.max_upstream_connections = 2).await;
    let t = add_header_rule(&env);
    let started = Instant::now();
    let res = h2_get_all(&env, &t, &["/delay"; 6]).await;
    assert!(res.iter().all(|(s, _)| *s == 200), "{res:?}");
    assert_eq!(up.count(), 6);
    // 6 requests x 300 ms through 2 slots need at least 3 waves.
    assert!(
        started.elapsed() >= Duration::from_millis(850),
        "burst was not limited: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_request_that_cannot_get_an_upstream_slot_in_time_is_502() {
    let (env, _up) = env_with_upstream_cfg(HOST, |c| {
        c.max_upstream_connections = 1;
        c.connect_timeout = Duration::from_millis(300);
        c.response_header_timeout = Duration::from_secs(2);
    })
    .await;
    let t = add_header_rule(&env);
    let res = h2_get_all(&env, &t, &["/slow", "/x"]).await;
    let (second, _) = res[1];
    assert_eq!(second, 502, "{res:?}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "upstream-error" && r.status == Some(502)));
}

// ---- per-identity limits -----------------------------------------------------------------

async fn h2_sender(
    env: &Env,
    token: &str,
) -> hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let tls = tunnel_tls(env, token, HOST, true).await.ok().unwrap();
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    sender
}

fn h2_req(path: &str) -> hyper::Request<http_body_util::Empty<bytes::Bytes>> {
    hyper::Request::builder()
        .uri(format!("https://{HOST}{path}"))
        .body(http_body_util::Empty::new())
        .unwrap()
}

#[tokio::test]
async fn one_identity_cannot_hold_more_tunnels_than_its_cap_nor_starve_another() {
    let opts = ServeOptions {
        max_tunnels_per_identity: 2,
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let a = add_header_rule(&env);
    let b = env.token("other", "developer");
    let echo = echo_server().await;
    let tunnel1 = open_tunnel(&env, &a, HOST).await;
    let (line, _tunnel2) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&a))).await;
    assert!(line.contains("200"), "{line}");

    // Both kinds of tunnel count against the same cap.
    let (head, _) =
        raw_connect_head(env.proxy_addr, &format!("{HOST}:443"), Some(&basic(&a))).await;
    assert!(head.contains(" 429"), "{head}");
    assert!(head.to_lowercase().contains("retry-after: 1"), "{head}");
    let (line, _) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&a))).await;
    assert!(line.contains("429"), "{line}");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows.iter().any(|r| r.decision == "identity-limit"
        && r.status == Some(429)
        && r.method == "CONNECT"
        && r.jti.is_some()));

    // Another identity is still served.
    let (line, _s) = raw_connect(env.proxy_addr, &format!("{HOST}:443"), Some(&basic(&b))).await;
    assert!(line.contains("200"), "{line}");

    // Closing a tunnel frees a slot for the first identity.
    drop(tunnel1);
    let mut served = false;
    for _ in 0..30 {
        let (line, _s) =
            raw_connect(env.proxy_addr, &format!("{HOST}:443"), Some(&basic(&a))).await;
        if line.contains("200") {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "the slot was never released");
}

#[tokio::test]
async fn one_identity_cannot_hold_more_upstream_requests_than_its_cap_nor_starve_another() {
    let opts = ServeOptions {
        max_upstream_per_identity: 2,
        ..ServeOptions::default()
    };
    let (env, up) = env_with_upstream_opts(HOST, opts, |c| {
        c.response_header_timeout = Duration::from_secs(60);
    })
    .await;
    let a = add_header_rule(&env);
    let b = env.token("other", "developer");
    let mut sa = h2_sender(&env, &a).await;
    for _ in 0..2 {
        let mut s = sa.clone();
        tokio::spawn(async move {
            let _ = s.send_request(h2_req("/slow")).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = sa.send_request(h2_req("/x")).await.unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers().get("retry-after").unwrap(), "1");
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "identity-limit" && r.status == Some(429)));
    assert_eq!(up.count(), 2, "the refused request reached the upstream");

    let mut sb = h2_sender(&env, &b).await;
    let r = sb.send_request(h2_req("/x")).await.unwrap();
    assert_eq!(r.status(), 200);
}

// ---- body progress timeout -----------------------------------------------------------------

#[tokio::test]
async fn a_client_that_never_reads_an_h1_response_body_is_cut_off_and_frees_the_slot() {
    let opts = ServeOptions {
        body_idle_timeout: Duration::from_millis(700),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |c| {
        c.max_upstream_connections = 1;
        c.connect_timeout = Duration::from_millis(500);
    })
    .await;
    let t = add_header_rule(&env);
    let mut tun = open_tunnel(&env, &t, HOST).await;
    let stalled = tun.send_streaming("/endless").await;
    assert_eq!(stalled.status(), 200);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // The only upstream slot is free again.
    let r = proxy_request(&env, &t, HOST, "GET", "/x", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    // And the stalled body ends in an error instead of streaming forever.
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        http_body_util::BodyExt::collect(stalled.into_body()),
    )
    .await
    .expect("the stalled body was never aborted");
    assert!(res.is_err(), "a truncated body must not look complete");
}

#[tokio::test]
async fn a_client_that_never_reads_an_h2_response_body_is_cut_off_and_frees_the_slot() {
    let opts = ServeOptions {
        body_idle_timeout: Duration::from_millis(700),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |c| {
        c.max_upstream_connections = 1;
        c.connect_timeout = Duration::from_millis(500);
    })
    .await;
    let t = add_header_rule(&env);
    let mut s = h2_sender(&env, &t).await;
    let stalled = s.send_request(h2_req("/endless")).await.unwrap();
    assert_eq!(stalled.status(), 200);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let mut other = h2_sender(&env, &t).await;
    let r = other.send_request(h2_req("/x")).await.unwrap();
    assert_eq!(r.status(), 200);
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        http_body_util::BodyExt::collect(stalled.into_body()),
    )
    .await
    .expect("the stalled body was never aborted");
    assert!(res.is_err(), "a truncated body must not look complete");
}

#[tokio::test]
async fn a_stalled_response_no_longer_keeps_the_mitm_connection_busy() {
    let opts = ServeOptions {
        body_idle_timeout: Duration::from_millis(500),
        tunnel_idle_timeout: Duration::from_millis(800),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let mut s = h2_sender(&env, &t).await;
    let _stalled = s.send_request(h2_req("/endless")).await.unwrap();
    // After the body is aborted the in-flight counter drops and the idle timeout closes the
    // connection (probing earlier would itself count as activity).
    tokio::time::sleep(Duration::from_millis(3500)).await;
    assert!(
        s.send_request(h2_req("/x")).await.is_err(),
        "the stalled response kept the connection busy forever"
    );
}

#[tokio::test]
async fn a_slow_but_progressing_response_body_is_not_cut() {
    let opts = ServeOptions {
        body_idle_timeout: Duration::from_millis(1000),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let started = Instant::now();
    let r = proxy_request(&env, &t, HOST, "GET", "/drip", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "chunk\n".repeat(6));
    assert!(
        started.elapsed() > Duration::from_millis(1500),
        "the body must outlive the idle timeout"
    );
    let r = proxy_request(&env, &t, HOST, "GET", "/drip", &[], vec![], true).await;
    assert_eq!(r.body, "chunk\n".repeat(6));
}

// ---- lifetimes -------------------------------------------------------------------------------

#[tokio::test]
async fn max_lifetime_closes_a_busy_plain_http_connection() {
    let opts = ServeOptions {
        tunnel_max_lifetime: Duration::from_millis(800),
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    let mut s = tokio::net::TcpStream::connect(env.proxy_addr)
        .await
        .unwrap();
    let (mut r, mut w) = s.split();
    let started = Instant::now();
    // Keep-alive requests (answered 407) arrive all the time: the connection is never idle.
    let req = b"GET http://x.test/ HTTP/1.1\r\nHost: x.test\r\n\r\n";
    let closed = tokio::time::timeout(Duration::from_secs(4), async {
        let mut sink = [0u8; 1024];
        loop {
            if w.write_all(req).await.is_err() {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(100), r.read(&mut sink)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "busy plain connection outlived its max lifetime"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(600),
        "closed too early"
    );
}

#[tokio::test]
async fn max_lifetime_closes_a_busy_h2_mitm_connection() {
    let opts = ServeOptions {
        tunnel_max_lifetime: Duration::from_millis(800),
        ..ServeOptions::default()
    };
    let (env, _up) = env_with_upstream_opts(HOST, opts, |_| {}).await;
    let t = add_header_rule(&env);
    let mut s = h2_sender(&env, &t).await;
    let started = Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            match s.send_request(h2_req("/x")).await {
                Ok(r) => {
                    let _ = http_body_util::BodyExt::collect(r.into_body()).await;
                }
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "busy h2 connection outlived its max lifetime"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(600),
        "closed too early"
    );
}

// ---- one-sided stalls in passthrough tunnels ------------------------------------------------

async fn passthrough_env_with_idle() -> (Env, String) {
    let opts = ServeOptions {
        tunnel_idle_timeout: Duration::from_millis(500),
        ..ServeOptions::default()
    };
    let env = Env::custom(no_extra_roots(), opts, None).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "developer");
    (env, t)
}

#[tokio::test]
async fn a_passthrough_client_that_stops_reading_is_cut_even_if_it_keeps_sending() {
    // The destination floods data; the client never reads but keeps sending a byte now and then.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flood = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let chunk = vec![b'f'; 64 * 1024];
                while s.write_all(&chunk).await.is_ok() {}
            });
        }
    });
    let (env, t) = passthrough_env_with_idle().await;
    let (line, s) = raw_connect(env.proxy_addr, &flood.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    let (_r, mut w) = s.into_split();
    let started = Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        while w.write_all(b"x").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "a one-sided stall kept the tunnel open");
    assert!(started.elapsed() < Duration::from_secs(8));
}

#[tokio::test]
async fn a_passthrough_destination_that_stops_reading_is_cut_even_if_it_keeps_sending() {
    // The destination never reads but trickles a byte; the client floods.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hole = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                while s.write_all(b".").await.is_ok() {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }
    });
    let (env, t) = passthrough_env_with_idle().await;
    let (line, s) = raw_connect(env.proxy_addr, &hole.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    let (mut r, mut w) = s.into_split();
    tokio::spawn(async move {
        let mut b = [0u8; 64];
        while matches!(r.read(&mut b).await, Ok(n) if n > 0) {}
    });
    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        let chunk = vec![b'u'; 64 * 1024];
        while w.write_all(&chunk).await.is_ok() {}
    })
    .await;
    assert!(closed.is_ok(), "a one-sided stall kept the tunnel open");
}
