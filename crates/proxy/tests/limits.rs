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
