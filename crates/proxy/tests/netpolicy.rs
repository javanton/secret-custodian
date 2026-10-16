//! Network policy for passthrough CONNECT and forwarded requests (SSRF defence).
mod common;
use common::*;
use sg_policy::*;
use sg_proxy::NetPolicy;
use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn passthrough_env(cfg: sg_proxy::UpstreamConfig) -> (Env, String) {
    let env = Env::new(cfg).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let t = env.token("m", "developer");
    (env, t)
}

fn last_decision(env: &Env) -> String {
    env.vault.list_audit(&Default::default()).unwrap()[0]
        .decision
        .clone()
}

#[tokio::test]
async fn default_policy_refuses_local_and_metadata_targets_without_connecting() {
    let (env, t) = passthrough_env(strict_upstream()).await;
    let (addr, seen) = counting_listener().await;
    let port = addr.port();
    for target in [
        format!("127.0.0.1:{port}"),
        format!("[::1]:{port}"),
        "169.254.169.254:80".to_string(),
        format!("0.0.0.0:{port}"),
        "[fe80::1]:80".to_string(),
        format!("[::ffff:127.0.0.1]:{port}"),
        "224.0.0.1:80".to_string(),
        "255.255.255.255:80".to_string(),
    ] {
        let (line, _) = raw_connect(env.proxy_addr, &target, Some(&basic(&t))).await;
        assert!(line.contains("403"), "{target} -> {line}");
        assert_eq!(last_decision(&env), "target-denied", "{target}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "a refused target was contacted"
    );
}

#[tokio::test]
async fn a_denied_bind_address_is_refused_even_with_allow_loopback() {
    let (admin, admin_seen) = counting_listener().await;
    let echo = echo_server().await;
    let mut cfg = no_extra_roots();
    cfg.net_policy.denied = vec![admin];
    let (env, t) = passthrough_env(cfg).await;
    let (line, _) = raw_connect(env.proxy_addr, &admin.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("403"), "{line}");
    assert_eq!(last_decision(&env), "target-denied");
    let (line, _s) = raw_connect(env.proxy_addr, &echo.to_string(), Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    assert_eq!(admin_seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_denied_wildcard_bind_means_that_port_on_every_local_address() {
    let (admin, admin_seen) = counting_listener().await;
    let mut cfg = no_extra_roots();
    cfg.net_policy.denied = vec![SocketAddr::from(([0, 0, 0, 0], admin.port()))];
    let (env, t) = passthrough_env(cfg).await;
    for target in [
        format!("127.0.0.1:{}", admin.port()),
        format!("[::1]:{}", admin.port()),
    ] {
        let (line, _) = raw_connect(env.proxy_addr, &target, Some(&basic(&t))).await;
        assert!(line.contains("403"), "{target} -> {line}");
    }
    assert_eq!(admin_seen.load(Ordering::SeqCst), 0);
}

#[test]
fn rfc1918_and_ula_targets_pass_the_policy() {
    let p = NetPolicy::default();
    for a in [
        "10.1.2.3:80",
        "192.168.1.10:443",
        "172.16.0.5:22",
        "[fd00::1]:80",
        "8.8.8.8:53",
    ] {
        assert!(p.permits(a.parse().unwrap(), false), "{a}");
    }
    for a in [
        "127.0.0.1:80",
        "[::1]:80",
        "0.0.0.0:80",
        "[::]:80",
        "169.254.169.254:80",
        "[fe80::1]:80",
        "224.0.0.1:80",
        "[ff02::1]:80",
        "255.255.255.255:80",
        "[::ffff:127.0.0.1]:80",
        "[::ffff:169.254.169.254]:80",
    ] {
        assert!(!p.permits(a.parse().unwrap(), false), "{a}");
    }
    // The localhost service exception never overrides `denied`.
    let denied: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let p = NetPolicy::default().with_denied(vec![denied]);
    assert!(p.permits("127.0.0.1:8080".parse().unwrap(), true));
    assert!(!p.permits(denied, true));
    assert!(!NetPolicy::default().permits("127.0.0.1:8080".parse().unwrap(), false));
}

#[tokio::test]
async fn a_hostname_resolving_to_a_refused_address_is_refused() {
    let (addr, seen) = counting_listener().await;
    let mut cfg = strict_upstream();
    cfg.resolve_override.insert("rebind.test".into(), addr);
    let (env, t) = passthrough_env(cfg).await;
    let (line, _) = raw_connect(env.proxy_addr, "rebind.test:443", Some(&basic(&t))).await;
    assert!(line.contains("403"), "{line}");
    assert_eq!(last_decision(&env), "target-denied");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_vetted_resolved_address_is_the_one_connected_to() {
    let echo = echo_server().await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert("svc.test".into(), echo);
    let (env, t) = passthrough_env(cfg).await;
    let (line, mut s) = raw_connect(env.proxy_addr, "svc.test:443", Some(&basic(&t))).await;
    assert!(line.contains("200"), "{line}");
    s.write_all(b"hi").await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hi");
}

// ---- forwarded (MITM) requests ----

fn add_rule_for(env: &Env, host: &str) -> String {
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: host.into(),
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
async fn forwarding_to_a_loopback_address_is_refused_by_default() {
    let (env, up) =
        env_with_upstream_cfg("svc.test", |c| c.net_policy.allow_loopback = false).await;
    let t = add_rule_for(&env, "svc.test");
    let r = proxy_request(&env, &t, "svc.test", "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 403);
    assert_eq!(up.count(), 0);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "target-denied" && r.status == Some(403)));
}

#[tokio::test]
async fn host_localhost_with_a_rule_may_reach_loopback() {
    let (env, up) =
        env_with_upstream_cfg("localhost", |c| c.net_policy.allow_loopback = false).await;
    let t = add_rule_for(&env, "localhost");
    let r = proxy_request(&env, &t, "localhost", "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.count(), 1);
}

#[tokio::test]
async fn the_localhost_exception_never_overrides_denied() {
    let up = spawn_tls_upstream("localhost").await;
    let mut cfg = sg_proxy::UpstreamConfig::new(vec![up.ca_der.clone()]);
    cfg.resolve_override.insert("localhost".into(), up.addr);
    cfg.net_policy.denied = vec![up.addr];
    let env = Env::new(cfg).await;
    env.ca.allow_domain("localhost").unwrap();
    let t = add_rule_for(&env, "localhost");
    let r = proxy_request(&env, &t, "localhost", "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 403);
    assert_eq!(up.count(), 0);
}
