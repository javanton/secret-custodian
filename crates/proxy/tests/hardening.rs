//! Request-level hardening inside the MITM: routing-override headers, TRACE/CONNECT, query
//! separators and absolute-form request targets.
mod common;
use common::*;
use sg_policy::*;

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

const ROUTING_HEADERS: &[&str] = &[
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Forwarded-Host",
    "X-Forwarded-Prefix",
    "X-Forwarded-Path",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-Forwarded-Port",
    "X-Forwarded-Server",
    "X-Forwarded-Anything-Else",
    "X-Real-IP",
    "Forwarded",
    "X-Original-Host",
    "X-Host",
    "Via",
    "Front-End-Https",
];

#[tokio::test]
async fn routing_override_headers_are_stripped_from_injected_requests() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let mut headers: Vec<(&str, &str)> = ROUTING_HEADERS.iter().map(|h| (*h, "evil")).collect();
    headers.push(("x-keep", "yes"));
    let r = proxy_request(&env, &t, HOST, "POST", "/x", &headers, vec![], false).await;
    assert_eq!(r.status, 200);
    for h in ROUTING_HEADERS {
        assert!(up.header(0, h).is_empty(), "{h} reached the upstream");
    }
    assert_eq!(up.header(0, "x-keep"), vec!["yes".to_string()]);
}

#[tokio::test]
async fn routing_override_headers_are_stripped_over_http2_too() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let headers: Vec<(&str, &str)> = ROUTING_HEADERS.iter().map(|h| (*h, "evil")).collect();
    let r = proxy_request(&env, &t, HOST, "GET", "/x", &headers, vec![], true).await;
    assert_eq!(r.status, 200);
    for h in ROUTING_HEADERS {
        assert!(up.header(0, h).is_empty(), "{h} reached the upstream");
    }
}

#[tokio::test]
async fn query_param_removal_treats_semicolon_as_a_separator() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL").unwrap();
    add_rule(
        &env.vault,
        NewRule {
            role: "developer".into(),
            host_pattern: HOST.into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Query,
            target_name: "api_key".into(),
            template: "{secret}".into(),
            secret_id: s.id,
        },
    )
    .unwrap();
    let t = env.token("laptop", "developer");
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/x?a=1;API_KEY=agent&b=2&api%5Fkey=agent2;c=3",
        &[],
        vec![],
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    let uri = up.received.lock().unwrap()[0].uri.clone();
    assert!(!uri.contains("agent"), "agent value survived: {uri}");
    assert_eq!(uri, "/x?a=1&b=2&c=3&api_key=REAL");
}

#[tokio::test]
async fn trace_and_connect_are_refused_with_405_and_audited() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let mut tun = open_tunnel(&env, &t, HOST).await;
    let r = tun.request("TRACE", "/x", &[("x-echo", "1")]).await;
    assert_eq!(r.status, 405);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.method == "TRACE" && r.decision == "method-refused" && r.status == Some(405)));

    let raw = format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    let r = proxy_raw_request(&env, &t, HOST, raw.as_bytes()).await;
    assert_eq!(r.status, 405);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.method == "CONNECT" && r.decision == "method-refused"));
    assert_eq!(up.count(), 0, "TRACE/CONNECT reached the upstream");
}

#[tokio::test]
async fn ordinary_methods_still_flow() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let mut tun = open_tunnel(&env, &t, HOST).await;
    for m in ["OPTIONS", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
        let r = tun.request(m, "/m", &[]).await;
        assert_eq!(r.status, 200, "{m}");
    }
    assert_eq!(up.count(), 7);
}

#[tokio::test]
async fn absolute_form_with_another_authority_is_421() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"https://other.host/x")).await;
    assert_eq!(r.status, 421);
    assert_eq!(up.count(), 0);
}

#[tokio::test]
async fn absolute_form_with_the_connect_host_is_forwarded_as_origin_form() {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env);
    let target = format!("https://{HOST}/x?q=1");
    let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, target.as_bytes())).await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap()[0].uri, "/x?q=1");
    assert_eq!(up.header(0, "host"), vec![HOST.to_string()]);
}
