mod common;
use common::*;
use sg_policy::*;
use std::time::Duration;

const HOST: &str = "api.example.test";

fn new_rule(
    host: &str,
    path: &str,
    methods: &[&str],
    kind: InjectionKind,
    target: &str,
    template: &str,
    secret_id: i64,
) -> NewRule {
    NewRule {
        role: "developer".into(),
        host_pattern: host.into(),
        path_pattern: path.into(),
        methods: methods.iter().map(|m| m.to_string()).collect(),
        kind,
        target_name: target.into(),
        template: template.into(),
        secret_id,
    }
}

async fn setup(methods: &[&str], path: &str) -> (Env, TestUpstream, String) {
    let (env, up) = env_with_upstream(HOST).await;
    let t = add_header_rule(&env, methods, path);
    (env, up, t)
}

fn add_header_rule(env: &Env, methods: &[&str], path: &str) -> String {
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    add_rule(
        &env.vault,
        new_rule(
            HOST,
            path,
            methods,
            InjectionKind::Header,
            "Authorization",
            "Bearer {secret}",
            s.id,
        ),
    )
    .unwrap();
    env.token("laptop", "developer")
}

#[tokio::test]
async fn injects_header_and_agent_never_sees_the_secret() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/v1/x", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert!(!r.body.contains("REAL-SECRET"));
    assert_eq!(
        up.header(0, "authorization"),
        vec!["Bearer REAL-SECRET".to_string()]
    );
}

#[tokio::test]
async fn agent_supplied_credentials_are_discarded() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/",
        &[
            ("authorization", "Bearer AGENT-A"),
            ("Authorization", "Bearer AGENT-B"),
        ],
        vec![],
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        up.header(0, "authorization"),
        vec!["Bearer REAL-SECRET".to_string()]
    );
}

#[tokio::test]
async fn query_injection_replaces_agent_param_and_encodes() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("q", "a b&c").unwrap();
    add_rule(
        &env.vault,
        new_rule(
            HOST,
            "*",
            &[],
            InjectionKind::Query,
            "api_key",
            "{secret}",
            s.id,
        ),
    )
    .unwrap();
    let t = env.token("m", "developer");
    proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/p?API_KEY=agent&z=1&Api_Key=x",
        &[],
        vec![],
        false,
    )
    .await;
    assert_eq!(
        up.received.lock().unwrap()[0].uri,
        "/p?z=1&api_key=a%20b%26c"
    );
}

#[tokio::test]
async fn disallowed_method_is_403_and_never_reaches_upstream() {
    let (env, up, t) = setup(&["GET"], "*").await;
    let r = proxy_request(&env, &t, HOST, "POST", "/x", &[], b"data".to_vec(), false).await;
    assert_eq!(r.status, 403);
    assert!(up.received.lock().unwrap().is_empty());
}

/// Every bypass witness of the plan, sent as raw HTTP/1.1 bytes so that characters `http::Uri`
/// refuses (raw `\`, non-ASCII) really reach the proxy. Rule: `GET /repos/*`.
#[tokio::test]
async fn path_traversal_cannot_escape_a_restricted_rule() {
    let (env, up, t) = setup(&["GET"], "/repos/*").await;
    let ok = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"/repos/ok")).await;
    assert_eq!(ok.status, 200);
    let witnesses: &[&[u8]] = &[
        b"/repos/../admin",
        b"/repos/%2e%2e/admin",
        b"/repos/..%2fadmin",
        b"/repos/..;/admin",
        b"/repos/%252e%252e%252fadmin",
        b"/repos/x%252F..%252F..%252Frepos%252Fz%252Fw%2F..%2F..%2Fadmin",
        b"/repos/..;%2Frepos%2Fx/..;/admin",
        b"/repos/..%2F..%2Fadmin%3F%2F..%2F..%2Frepos%2Fy",
        b"/repos/%u002e%u002e/admin",
        b"/repos/%U002E%U002E/admin",
        b"/repos/a;%2Fk/..%3B/..%3B/admin",
        b"/repos/..%20/admin",
        b"/repos/.../admin",
        b"/repos/%E2%80%A5/admin",
        b"/repos/%EF%BC%8E%EF%BC%8E/admin",
        b"/repos/a%09b",
        b"/repos/a%0Ab",
        b"/repos/a%00b",
        b"/repos/%zz",
        b"/repos/%",
        b"/repos/a%ff",
        b"/other",
        "/repos/\u{2025}/admin".as_bytes(),
        "/repos/\u{ff0e}\u{ff0e}/admin".as_bytes(),
        "/repos/a\u{200b}b".as_bytes(),
        "/repos/a\u{a0}b".as_bytes(),
        b"/repos/..\\admin",
        b"/repos/%2e%2e%5cadmin",
        b"/repos/..+/admin",
        b"/repos/..%2B/admin",
    ];
    let mut bad = Vec::new();
    for p in witnesses {
        let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, p)).await;
        if r.status != 403 {
            bad.push(format!("{} -> {}", String::from_utf8_lossy(p), r.status));
        }
    }
    let sent: Vec<String> = up
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.uri.clone())
        .collect();
    assert!(
        bad.is_empty() && sent.len() == 1,
        "not forbidden: {bad:#?}; upstream saw {sent:#?}"
    );
}

/// The plan lists `/repos/a\..%3B\k/../admin` among the 403 witnesses, but `normalize_path`
/// resolves its plain `..` segment (which swallows `a\..%3B\k`) before judging, so the request
/// that is judged AND forwarded is `/repos/admin`: inside the rule's prefix, nothing to escape
/// (spec 6.2: "lo autorizado es lo enviado"). A raw `\` that is not a dot segment is allowed too.
#[tokio::test]
async fn witness_that_normalizes_into_the_prefix_is_forwarded_normalized() {
    let (env, up, t) = setup(&["GET"], "/repos/*").await;
    let r = proxy_raw_request(
        &env,
        &t,
        HOST,
        &raw_get(HOST, b"/repos/a\\..%3B\\k/../admin"),
    )
    .await;
    assert_eq!(r.status, 200);
    let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, b"/repos/a\\b")).await;
    assert_eq!(r.status, 200);
    let uris: Vec<String> = up
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.uri.clone())
        .collect();
    assert_eq!(
        uris,
        vec!["/repos/admin".to_string(), "/repos/a\\b".to_string()]
    );
}

#[tokio::test]
async fn restricted_rule_still_authorises_legitimate_encoded_paths() {
    let (env, up, t) = setup(&["GET"], "/repos/*").await;
    for p in ["/repos/ok", "/repos/a%2Fb", "/repos/a/../b"] {
        let r = proxy_raw_request(&env, &t, HOST, &raw_get(HOST, p.as_bytes())).await;
        assert_eq!(r.status, 200, "{p}");
    }
    let uris: Vec<String> = up
        .received
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.uri.clone())
        .collect();
    assert_eq!(uris, vec!["/repos/ok", "/repos/a%2Fb", "/repos/b"]);
    assert_eq!(
        up.header(0, "authorization"),
        vec!["Bearer REAL-SECRET".to_string()]
    );
}

#[tokio::test]
async fn gitlab_style_encoded_project_path_still_injects() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Deny).unwrap();
    let s = env.vault.add_secret("k", "GL-TOKEN").unwrap();
    add_rule(
        &env.vault,
        new_rule(
            HOST,
            "/api/v4/projects/*",
            &["GET"],
            InjectionKind::Header,
            "PRIVATE-TOKEN",
            "{secret}",
            s.id,
        ),
    )
    .unwrap();
    let t = env.token("m", "developer");
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/api/v4/projects/a%2Fb/issues",
        &[],
        vec![],
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        up.received.lock().unwrap()[0].uri,
        "/api/v4/projects/a%2Fb/issues"
    );
    assert_eq!(up.header(0, "private-token"), vec!["GL-TOKEN".to_string()]);
}

#[tokio::test]
async fn normalized_path_is_what_gets_forwarded() {
    let (env, up, t) = setup(&["GET"], "*").await;
    proxy_request(&env, &t, HOST, "GET", "//a/./b//c", &[], vec![], false).await;
    assert_eq!(up.received.lock().unwrap()[0].uri, "/a/b/c");
}

#[tokio::test]
async fn host_header_different_from_connect_target_is_421() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/",
        &[("host", "evil.example.test")],
        vec![],
        false,
    )
    .await;
    assert_eq!(r.status, 421);
    assert!(up.received.lock().unwrap().is_empty());
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "host-mismatch" && r.status == Some(421)));
}

#[tokio::test]
async fn host_header_variants_equivalent_to_the_connect_host_are_accepted() {
    let (env, up, t) = setup(&[], "*").await;
    for (i, h) in [
        "API.Example.Test.",
        "api.example.test:443",
        "Api.Example.Test:8443",
        "API.EXAMPLE.TEST",
    ]
    .iter()
    .enumerate()
    {
        let r = proxy_request(&env, &t, HOST, "GET", "/", &[("host", h)], vec![], false).await;
        assert_eq!(r.status, 200, "{h}");
        assert_eq!(up.count(), i + 1);
        assert_eq!(
            up.header(i, "authorization"),
            vec!["Bearer REAL-SECRET".to_string()]
        );
    }
}

#[tokio::test]
async fn host_lookalikes_and_missing_host_are_421() {
    let (env, up, t) = setup(&[], "*").await;
    for h in [
        "api.example.test.evil.test",
        "xapi.example.test",
        "api.example.test@evil.test",
        "127.0.0.1",
    ] {
        let r = proxy_request(&env, &t, HOST, "GET", "/", &[("host", h)], vec![], false).await;
        assert_eq!(r.status, 421, "{h}");
    }
    let raw = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    assert_eq!(proxy_raw_request(&env, &t, HOST, raw).await.status, 421);
    assert!(up.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn http2_authority_mismatch_is_421() {
    let (env, up, t) = setup(&[], "*").await;
    let tls = tunnel_tls(&env, &t, HOST, true).await.ok().unwrap();
    let (mut s, c) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls),
    )
    .await
    .unwrap();
    tokio::spawn(c);
    let req = hyper::Request::builder()
        .uri("https://evil.example.test/")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    assert_eq!(s.send_request(req).await.unwrap().status().as_u16(), 421);
    assert!(up.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_request_is_audited_with_identity_and_without_query() {
    let (env, _up, t) = setup(&[], "*").await;
    proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/v1?secret_param=1",
        &[],
        vec![],
        false,
    )
    .await;
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    let e = rows.iter().find(|r| r.decision == "inject").unwrap();
    assert_eq!(
        (e.path.as_str(), e.status, e.machine.as_deref()),
        ("/v1", Some(200), Some("laptop"))
    );
    assert_eq!(
        (e.role.as_deref(), e.host.as_str()),
        (Some("developer"), HOST)
    );
    assert!(e.jti.is_some() && e.rule_id.is_some());
}

#[tokio::test]
async fn forbidden_requests_are_audited() {
    let (env, _up, t) = setup(&["GET"], "*").await;
    proxy_request(&env, &t, HOST, "DELETE", "/x?k=v", &[], vec![], false).await;
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    let e = rows.iter().find(|r| r.decision == "forbidden").unwrap();
    assert_eq!(
        (e.path.as_str(), e.status, e.method.as_str()),
        ("/x", Some(403), "DELETE")
    );
}

#[tokio::test]
async fn http2_from_the_agent_is_supported() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/h2", &[], vec![], true).await;
    assert_eq!(r.status, 200);
    assert_eq!(
        up.header(0, "authorization"),
        vec!["Bearer REAL-SECRET".to_string()]
    );
    assert_eq!(up.header(0, "host"), vec![HOST.to_string()]);
}

#[tokio::test]
async fn proxy_and_hop_by_hop_request_headers_are_not_forwarded() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "GET",
        "/",
        &[
            ("proxy-authorization", "Basic c2VjcmV0"),
            ("proxy-connection", "keep-alive"),
            ("keep-alive", "5"),
            ("connection", "x-private"),
            ("x-private", "1"),
            ("x-keep", "yes"),
        ],
        vec![],
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    for h in [
        "proxy-authorization",
        "proxy-connection",
        "keep-alive",
        "connection",
        "x-private",
    ] {
        assert!(up.header(0, h).is_empty(), "{h} leaked upstream");
    }
    assert_eq!(up.header(0, "x-keep"), vec!["yes".to_string()]);
}

#[tokio::test]
async fn upstream_response_is_returned_without_hop_by_hop_headers() {
    let (env, _up, t) = setup(&[], "*").await;
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, "ok");
    assert_eq!(r.header("x-up"), Some("1"));
    assert!(r.header("keep-alive").is_none() && r.header("proxy-foo").is_none());
    let h2 = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], true).await;
    assert_eq!(h2.status, 200);
    assert!(h2.header("keep-alive").is_none() && h2.header("proxy-foo").is_none());
}

#[tokio::test]
async fn response_body_is_streamed_not_buffered() {
    use http_body_util::BodyExt;
    let (env, _up, t) = setup(&[], "*").await;
    let mut tun = open_tunnel(&env, &t, HOST).await;
    let started = std::time::Instant::now();
    let mut resp = tun.send_streaming("/stream").await;
    let first = resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(&first[..], b"first");
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "first chunk must not wait for the whole body"
    );
    let second = resp
        .body_mut()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(&second[..], b"second");
}

#[tokio::test]
async fn one_mib_request_body_streams_through() {
    let (env, up, t) = setup(&[], "*").await;
    let r = proxy_request(
        &env,
        &t,
        HOST,
        "POST",
        "/up",
        &[],
        vec![7u8; 1024 * 1024],
        false,
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(up.received.lock().unwrap()[0].body_len, 1024 * 1024);
}

#[tokio::test]
async fn revoking_the_token_stops_an_open_tunnel() {
    let (env, up, _t) = setup(&[], "*").await;
    let issued = env.tokens.issue("laptop", "developer", None).unwrap();
    let mut tun = open_tunnel(&env, &issued.token, HOST).await;
    assert_eq!(tun.request("GET", "/a", &[]).await.status, 200);
    env.tokens.revoke(&issued.jti).unwrap();
    let r = tun.request("GET", "/b", &[]).await;
    assert_eq!(r.status, 407);
    assert_eq!(
        up.count(),
        1,
        "the request after revocation must not be forwarded"
    );
    // The proxy closes the tunnel afterwards.
    assert!(tun.try_request("GET", "/c", &[]).await.is_none());
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows.iter().any(|r| r.decision == "token-invalid"
        && r.status == Some(407)
        && r.jti.as_deref() == Some(issued.jti.as_str())));
}

#[tokio::test]
async fn rule_changes_apply_to_requests_inside_an_open_tunnel() {
    let (env, up) = env_with_upstream(HOST).await;
    add_role(&env.vault, "developer", Unmatched::Passthrough).unwrap();
    let s = env.vault.add_secret("k", "REAL-SECRET").unwrap();
    let rule = add_rule(
        &env.vault,
        new_rule(
            HOST,
            "*",
            &[],
            InjectionKind::Header,
            "Authorization",
            "Bearer {secret}",
            s.id,
        ),
    )
    .unwrap();
    let t = env.token("laptop", "developer");
    let mut tun = open_tunnel(&env, &t, HOST).await;
    assert_eq!(tun.request("GET", "/a", &[]).await.status, 200);
    remove_rule(&env.vault, rule.id).unwrap();
    assert_eq!(tun.request("GET", "/b", &[]).await.status, 403);
    assert_eq!(up.count(), 1);
}

#[tokio::test]
async fn upstream_with_an_untrusted_certificate_is_502_and_nothing_is_sent() {
    // The proxy does not trust the test upstream's CA.
    let up = spawn_tls_upstream(HOST).await;
    let mut cfg = no_extra_roots();
    cfg.resolve_override.insert(HOST.into(), up.addr);
    let env = Env::new(cfg).await;
    env.ca.allow_domain(HOST).unwrap();
    let t = add_header_rule(&env, &[], "*");
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 502);
    assert_eq!(up.count(), 0);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    let e = rows
        .iter()
        .find(|r| r.decision == "upstream-error")
        .unwrap();
    assert_eq!(e.status, Some(502));
}

#[tokio::test]
async fn unreachable_upstream_is_502_and_audited() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = l.local_addr().unwrap();
    drop(l);
    let (env, _up) = env_with_upstream_cfg(HOST, |c| {
        c.resolve_override.insert(HOST.into(), dead);
    })
    .await;
    let t = add_header_rule(&env, &[], "*");
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 502);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "upstream-error" && r.status == Some(502)));
}

#[tokio::test]
async fn connect_timeout_is_502_and_audited() {
    // Blackholed address (TEST-NET-1): the connect either hangs until our timeout or fails fast;
    // both must end as an audited 502 within the bound.
    let (env, _up) = env_with_upstream_cfg(HOST, |c| {
        c.connect_timeout = Duration::from_millis(300);
        c.resolve_override
            .insert(HOST.into(), "192.0.2.1:81".parse().unwrap());
    })
    .await;
    let t = add_header_rule(&env, &[], "*");
    let started = std::time::Instant::now();
    let r = proxy_request(&env, &t, HOST, "GET", "/", &[], vec![], false).await;
    assert_eq!(r.status, 502);
    assert!(started.elapsed() < Duration::from_secs(5));
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    assert!(rows
        .iter()
        .any(|r| r.decision == "upstream-error" && r.status == Some(502)));
}

#[tokio::test]
async fn response_header_timeout_is_502_and_audited() {
    let (env, up) = env_with_upstream_cfg(HOST, |c| {
        c.response_header_timeout = Duration::from_millis(300)
    })
    .await;
    let t = add_header_rule(&env, &[], "*");
    let r = proxy_request(&env, &t, HOST, "GET", "/slow", &[], vec![], false).await;
    assert_eq!(r.status, 502);
    assert_eq!(up.count(), 1);
    let rows = env.vault.list_audit(&Default::default()).unwrap();
    let e = rows
        .iter()
        .find(|r| r.decision == "upstream-error")
        .unwrap();
    assert_eq!(e.status, Some(502));
}
