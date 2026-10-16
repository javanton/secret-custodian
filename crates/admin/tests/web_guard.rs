use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use sg_admin::{web_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost:9090";

fn app() -> (tempfile::TempDir, Router, Arc<Sessions>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    let sessions = Arc::new(Sessions::new());
    let state = AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: sessions.clone(),
        allowed_hosts: vec!["localhost:9090".into(), "127.0.0.1:9090".into()],
    };
    (dir, web_router(state), sessions)
}

fn req(method: &str, uri: &str, host: &str, cookie: Option<&str>, csrf: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, format!("sg_session={c}"));
    }
    if csrf {
        b = b.header("x-sg-csrf", "1");
    }
    b.body(Body::empty()).unwrap()
}

fn json_write(
    method: &str,
    uri: &str,
    cookie: &str,
    origin: Option<&str>,
    csrf: bool,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::COOKIE, format!("sg_session={cookie}"))
        .header(header::CONTENT_TYPE, "application/json");
    if csrf {
        b = b.header("x-sg-csrf", "1");
    }
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    b.body(Body::from(r#"{"name":"dev","unmatched":"deny"}"#))
        .unwrap()
}

#[tokio::test]
async fn wrong_host_header_is_rejected_everywhere() {
    let (_d, app, _s) = app();
    for uri in ["/", "/login?t=x", "/api/secrets", "/app.js", "/nope"] {
        for host in [
            "evil.com",
            "localhost",
            "localhost:1",
            "LOCALHOST:9090.evil.com",
        ] {
            let r = app
                .clone()
                .oneshot(req("GET", uri, host, None, false))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST, "{uri} {host}");
        }
    }
    // missing Host header
    let r = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
    // case-insensitive match is allowed
    let r = app
        .oneshot(req("GET", "/", "LocalHost:9090", None, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_requires_a_session() {
    let (_d, app, _s) = app();
    for (uri, cookie) in [
        ("/api/secrets", None),
        ("/api/secrets", Some("bogus")),
        ("/api/nope", None),
    ] {
        let r = app
            .clone()
            .oneshot(req("GET", uri, HOST, cookie, false))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn login_token_is_single_use_and_sets_a_strict_cookie() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    let r = app
        .clone()
        .oneshot(req("GET", &format!("/login?t={t}"), HOST, None, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()[header::LOCATION], "/");
    let cookie = r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    for attr in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=28800"] {
        assert!(cookie.contains(attr), "{cookie}");
    }
    assert!(!cookie.contains(&t) && !format!("{:?}", r.headers()).contains(&t));
    let again = app
        .clone()
        .oneshot(req("GET", &format!("/login?t={t}"), HOST, None, false))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    // unknown and missing tokens answer identically
    let unknown = app
        .clone()
        .oneshot(req("GET", "/login?t=deadbeef", HOST, None, false))
        .await
        .unwrap();
    let missing = app
        .clone()
        .oneshot(req("GET", "/login", HOST, None, false))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    let bytes = |r: axum::response::Response| async move {
        use http_body_util::BodyExt;
        r.into_body().collect().await.unwrap().to_bytes()
    };
    assert_eq!(bytes(again).await, bytes(unknown).await);
    assert!(!cookie.is_empty());
}

#[tokio::test]
async fn cookie_from_login_opens_the_api() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    let r = app
        .clone()
        .oneshot(req("GET", &format!("/login?t={t}"), HOST, None, false))
        .await
        .unwrap();
    let c = r.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .to_string();
    let sid = c
        .split(';')
        .next()
        .unwrap()
        .trim_start_matches("sg_session=")
        .to_string();
    let r = app
        .oneshot(req("GET", "/api/secrets", HOST, Some(&sid), false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn writes_need_the_csrf_header() {
    let (_d, app, sessions) = app();
    let s = sessions.exchange(&sessions.new_login_token()).unwrap();
    let no = app
        .clone()
        .oneshot(req("POST", "/api/roles", HOST, Some(&s), false))
        .await
        .unwrap();
    assert_eq!(no.status(), StatusCode::FORBIDDEN);
    let no = app
        .clone()
        .oneshot(json_write("POST", "/api/roles", &s, None, false))
        .await
        .unwrap();
    assert_eq!(no.status(), StatusCode::FORBIDDEN);
    let del = app
        .clone()
        .oneshot(req("DELETE", "/api/roles/x", HOST, Some(&s), false))
        .await
        .unwrap();
    assert_eq!(del.status(), StatusCode::FORBIDDEN);
    let get = app
        .clone()
        .oneshot(req("GET", "/api/secrets", HOST, Some(&s), false))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let ok = app
        .oneshot(json_write("POST", "/api/roles", &s, None, true))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn origin_header_on_writes_must_match_an_allowed_host() {
    let (_d, app, sessions) = app();
    let s = sessions.exchange(&sessions.new_login_token()).unwrap();
    for (origin, expected) in [
        ("http://evil.com", StatusCode::FORBIDDEN),
        ("null", StatusCode::FORBIDDEN),
        ("https://localhost:9090", StatusCode::FORBIDDEN),
        ("http://localhost:9090.evil.com", StatusCode::FORBIDDEN),
        ("http://127.0.0.1:9090", StatusCode::CREATED),
    ] {
        let r = app
            .clone()
            .oneshot(json_write("POST", "/api/roles", &s, Some(origin), true))
            .await
            .unwrap();
        assert_eq!(r.status(), expected, "{origin}");
    }
    let r = app
        .oneshot(json_write(
            "POST",
            "/api/roles",
            &s,
            Some("http://localhost:9090"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn static_pages_carry_a_strict_csp_and_security_headers() {
    let (_d, app, _s) = app();
    for uri in ["/", "/nope"] {
        let r = app
            .clone()
            .oneshot(req("GET", uri, HOST, None, false))
            .await
            .unwrap();
        let h = r.headers();
        let csp = h["content-security-policy"].to_str().unwrap();
        assert_eq!(
            csp,
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        );
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["cross-origin-opener-policy"], "same-origin");
        assert_eq!(h["cross-origin-resource-policy"], "same-origin");
    }
    let r = app
        .clone()
        .oneshot(req("GET", "/", HOST, None, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // security headers also on guard rejections
    let r = app
        .oneshot(req("GET", "/", "evil.com", None, false))
        .await
        .unwrap();
    assert_eq!(r.headers()["x-frame-options"], "DENY");
}

#[tokio::test]
async fn static_assets_only_answer_get_and_head() {
    let (_d, app, _s) = app();
    let r = app
        .clone()
        .oneshot(req("POST", "/", HOST, None, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    let r = app
        .clone()
        .oneshot(req("GET", "/..%2f..%2fCargo.toml", HOST, None, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = app
        .oneshot(req("GET", "/missing.js", HOST, None, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
