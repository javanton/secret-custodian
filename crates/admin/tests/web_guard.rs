use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use sg_admin::{api_router, socket_router, web_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

const HOST: &str = "localhost:9090";

struct Env {
    _dir: tempfile::TempDir,
    app: Router,
    sessions: Arc<Sessions>,
    vault: Arc<Vault>,
    state: AppState,
}

fn env() -> Env {
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
        vault: vault.clone(),
        sessions: sessions.clone(),
        allowed_hosts: vec!["localhost:9090".into(), "127.0.0.1:9090".into()],
        web_base_url: Some("http://localhost:9090".into()),
    };
    Env {
        _dir: dir,
        app: web_router(state.clone()),
        sessions,
        vault,
        state,
    }
}

fn app() -> (tempfile::TempDir, Router, Arc<Sessions>) {
    let e = env();
    (e._dir, e.app, e.sessions)
}

fn session(s: &Sessions) -> String {
    s.exchange(&s.new_login_token()).unwrap()
}

fn req(method: &str, uri: &str, host: &str, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, host);
    if let Some(c) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {c}"));
    }
    b.body(Body::empty()).unwrap()
}

fn json_write(method: &str, uri: &str, bearer: &str, origin: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    b.body(Body::from(r#"{"name":"dev","unmatched":"deny"}"#))
        .unwrap()
}

fn login_req(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"token":"{token}"}}"#)))
        .unwrap()
}

async fn body_of(r: axum::response::Response) -> String {
    String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned()
}

#[tokio::test]
async fn api_requires_a_bearer_session() {
    let (_d, app, _s) = app();
    for (uri, bearer) in [
        ("/api/secrets", None),
        ("/api/secrets", Some("bogus")),
        ("/api/nope", None),
    ] {
        let r = app
            .clone()
            .oneshot(req("GET", uri, HOST, bearer))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
}

#[tokio::test]
async fn cookies_are_ignored_entirely() {
    let (_d, app, sessions) = app();
    let sid = session(&sessions);
    let mut r = req("GET", "/api/secrets", HOST, None);
    r.headers_mut()
        .insert(header::COOKIE, format!("sg_session={sid}").parse().unwrap());
    let r = app.clone().oneshot(r).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // and no response ever sets one
    let t = sessions.new_login_token();
    let r = app.oneshot(login_req(&t)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(!r.headers().contains_key(header::SET_COOKIE));
}

#[tokio::test]
async fn authorization_header_must_be_one_well_formed_bearer() {
    let (_d, app, sessions) = app();
    let sid = session(&sessions);
    let with = |vals: &[String]| {
        let mut b = Request::builder()
            .uri("/api/secrets")
            .header(header::HOST, HOST);
        for v in vals {
            b = b.header(header::AUTHORIZATION, v.as_str());
        }
        b.body(Body::empty()).unwrap()
    };
    for (name, vals) in [
        ("basic", vec![format!("Basic {sid}")]),
        ("no scheme", vec![sid.clone()]),
        ("empty token", vec!["Bearer ".to_string()]),
        ("bare scheme", vec!["Bearer".to_string()]),
        ("extra part", vec![format!("Bearer {sid} x")]),
        (
            "duplicated",
            vec![format!("Bearer {sid}"), format!("Bearer {sid}")],
        ),
        (
            "bad then good",
            vec!["Bearer nope".into(), format!("Bearer {sid}")],
        ),
        ("truncated", vec![format!("Bearer {}", &sid[..63])]),
    ] {
        let r = app.clone().oneshot(with(&vals)).await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{name}");
    }
    // scheme is case-insensitive
    for scheme in ["Bearer", "bearer", "BEARER"] {
        let r = app
            .clone()
            .oneshot(with(&[format!("{scheme} {sid}")]))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{scheme}");
    }
}

#[tokio::test]
async fn login_exchanges_the_token_once_and_the_session_opens_the_api() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    let r = app.clone().oneshot(login_req(&t)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
    let body = body_of(r).await;
    assert!(!body.contains(&t));
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let sid = v["session"].as_str().unwrap().to_string();
    assert_eq!(sid.len(), 64);
    assert!(sid.bytes().all(|c| c.is_ascii_hexdigit()));
    let r = app
        .clone()
        .oneshot(req("GET", "/api/secrets", HOST, Some(&sid)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // second use, unknown, malformed and missing tokens all answer identically
    let again = app.clone().oneshot(login_req(&t)).await.unwrap();
    let unknown = app.clone().oneshot(login_req("deadbeef")).await.unwrap();
    let malformed = app
        .clone()
        .oneshot(login_req(r"\u0000\u00e9 ../"))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    let (a, u, m) = (
        body_of(again).await,
        body_of(unknown).await,
        body_of(malformed).await,
    );
    assert_eq!(a, u);
    assert_eq!(a, m);
    assert!(!a.contains(&t));
}

#[tokio::test]
async fn login_is_post_json_only() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    // GET (also with the old query form) is a 404, HEAD too, and neither consumes the token
    for method in ["GET", "HEAD"] {
        for uri in ["/login", &format!("/login?t={t}")] {
            let r = app
                .clone()
                .oneshot(req(method, uri, HOST, None))
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{method} {uri}");
        }
    }
    // form content type -> 415
    for ct in [
        "application/x-www-form-urlencoded",
        "text/plain",
        "multipart/form-data",
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::HOST, HOST)
                    .header(header::CONTENT_TYPE, ct)
                    .body(Body::from(format!("token={t}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE, "{ct}");
    }
    // cross-origin login is refused without consuming the token
    let mut cross = login_req(&t);
    cross
        .headers_mut()
        .insert(header::ORIGIN, "http://evil.com".parse().unwrap());
    let r = app.clone().oneshot(cross).await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // wrong Host too
    let mut bad_host = login_req(&t);
    bad_host
        .headers_mut()
        .insert(header::HOST, "evil.com".parse().unwrap());
    let r = app.clone().oneshot(bad_host).await.unwrap();
    assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST);
    // the token survived all of it
    let ok = app.oneshot(login_req(&t)).await.unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_token_is_single_use_under_concurrent_posts() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let (app, t) = (app.clone(), t.clone());
            tokio::spawn(async move { app.oneshot(login_req(&t)).await.unwrap().status() })
        })
        .collect();
    let mut ok = 0;
    for h in handles {
        match h.await.unwrap() {
            StatusCode::OK => ok += 1,
            s => assert_eq!(s, StatusCode::UNAUTHORIZED),
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn login_rejects_a_malformed_body_without_echoing_it() {
    let (_d, app, _s) = app();
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"token": SECRET-MARKER-123"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(!body_of(r).await.contains("SECRET-MARKER-123"));
}

#[tokio::test]
async fn guard_order_is_auth_then_media_type_then_body() {
    let (_d, app, sessions) = app();
    // unauthenticated: 401 even with a wrong content type or a broken body
    for (ct, body) in [
        (Some("text/plain"), "x"),
        (Some("application/json"), "{not json"),
        (None, ""),
    ] {
        let mut b = Request::builder()
            .method("POST")
            .uri("/api/roles")
            .header(header::HOST, HOST);
        if let Some(ct) = ct {
            b = b.header(header::CONTENT_TYPE, ct);
        }
        let r = app
            .clone()
            .oneshot(b.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{ct:?}");
    }
    // authenticated: now the media type and the body are judged
    let s = session(&sessions);
    let r = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/roles")
                .header(header::HOST, HOST)
                .header(header::AUTHORIZATION, format!("Bearer {s}"))
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // a malformed JSON body is never echoed back
    let r = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/roles")
                .header(header::HOST, HOST)
                .header(header::AUTHORIZATION, format!("Bearer {s}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"name": SECRET-MARKER-123"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(!body_of(r).await.contains("SECRET-MARKER-123"));
}

#[tokio::test]
async fn origin_header_on_writes_must_match_an_allowed_host() {
    let (_d, app, sessions) = app();
    let s = session(&sessions);
    for (origin, expected) in [
        ("http://evil.com", StatusCode::FORBIDDEN),
        ("null", StatusCode::FORBIDDEN),
        ("https://localhost:9090", StatusCode::FORBIDDEN),
        ("http://localhost:9090.evil.com", StatusCode::FORBIDDEN),
        ("http://127.0.0.1:9090", StatusCode::CREATED),
    ] {
        let r = app
            .clone()
            .oneshot(json_write("POST", "/api/roles", &s, Some(origin)))
            .await
            .unwrap();
        assert_eq!(r.status(), expected, "{origin}");
    }
    let r = app
        .clone()
        .oneshot(json_write(
            "POST",
            "/api/roles",
            &s,
            Some("http://localhost:9090"),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    // no Origin (CLI-like clients) and no CSRF header needed: the Bearer is the credential
    let r = app
        .oneshot(json_write("POST", "/api/roles", &s, None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn no_cors_headers_are_ever_sent() {
    let (_d, app, sessions) = app();
    let s = session(&sessions);
    let mut pre = req("OPTIONS", "/api/secrets", HOST, Some(&s));
    pre.headers_mut()
        .insert(header::ORIGIN, "http://evil.com".parse().unwrap());
    for r in [
        app.clone().oneshot(pre).await.unwrap(),
        app.clone()
            .oneshot(req("GET", "/api/secrets", HOST, Some(&s)))
            .await
            .unwrap(),
        app.clone().oneshot(login_req("x")).await.unwrap(),
    ] {
        assert!(r
            .headers()
            .keys()
            .all(|k| !k.as_str().starts_with("access-control-")));
    }
}

#[tokio::test]
async fn static_traversal_and_odd_api_paths_leak_nothing() {
    let e = env();
    e.vault.add_secret("marker-name-xyz", "v").unwrap();
    let sid = session(&e.sessions);
    // raw (non-normalised) paths, as a hand-written client would send them
    for uri in [
        "/../../Cargo.toml",
        "/%2e%2e/%2e%2e/Cargo.toml",
        "/%2e%2e%2fCargo.toml",
    ] {
        let r = e
            .app
            .clone()
            .oneshot(req("GET", uri, HOST, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{uri}");
        let body = body_of(r).await;
        assert!(
            !body.contains("[workspace]") && !body.contains("sg-admin"),
            "{uri}"
        );
    }
    for uri in [
        "//api/secrets",
        "/API/secrets",
        "/api%2Fsecrets",
        "/api%2fsecrets",
    ] {
        let r = e
            .app
            .clone()
            .oneshot(req("GET", uri, HOST, Some(&sid)))
            .await
            .unwrap();
        let st = r.status();
        let body = body_of(r).await;
        assert!(!body.contains("marker-name-xyz"), "{uri} {st}");
        assert_ne!(st, StatusCode::OK, "{uri}");
    }
    // sanity: the proper path does return it
    let r = e
        .app
        .clone()
        .oneshot(req("GET", "/api/secrets", HOST, Some(&sid)))
        .await
        .unwrap();
    assert!(body_of(r).await.contains("marker-name-xyz"));
}

#[tokio::test]
async fn login_url_route_exists_only_on_the_socket_router() {
    let e = env();
    let sid = session(&e.sessions);
    let post = |uri: &str, bearer: Option<&str>| {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(s) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {s}"));
        }
        b.body(Body::empty()).unwrap()
    };
    // not on the web listener, with or without a session, at either path
    for (uri, bearer) in [
        ("/admin/login-token", None),
        ("/admin/login-token", Some(sid.as_str())),
        ("/api/admin/login-token", Some(sid.as_str())),
    ] {
        let r = e.app.clone().oneshot(post(uri, bearer)).await.unwrap();
        assert!(
            [
                StatusCode::NOT_FOUND,
                StatusCode::UNAUTHORIZED,
                StatusCode::METHOD_NOT_ALLOWED
            ]
            .contains(&r.status()),
            "{uri} {}",
            r.status()
        );
        assert!(!body_of(r).await.contains("token"), "{uri}");
    }
    // not on the plain api router either
    let r = api_router(e.state.clone())
        .oneshot(post("/admin/login-token", None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    // on the socket router it works and the token logs in on the web router
    let r = socket_router(e.state.clone())
        .oneshot(post("/admin/login-token", None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
    let v: serde_json::Value = serde_json::from_str(&body_of(r).await).unwrap();
    let token = v["token"].as_str().unwrap();
    assert_eq!(v["url"], format!("http://localhost:9090/#t={token}"));
    let r = e.app.clone().oneshot(login_req(token)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_url_is_omitted_without_a_base_url() {
    let mut e = env();
    e.state.web_base_url = None;
    let r = socket_router(e.state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/login-token")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&body_of(r).await).unwrap();
    assert!(v["token"].is_string());
    assert!(v.get("url").is_none());
}

#[tokio::test]
async fn head_requests_never_consume_a_login_token() {
    let (_d, app, sessions) = app();
    let t = sessions.new_login_token();
    for uri in ["/", "/login", "/api/secrets", &format!("/login?t={t}")] {
        app.clone()
            .oneshot(req("HEAD", uri, HOST, None))
            .await
            .unwrap();
    }
    assert!(sessions.exchange(&t).is_some());
}

#[tokio::test]
async fn wrong_host_header_is_rejected_everywhere() {
    let (_d, app, _s) = app();
    for uri in ["/", "/login", "/api/secrets", "/app.js", "/nope"] {
        for host in [
            "evil.com",
            "localhost",
            "localhost:1",
            "LOCALHOST:9090.evil.com",
        ] {
            let r = app
                .clone()
                .oneshot(req("GET", uri, host, None))
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
        .oneshot(req("GET", "/", "LocalHost:9090", None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn static_pages_carry_a_strict_csp_and_security_headers() {
    let (_d, app, _s) = app();
    for uri in ["/", "/nope"] {
        let r = app
            .clone()
            .oneshot(req("GET", uri, HOST, None))
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
        .oneshot(req("GET", "/", HOST, None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // security headers also on guard rejections
    let r = app
        .oneshot(req("GET", "/", "evil.com", None))
        .await
        .unwrap();
    assert_eq!(r.headers()["x-frame-options"], "DENY");
}

#[tokio::test]
async fn static_assets_only_answer_get_and_head() {
    let (_d, app, _s) = app();
    let r = app
        .clone()
        .oneshot(req("POST", "/", HOST, None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
    let r = app
        .clone()
        .oneshot(req("GET", "/..%2f..%2fCargo.toml", HOST, None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = app
        .oneshot(req("GET", "/missing.js", HOST, None))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}
