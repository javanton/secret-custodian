use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sg_admin::{api_router, AppState, Sessions};
use sg_auth::{TokenService, TokenVerifier};
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

struct Env {
    _dir: tempfile::TempDir,
    app: Router,
    tokens: Arc<TokenService>,
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
    let tokens = Arc::new(TokenService::new(vault.clone()).unwrap());
    let state = AppState {
        tokens: tokens.clone(),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: Arc::new(Sessions::new()),
        allowed_hosts: vec!["localhost:9090".into()],
    };
    Env {
        _dir: dir,
        app: api_router(state),
        tokens,
    }
}

fn app() -> (tempfile::TempDir, Router) {
    let e = env();
    (e._dir, e.app)
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, String) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let (st, h) = (resp.status(), resp.headers().clone());
    let body =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    (st, h, body)
}

async fn call(app: &Router, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            b = b.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let (st, _, body) = send(app, b.body(body).unwrap()).await;
    (st, body)
}

async fn raw(app: &Router, method: &str, uri: &str, ct: Option<&str>, body: String) -> StatusCode {
    let mut b = Request::builder().method(method).uri(uri);
    if let Some(ct) = ct {
        b = b.header("content-type", ct);
    }
    send(app, b.body(Body::from(body)).unwrap()).await.0
}

fn json_of(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

fn rule_body(secret_id: i64) -> Value {
    json!({
        "role":"dev","host_pattern":"api.github.com","methods":["GET"],"kind":"header",
        "target_name":"Authorization","template":"Bearer {secret}","secret_id":secret_id
    })
}

#[tokio::test]
async fn no_route_ever_returns_a_secret_value() {
    let (_d, app) = app();
    let (st, _) = call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"TOPSECRET-VALUE"})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let mut dump = String::new();
    for uri in [
        "/secrets",
        "/secrets/gh",
        "/roles",
        "/rules",
        "/tokens",
        "/ca",
        "/audit",
    ] {
        dump.push_str(&call(&app, "GET", uri, None).await.1);
    }
    let (_, rot) = call(
        &app,
        "PUT",
        "/secrets/gh",
        Some(json!({"value":"ROTATED-VALUE"})),
    )
    .await;
    dump.push_str(&rot);
    assert!(!dump.contains("TOPSECRET-VALUE") && !dump.contains("ROTATED-VALUE"));
    assert!(!dump.contains("\"value\""));
}

#[tokio::test]
async fn secret_with_crlf_is_rejected_with_400() {
    let (_d, app) = app();
    let (st, body) = call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"x","value":"a\r\nEvil: 1"})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(json_of(&body)["error"].is_string());
}

#[tokio::test]
async fn secret_create_rotate_delete_list_flow_and_conflicts() {
    let (_d, app) = app();
    let (st, body) = call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"v1"})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(json_of(&body)["name"], "gh");
    assert_eq!(
        call(
            &app,
            "POST",
            "/secrets",
            Some(json!({"name":"gh","value":"v2"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/secrets",
            Some(json!({"name":"BAD NAME","value":"v"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (st, body) = call(&app, "PUT", "/secrets/gh", Some(json!({"value":"v3"}))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(json_of(&body)["rotated_at"].is_number());
    assert_eq!(
        call(&app, "PUT", "/secrets/missing", Some(json!({"value":"v"})))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", "/secrets/missing", None).await.0,
        StatusCode::NOT_FOUND
    );
    let list = json_of(&call(&app, "GET", "/secrets", None).await.1);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(
        call(&app, "DELETE", "/secrets/gh", None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "DELETE", "/secrets/gh", None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn full_policy_flow_and_conflicts() {
    let (_d, app) = app();
    call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"v"})),
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            "/roles",
            Some(json!({"name":"dev","unmatched":"passthrough"}))
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/roles",
            Some(json!({"name":"dev","unmatched":"deny"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (st, body) = call(&app, "POST", "/rules", Some(rule_body(1))).await;
    assert_eq!(st, StatusCode::CREATED);
    let v = json_of(&body);
    assert!(v["ca_warning"].as_str().unwrap().contains("allow-domain"));
    assert_eq!(
        call(&app, "DELETE", "/secrets/gh", None).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(&app, "DELETE", &format!("/rules/{}", v["rule"]["id"]), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "DELETE", "/secrets/gh", None).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn no_ca_warning_once_the_domain_is_allowed() {
    let (_d, app) = app();
    call(
        &app,
        "POST",
        "/ca/domains",
        Some(json!({"domain":"github.com"})),
    )
    .await;
    call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"v"})),
    )
    .await;
    call(
        &app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    let v = json_of(&call(&app, "POST", "/rules", Some(rule_body(1))).await.1);
    assert!(v["ca_warning"].is_null());
}

#[tokio::test]
async fn rule_validation_errors_surface_as_400_with_the_policy_message() {
    let (_d, app) = app();
    call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"v"})),
    )
    .await;
    call(
        &app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    let cases: Vec<(Value, &str)> = vec![
        (json!({"host_pattern":"github"}), "host_pattern"),
        (json!({"host_pattern":"127.0.0.1"}), "host_pattern"),
        (json!({"path_pattern":"/a/../b"}), "path_pattern"),
        (
            json!({"kind":"query","target_name":"key","template":"abc"}),
            "template",
        ),
        (json!({"target_name":"Host"}), "target_name"),
        (json!({"secret_id":999}), "unknown secret"),
        (json!({"role":"ghost"}), ""),
    ];
    for (patch, needle) in cases {
        let mut b = rule_body(1);
        for (k, v) in patch.as_object().unwrap() {
            b[k] = v.clone();
        }
        let (st, body) = call(&app, "POST", "/rules", Some(b)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{patch} -> {body}");
        assert!(
            json_of(&body)["error"].as_str().unwrap().contains(needle),
            "{body}"
        );
    }
    // single-label host is rejected but localhost is accepted
    let mut b = rule_body(1);
    b["host_pattern"] = json!("localhost");
    assert_eq!(
        call(&app, "POST", "/rules", Some(b)).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn deleting_a_role_cascades_its_rules() {
    let (_d, app) = app();
    call(
        &app,
        "POST",
        "/secrets",
        Some(json!({"name":"gh","value":"v"})),
    )
    .await;
    call(
        &app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    call(&app, "POST", "/rules", Some(rule_body(1))).await;
    assert_eq!(
        json_of(&call(&app, "GET", "/rules?role=dev", None).await.1)
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        call(&app, "DELETE", "/roles/dev", None).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        json_of(&call(&app, "GET", "/rules", None).await.1)
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        call(&app, "DELETE", "/roles/dev", None).await.0,
        StatusCode::NOT_FOUND
    );
    // and the secret is free again
    assert_eq!(
        call(&app, "DELETE", "/secrets/gh", None).await.0,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn token_is_shown_once_and_can_be_revoked() {
    let e = env();
    let app = &e.app;
    call(
        app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    let (st, body) = call(
        app,
        "POST",
        "/tokens",
        Some(json!({"machine":"laptop","role":"dev","ttl_secs":3600})),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let created = json_of(&body);
    let token = created["token"].as_str().unwrap().to_string();
    let id = e.tokens.verify(&token).expect("API token verifies");
    assert_eq!((id.machine.as_str(), id.role.as_str()), ("laptop", "dev"));
    let listing = call(app, "GET", "/tokens", None).await.1;
    assert!(!listing.contains(&token));
    assert!(listing.contains(created["jti"].as_str().unwrap()));
    let jti = created["jti"].as_str().unwrap();
    assert_eq!(
        call(app, "DELETE", &format!("/tokens/{jti}"), None).await.0,
        StatusCode::NO_CONTENT
    );
    assert!(e.tokens.verify(&token).is_err());
    assert_eq!(
        call(app, "DELETE", &format!("/tokens/{jti}"), None).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn token_creation_validation() {
    let (_d, app) = app();
    call(
        &app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    let bad = [
        json!({"machine":"m","role":"ghost"}),
        json!({"machine":"","role":"dev"}),
        json!({"machine":"   ","role":"dev"}),
        json!({"machine":"a".repeat(129),"role":"dev"}),
        json!({"machine":"ev\nil","role":"dev"}),
        json!({"machine":"m","role":"dev","ttl_secs":315_360_001u64}),
        json!({"machine":"m","role":"dev","extra":1}),
        json!({"machine":"m","role":"../x"}),
    ];
    for b in bad {
        assert_eq!(
            call(&app, "POST", "/tokens", Some(b.clone())).await.0,
            StatusCode::BAD_REQUEST,
            "{b}"
        );
    }
    let ok = json!({"machine":"a".repeat(128),"role":"dev","ttl_secs":315_360_000u64});
    assert_eq!(
        call(&app, "POST", "/tokens", Some(ok)).await.0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn revoke_by_machine_and_path_validation() {
    let e = env();
    let app = &e.app;
    call(
        app,
        "POST",
        "/roles",
        Some(json!({"name":"dev","unmatched":"deny"})),
    )
    .await;
    let mut tokens = vec![];
    for m in ["laptop", "laptop", "other"] {
        let b = json_of(
            &call(
                app,
                "POST",
                "/tokens",
                Some(json!({"machine":m,"role":"dev"})),
            )
            .await
            .1,
        );
        tokens.push(b["token"].as_str().unwrap().to_string());
    }
    let (st, body) = call(app, "POST", "/machines/laptop/revoke", None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(json_of(&body)["revoked"], 2);
    assert!(e.tokens.verify(&tokens[0]).is_err() && e.tokens.verify(&tokens[1]).is_err());
    assert!(e.tokens.verify(&tokens[2]).is_ok());
    // jti must be a UUID, names must match [a-z0-9._-]
    assert_eq!(
        call(app, "DELETE", "/tokens/not-a-uuid", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(app, "GET", "/secrets/Bad%20Name", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(app, "DELETE", "/roles/UPPER", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(app, "DELETE", "/rules/abc", None).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(app, "POST", "/machines/ev%0Ail/revoke", None).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn ca_endpoints() {
    let (_d, app) = app();
    let (st, headers, pem) = send(
        &app,
        Request::builder()
            .uri("/ca/cert")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-pem-file");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    let (st, body) = call(
        &app,
        "POST",
        "/ca/domains",
        Some(json!({"domain":" GitHub.com "})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v = json_of(&body);
    assert!(v["notice"].as_str().unwrap().contains("reload"));
    assert_eq!(v["domains"], json!(["github.com"]));
    let (st, body) = call(&app, "POST", "/ca/domains", Some(json!({"domain":"com"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(json_of(&body)["error"].as_str().unwrap().contains("domain"));
    let (_, status) = call(&app, "GET", "/ca", None).await;
    assert!(status.contains("github.com"));
}

#[tokio::test]
async fn audit_filters_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    for (host, role, ts) in [
        ("a.com", "dev", 100),
        ("b.com", "ops", 200),
        ("a.com", "ops", 300),
    ] {
        let mut e = sg_core::audit::AuditEntry::new(host, "GET", "/p?secret=1", "allow");
        e.role = Some(role.into());
        e.ts = ts;
        vault.record_audit(&e).unwrap();
    }
    let app = api_router(AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: Arc::new(Sessions::new()),
        allowed_hosts: vec![],
    });
    let n = |q: &'static str| {
        let app = app.clone();
        async move {
            let (st, b) = call(&app, "GET", &format!("/audit{q}"), None).await;
            (
                st,
                if st == StatusCode::OK {
                    json_of(&b).as_array().unwrap().len()
                } else {
                    0
                },
            )
        }
    };
    assert_eq!(n("").await, (StatusCode::OK, 3));
    assert_eq!(n("?role=ops").await.1, 2);
    assert_eq!(n("?host=a.com").await.1, 2);
    assert_eq!(n("?since=250").await.1, 1);
    assert_eq!(n("?limit=1").await.1, 1);
    assert_eq!(n("?limit=1000").await.0, StatusCode::OK);
    assert_eq!(n("?limit=1001").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(n("?limit=abc").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(n("?since=abc").await.0, StatusCode::BAD_REQUEST);
    assert_eq!(n("?bogus=1").await.0, StatusCode::BAD_REQUEST);
    let body = call(&app, "GET", "/audit", None).await.1;
    assert!(!body.contains("secret=1"));
    assert!(json_of(&body)[0]["decision"] == "allow");
}

#[tokio::test]
async fn unknown_routes_404_and_wrong_methods_405() {
    let (_d, app) = app();
    let (st, _, body) = send(
        &app,
        Request::builder().uri("/nope").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert!(json_of(&body)["error"].is_string());
    assert_eq!(
        call(&app, "PATCH", "/secrets", None).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        call(&app, "DELETE", "/ca", None).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        call(&app, "GET", "/machines/x/revoke", None).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn oversized_bodies_get_413_and_wrong_content_type_gets_415() {
    let (_d, app) = app();
    let big = json!({"name":"x","value":"a".repeat(70 * 1024)}).to_string();
    assert_eq!(
        raw(&app, "POST", "/secrets", Some("application/json"), big).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let ok = json!({"name":"x","value":"v"}).to_string();
    for ct in [
        Some("application/x-www-form-urlencoded"),
        Some("text/plain"),
        Some("multipart/form-data; boundary=x"),
        None,
    ] {
        assert_eq!(
            raw(&app, "POST", "/secrets", ct, ok.clone()).await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{ct:?}"
        );
    }
    // body-less write endpoints also refuse form posts
    assert_eq!(
        raw(
            &app,
            "POST",
            "/machines/x/revoke",
            Some("application/x-www-form-urlencoded"),
            String::new()
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        raw(
            &app,
            "DELETE",
            "/secrets/x",
            Some("text/plain"),
            "junk".into()
        )
        .await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        raw(
            &app,
            "POST",
            "/secrets",
            Some("application/json; charset=utf-8"),
            ok
        )
        .await,
        StatusCode::CREATED
    );
    // malformed JSON and unknown fields are 400 with the JSON error shape
    assert_eq!(
        raw(
            &app,
            "POST",
            "/secrets",
            Some("application/json"),
            "{".into()
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        raw(
            &app,
            "POST",
            "/secrets",
            Some("application/json"),
            json!({"name":"y","value":"v","x":1}).to_string()
        )
        .await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn error_bodies_never_leak_internals() {
    let (_d, app) = app();
    for (m, u, b) in [
        ("GET", "/secrets/missing", None),
        ("POST", "/rules", Some(json!({"role":"x"}))),
        ("DELETE", "/rules/99999", None),
    ] {
        let (_, body) = call(&app, m, u, b).await;
        let lower = body.to_lowercase();
        assert!(json_of(&body)["error"].is_string());
        for leak in [
            "sqlite", "select ", "insert ", "/tmp", ".db", "rusqlite", "panicked",
        ] {
            assert!(!lower.contains(leak), "{body}");
        }
    }
}
