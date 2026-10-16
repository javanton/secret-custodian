use axum::{
    body::Body,
    http::{header, HeaderMap, Request, StatusCode},
};
use http_body_util::BodyExt;
use sg_admin::{web_router, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::sync::Arc;
use tower::ServiceExt;

async fn get(path: &str) -> (StatusCode, HeaderMap, String) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(
        Vault::init(
            &dir.path().join("v.db"),
            KeyInput::Raw(crypto::random_key()),
        )
        .unwrap(),
    );
    let app = web_router(AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: Arc::new(Sessions::new()),
        allowed_hosts: vec!["localhost:9090".into()],
        web_base_url: None,
    });
    let r = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::HOST, "localhost:9090")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let st = r.status();
    let headers = r.headers().clone();
    let body = r.into_body().collect().await.unwrap().to_bytes();
    (st, headers, String::from_utf8_lossy(&body).to_string())
}

#[tokio::test]
async fn assets_are_served_with_types_and_security_headers() {
    for (p, ct) in [
        ("/", "text/html; charset=utf-8"),
        ("/app.js", "text/javascript; charset=utf-8"),
        ("/style.css", "text/css; charset=utf-8"),
    ] {
        let (st, h, body) = get(p).await;
        assert_eq!(st, StatusCode::OK, "{p}");
        assert_eq!(h[header::CONTENT_TYPE], ct, "{p}");
        assert!(body.len() > 200, "{p} looks like a placeholder");
        assert!(h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'"));
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["x-frame-options"], "DENY");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
    }
}

#[tokio::test]
async fn frontend_never_uses_dangerous_dom_sinks_or_ambient_credentials() {
    let (_, _, js) = get("/app.js").await;
    for sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "localStorage",
        "document.cookie",
        "X-SG-CSRF",
        "credentials: \"include\"",
        "credentials: \"same-origin\"",
        "setAttribute(\"style\"",
        "setAttribute('style'",
    ] {
        assert!(!js.contains(sink), "app.js uses {sink}");
    }
}

#[tokio::test]
async fn index_html_is_inert() {
    let (_, _, html) = get("/").await;
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "index.html references an external origin"
    );
    assert!(
        !html.contains("style="),
        "inline style is blocked by the CSP"
    );
    // every <script> must be an external one with an empty body
    let mut rest = html.as_str();
    while let Some(i) = rest.find("<script") {
        let tag_end = rest[i..].find('>').unwrap() + i;
        assert!(
            rest[i..tag_end].contains("src=\"/app.js\""),
            "inline script"
        );
        let close = rest[tag_end..].find("</script>").unwrap() + tag_end;
        assert!(
            rest[tag_end + 1..close].trim().is_empty(),
            "inline script body"
        );
        rest = &rest[close..];
    }
    // no on*= event handler attributes inside any tag
    for tag in html.split('<').skip(1) {
        let tag = tag.split('>').next().unwrap().to_lowercase();
        for word in tag.split_whitespace() {
            assert!(
                !(word.starts_with("on") && word.contains('=')),
                "event handler attribute in <{tag}>"
            );
        }
    }
}

#[tokio::test]
async fn frontend_uses_fragment_session_storage_and_bearer() {
    let (_, _, js) = get("/app.js").await;
    for needle in [
        "sessionStorage",
        "Authorization",
        "Bearer",
        "replaceState",
        "location.hash",
        "credentials: \"omit\"",
    ] {
        assert!(js.contains(needle), "app.js lacks {needle}");
    }
}

/// Runs the node-based logic tests (fragment parsing, 401 handling, `el()` never parsing HTML,
/// hostile strings rendered as text). Skipped when `node` is not installed.
#[test]
fn js_logic_tests_under_node() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/js/app.test.js");
    let Ok(out) = std::process::Command::new("node")
        .arg("--test")
        .arg(&dir)
        .output()
    else {
        eprintln!("node not found: skipping JS logic tests");
        return;
    };
    assert!(
        out.status.success(),
        "node tests failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
