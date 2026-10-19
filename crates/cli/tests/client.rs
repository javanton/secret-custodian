use axum::{body::Body, http::Request, routing::get, Json, Router};
use serde_json::json;
use tokio::net::UnixListener;

/// A private (0700) directory, as the client now requires for the socket's parent.
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[tokio::test]
async fn call_roundtrips_json_over_a_unix_socket() {
    let dir = private_tempdir();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().route("/ping", get(|| async { Json(json!({"pong": true})) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (st, v) = sg_cli::call(&sock, http::Method::GET, "/ping", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    assert_eq!(v["pong"], true);
}

#[tokio::test]
async fn missing_socket_gives_an_actionable_error() {
    let err = sg_cli::call(
        std::path::Path::new("/nonexistent/sg.sock"),
        http::Method::GET,
        "/ping",
        None,
    )
    .await
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("sg serve"), "{msg}");
    assert!(msg.contains("/nonexistent/sg.sock"), "{msg}");
}

#[tokio::test]
async fn writes_declare_json_content_type() {
    let dir = private_tempdir();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().fallback(|req: Request<Body>| async move {
        let ct = req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        Json(json!({ "ct": ct }))
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (_, v) = sg_cli::call(&sock, http::Method::POST, "/x", Some(json!({"a": 1})))
        .await
        .unwrap();
    assert_eq!(v["ct"], "application/json");
}

#[tokio::test]
async fn oversized_responses_are_refused() {
    let dir = private_tempdir();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().fallback(|| async { "a".repeat(2 * 1024 * 1024) });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let err = sg_cli::call(&sock, http::Method::GET, "/big", None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

#[tokio::test]
async fn non_json_and_non_utf8_responses_do_not_panic() {
    let dir = private_tempdir();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().fallback(|| async { vec![0xffu8, 0xfe, b'x'] });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (st, v) = sg_cli::call(&sock, http::Method::GET, "/bin", None)
        .await
        .unwrap();
    assert_eq!(st, 200);
    assert!(v.is_string());
}

#[tokio::test]
async fn oversized_request_bodies_are_refused_before_connecting() {
    let big = json!({ "v": "a".repeat(2 * 1024 * 1024) });
    let err = sg_cli::call(
        std::path::Path::new("/nonexistent/sg.sock"),
        http::Method::POST,
        "/x",
        Some(big),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

#[tokio::test]
async fn refuses_a_socket_whose_directory_is_open_to_others() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let app = Router::new().route("/ping", get(|| async { Json(json!({"pong": true})) }));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let err = sg_cli::call(&sock, http::Method::GET, "/ping", None)
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("accessible to group/others"), "{msg}");
    assert!(msg.contains(dir.path().to_str().unwrap()), "{msg}");
}

#[tokio::test]
async fn refuses_a_group_writable_socket_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = private_tempdir();
    let sock = dir.path().join("t.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = sg_cli::call(&sock, http::Method::GET, "/ping", None)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("writable by group/others"),
        "{err}"
    );
}
