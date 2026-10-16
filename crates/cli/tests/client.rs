use axum::{body::Body, http::Request, routing::get, Json, Router};
use serde_json::json;
use tokio::net::UnixListener;

#[tokio::test]
async fn call_roundtrips_json_over_a_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
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
