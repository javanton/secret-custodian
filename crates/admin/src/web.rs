use crate::{
    api::{api_router, write_guard},
    error::ApiError,
    state::AppState,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{from_fn, from_fn_with_state, map_response, Next},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;

#[derive(RustEmbed)]
#[folder = "../../web/"]
struct Assets;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Requests to `/login` are small JSON documents.
const MAX_LOGIN_BODY: usize = 64 * 1024;

/// Router for the local web listener: `Host` guard on everything, `POST /login` to trade a
/// one-time token for a session id, `/api/*` behind a `Bearer` session check, and the
/// embedded frontend.
///
/// The session id is deliberately not a cookie: browsers share host-only cookies between
/// every `localhost` port, so another local web server could read it. The UI keeps it in
/// `sessionStorage` (scoped by origin, port included) and sends `Authorization: Bearer`.
/// The login token arrives in a URL fragment (never sent to a server) and is posted in a
/// JSON body, so it appears in no URL, log or `Referer`; no request-logging layer exists.
pub fn web_router(state: AppState) -> Router {
    let api = api_router(state.clone()).layer(from_fn_with_state(state.clone(), session_guard));
    let login_route = post(login)
        .fallback(|| async { ApiError::not_found() })
        .layer(DefaultBodyLimit::max(MAX_LOGIN_BODY))
        .layer(from_fn(write_guard))
        .layer(from_fn_with_state(state.clone(), origin_guard));
    Router::new()
        .route("/login", login_route)
        .fallback(static_asset)
        .with_state(state.clone())
        .nest("/api", api)
        .layer(from_fn_with_state(state, host_guard))
        .layer(map_response(security_headers))
}

async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    resp
}

async fn host_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| s.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h)));
    if !ok {
        return (StatusCode::MISDIRECTED_REQUEST, "unexpected Host header").into_response();
    }
    next.run(req).await
}

fn unauthorized() -> Response {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "login required: use the URL printed by `sc serve`".into(),
    )
    .into_response()
}

/// The session id from exactly one `Authorization: Bearer <id>` header (scheme is
/// case-insensitive). Anything else, cookies included, is ignored.
fn bearer_session(req: &Request) -> Option<&str> {
    let mut all = req.headers().get_all(header::AUTHORIZATION).iter();
    let value = all.next()?.to_str().ok()?;
    if all.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() && !token.contains(' '))
        .then_some(token)
}

/// A present `Origin` must be exactly `http://<allowed host>` (the web listener is plain HTTP).
fn origin_allowed(req: &Request, s: &AppState) -> bool {
    match req.headers().get(header::ORIGIN) {
        None => true,
        Some(o) => o
            .to_str()
            .ok()
            .and_then(|o| o.strip_prefix("http://"))
            .is_some_and(|h| s.allowed_hosts.iter().any(|a| a.eq_ignore_ascii_case(h))),
    }
}

fn cross_origin() -> Response {
    ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into()).into_response()
}

async fn origin_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    if !origin_allowed(&req, &s) {
        return cross_origin();
    }
    next.run(req).await
}

/// Authentication comes first (so an unauthenticated caller learns nothing about content
/// types or bodies), then the `Origin` check on writes. There is no CSRF header: the
/// credential is not ambient, a cross-site page cannot attach `Authorization` without a CORS
/// preflight, and this server answers none.
async fn session_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match bearer_session(&req) {
        Some(id) if s.sessions.is_valid(id) => {}
        _ => return unauthorized(),
    }
    let is_write = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_write && !origin_allowed(&req, &s) {
        return cross_origin();
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct LoginBody {
    token: String,
}

/// Same `401` for missing, unknown, used, expired and malformed tokens; the token is never
/// echoed. A body that is not the expected JSON is a plain `400` that does not repeat it.
async fn login(State(s): State<AppState>, body: Bytes) -> Response {
    let Ok(LoginBody { token }) = serde_json::from_slice(&body) else {
        return ApiError::bad_request("invalid JSON body").into_response();
    };
    match s.sessions.exchange(&token) {
        Some(session) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "session": session })),
        )
            .into_response(),
        None => ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid or already used login token".into(),
        )
        .into_response(),
    }
}

async fn static_asset(req: Request) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = req.uri().path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path) {
        Some(file) => (
            [(header::CONTENT_TYPE, content_type(path))],
            file.data.into_owned(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Content type by extension (the embedded frontend only has a handful of file kinds).
fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
