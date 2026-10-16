use crate::{api::api_router, state::AppState};
use axum::{
    extract::{Query, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{from_fn_with_state, map_response, Next},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use rust_embed::RustEmbed;
use serde::Deserialize;

#[derive(RustEmbed)]
#[folder = "../../web/"]
struct Assets;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Router for the local web listener: `Host` guard on everything, `/login` to trade a
/// one-time token for a session cookie, `/api/*` behind session + CSRF checks, and the
/// embedded frontend. No request-logging layer is installed on purpose: the login token
/// travels once in a query string and must not reach any log.
pub fn web_router(state: AppState) -> Router {
    let api = api_router(state.clone()).layer(from_fn_with_state(state.clone(), session_guard));
    Router::new()
        .route("/login", get(login))
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

fn session_cookie(req: &Request) -> Option<String> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .find_map(|p| p.trim().strip_prefix("sg_session=").map(String::from))
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

async fn session_guard(State(s): State<AppState>, req: Request, next: Next) -> Response {
    match session_cookie(&req) {
        Some(c) if s.sessions.is_valid(&c) => {}
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "login required: use the URL printed by `sg serve`",
            )
                .into_response()
        }
    }
    let is_write = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_write {
        if !req.headers().contains_key("x-sg-csrf") {
            return (StatusCode::FORBIDDEN, "missing X-SG-CSRF header").into_response();
        }
        if !origin_allowed(&req, &s) {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct LoginQuery {
    t: Option<String>,
}

/// Same `401` for missing, unknown, used and evicted tokens; the token is never echoed.
async fn login(
    State(s): State<AppState>,
    q: Result<Query<LoginQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let session = q
        .ok()
        .and_then(|Query(q)| q.t)
        .and_then(|t| s.sessions.exchange(&t));
    match session {
        Some(session) => {
            let cookie =
                format!("sg_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800");
            let mut r = Redirect::to("/").into_response();
            r.headers_mut().insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&cookie).expect("hex cookie is a valid header value"),
            );
            r
        }
        None => (
            StatusCode::UNAUTHORIZED,
            "invalid or already used login link",
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
