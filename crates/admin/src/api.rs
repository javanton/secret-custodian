//! JSON admin API. No handler ever touches secret plaintext: only metadata is returned.
//!
//! Handlers call the synchronous `Vault` directly (no `spawn_blocking`): operations are
//! short SQLite statements behind a mutex, and the admin API is low traffic. The proxy
//! makes the same trade-off.

use crate::{error::*, ops, state::AppState};
use axum::{
    extract::{
        rejection::PathRejection, DefaultBodyLimit, FromRequest, FromRequestParts, Path, Query,
        Request, State,
    },
    http::{header, request::Parts, Method, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use sg_core::{audit::AuditFilter, SecretMeta};
use sg_policy::{InjectionKind, NewRule, RuleSpec, Unmatched};
use std::time::Duration;

/// Every request body is capped at 64 KiB.
const MAX_BODY: usize = 64 * 1024;
const MAX_TTL_SECS: u64 = 315_360_000;
const MAX_MACHINE_LEN: usize = 128;
const MAX_AUDIT_LIMIT: usize = 1000;

/// Router for the Unix socket: no authentication of its own (the socket permissions are it).
pub fn api_router(state: AppState) -> Router {
    build_router(state, false)
}

/// [`api_router`] plus `POST /admin/login-token`, which mints a web login token. Only the Unix
/// socket router has it: whoever can open the socket (mode `0600`) is the operator, while the
/// web listener must never be able to mint its own credentials.
pub fn socket_router(state: AppState) -> Router {
    build_router(state, true)
}

fn build_router(state: AppState, socket_only: bool) -> Router {
    let router = Router::new()
        .route("/secrets", get(list_secrets).post(add_secret))
        .route(
            "/secrets/{name}",
            get(get_secret).put(rotate_secret).delete(delete_secret),
        )
        .route("/roles", get(list_roles).post(add_role))
        .route("/roles/{name}", delete(delete_role))
        .route("/rules", get(list_rules).post(add_rule))
        .route("/rules/{id}", delete(delete_rule))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{jti}", delete(revoke_token))
        .route("/machines/{machine}/revoke", post(revoke_machine))
        .route("/ca", get(ca_status))
        .route("/ca/cert", get(ca_cert))
        .route("/audit", get(audit));
    let router = if socket_only {
        router.route("/admin/login-token", post(login_token))
    } else {
        router
    };
    router
        .fallback(|| async { ApiError::not_found() })
        .method_not_allowed_fallback(|| async {
            ApiError(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into())
        })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(from_fn(write_guard))
        .with_state(state)
}

fn is_json_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

/// State-changing requests must be JSON: a cross-site HTML form cannot send that content type
/// without a CORS preflight. A body with no declared type is refused too.
pub(crate) async fn write_guard(req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let headers = req.headers();
        let ok = match headers.get(header::CONTENT_TYPE) {
            Some(ct) => ct.to_str().is_ok_and(is_json_content_type),
            None => {
                headers
                    .get(header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.trim() == "0")
                    || !headers.contains_key(header::CONTENT_LENGTH)
                        && !headers.contains_key(header::TRANSFER_ENCODING)
            }
        };
        if !ok {
            return ApiError(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "content type must be application/json".into(),
            )
            .into_response();
        }
    }
    next.run(req).await
}

// ---- extractors with JSON error bodies ------------------------------------------------------

struct JsonBody<T>(T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for JsonBody<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(r) => Err(match r.status() {
                StatusCode::PAYLOAD_TOO_LARGE => ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large".into(),
                ),
                StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "content type must be application/json".into(),
                ),
                _ => ApiError::bad_request("invalid JSON body"),
            }),
        }
    }
}

struct Q<T>(T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Q<T> {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(v)| Self(v))
            .map_err(|_| ApiError::bad_request("invalid query string"))
    }
}

/// A single path parameter, validated by the handler before it reaches the database.
struct Param(String);

impl<S: Send + Sync> FromRequestParts<S> for Param {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let r: Result<Path<String>, PathRejection> = Path::from_request_parts(parts, state).await;
        r.map(|Path(s)| Self(s))
            .map_err(|_| ApiError::bad_request("invalid path parameter"))
    }
}

// ---- validation -----------------------------------------------------------------------------

fn name_param(s: &str) -> ApiResult<&str> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if ok {
        Ok(s)
    } else {
        Err(ApiError::bad_request(
            "invalid name: use [a-z0-9._-], max 64 chars",
        ))
    }
}

fn jti_param(s: &str) -> ApiResult<&str> {
    let b = s.as_bytes();
    let ok = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        });
    if ok {
        Ok(s)
    } else {
        Err(ApiError::bad_request("invalid token id"))
    }
}

fn machine_name(s: &str) -> ApiResult<&str> {
    if s.trim().is_empty() || s.chars().count() > MAX_MACHINE_LEN || s.chars().any(char::is_control)
    {
        Err(ApiError::bad_request(
            "machine must be 1-128 characters without control characters",
        ))
    } else {
        Ok(s)
    }
}

// ---- secrets --------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSecret {
    name: String,
    value: String,
    /// Absent or empty is refused by `ops::create_secret` with a descriptive message.
    #[serde(default)]
    rules: Vec<RuleSpecBody>,
}

/// A rule as sent inside `POST /secrets`: the secret is the one being created.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpecBody {
    role: String,
    host_pattern: String,
    #[serde(default = "star")]
    path_pattern: String,
    #[serde(default)]
    methods: Vec<String>,
    kind: InjectionKind,
    target_name: String,
    template: String,
}

impl From<RuleSpecBody> for RuleSpec {
    fn from(b: RuleSpecBody) -> Self {
        Self {
            role: b.role,
            host_pattern: b.host_pattern,
            path_pattern: b.path_pattern,
            methods: b.methods,
            kind: b.kind,
            target_name: b.target_name,
            template: b.template,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateSecret {
    value: String,
}

async fn list_secrets(State(s): State<AppState>) -> ApiResult<Json<Vec<Value>>> {
    let list = s
        .vault
        .list_secrets_with_rule_counts()?
        .into_iter()
        .map(|(meta, rules)| {
            let mut v = serde_json::to_value(meta).unwrap_or(Value::Null);
            v["rules"] = json!(rules);
            v
        })
        .collect();
    Ok(Json(list))
}
async fn get_secret(State(s): State<AppState>, Param(name): Param) -> ApiResult<Json<SecretMeta>> {
    Ok(Json(s.vault.get_secret_meta(name_param(&name)?)?))
}
async fn add_secret(
    State(s): State<AppState>,
    JsonBody(b): JsonBody<NewSecret>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let c = ops::create_secret(
        &s,
        &b.name,
        &b.value,
        b.rules.into_iter().map(Into::into).collect(),
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "secret": c.secret,
            "rules": c.rules,
            "ca_changed": c.ca_changed,
            "notice": c.ca_changed.then_some(ops::CA_NOTICE),
        })),
    ))
}
async fn rotate_secret(
    State(s): State<AppState>,
    Param(name): Param,
    JsonBody(b): JsonBody<RotateSecret>,
) -> ApiResult<Json<SecretMeta>> {
    Ok(Json(s.vault.rotate_secret(name_param(&name)?, &b.value)?))
}
async fn delete_secret(State(s): State<AppState>, Param(name): Param) -> ApiResult<StatusCode> {
    ops::delete_secret(&s, name_param(&name)?)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- roles and rules ------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRole {
    name: String,
    unmatched: Unmatched,
}

async fn list_roles(State(s): State<AppState>) -> ApiResult<Json<Vec<sg_policy::Role>>> {
    Ok(Json(sg_policy::list_roles(&s.vault)?))
}
async fn add_role(
    State(s): State<AppState>,
    JsonBody(b): JsonBody<NewRole>,
) -> ApiResult<(StatusCode, Json<sg_policy::Role>)> {
    Ok((
        StatusCode::CREATED,
        Json(sg_policy::add_role(&s.vault, &b.name, b.unmatched)?),
    ))
}
async fn delete_role(State(s): State<AppState>, Param(name): Param) -> ApiResult<StatusCode> {
    ops::delete_role(&s, name_param(&name)?)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleQuery {
    role: Option<String>,
}

async fn list_rules(
    State(s): State<AppState>,
    Q(q): Q<RuleQuery>,
) -> ApiResult<Json<Vec<sg_policy::Rule>>> {
    let role = q.role.as_deref().map(name_param).transpose()?;
    Ok(Json(sg_policy::list_rules(&s.vault, role)?))
}

/// `NewRule` as sent over the wire: same fields as `sg_policy::NewRule`, but unknown fields
/// are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewRuleBody {
    role: String,
    host_pattern: String,
    #[serde(default = "star")]
    path_pattern: String,
    #[serde(default)]
    methods: Vec<String>,
    kind: InjectionKind,
    target_name: String,
    template: String,
    secret_id: i64,
}

fn star() -> String {
    "*".into()
}

async fn add_rule(
    State(s): State<AppState>,
    JsonBody(b): JsonBody<NewRuleBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let (rule, ca_changed) = ops::add_rule(
        &s,
        NewRule {
            role: b.role,
            host_pattern: b.host_pattern,
            path_pattern: b.path_pattern,
            methods: b.methods,
            kind: b.kind,
            target_name: b.target_name,
            template: b.template,
            secret_id: b.secret_id,
        },
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "rule": rule,
            "ca_changed": ca_changed,
            "notice": ca_changed.then_some(ops::CA_NOTICE),
        })),
    ))
}
async fn delete_rule(State(s): State<AppState>, Param(id): Param) -> ApiResult<StatusCode> {
    let id: i64 = id
        .parse()
        .ok()
        .filter(|i| *i > 0)
        .ok_or_else(|| ApiError::bad_request("invalid rule id"))?;
    ops::delete_rule(&s, id)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- tokens ---------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewToken {
    machine: String,
    role: String,
    ttl_secs: Option<u64>,
}

async fn create_token(
    State(s): State<AppState>,
    JsonBody(b): JsonBody<NewToken>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    machine_name(&b.machine)?;
    if b.ttl_secs.is_some_and(|t| t > MAX_TTL_SECS) {
        return Err(ApiError::bad_request(
            "ttl_secs must be at most 10 years (315360000)",
        ));
    }
    let role = name_param(&b.role).map_err(|_| ApiError::bad_request("unknown role"))?;
    if sg_policy::get_role(&s.vault, role)?.is_none() {
        return Err(ApiError::bad_request("unknown role"));
    }
    let t = s
        .tokens
        .issue(&b.machine, role, b.ttl_secs.map(Duration::from_secs))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "token": t.token, "jti": t.jti, "machine": b.machine, "role": b.role })),
    ))
}
async fn list_tokens(State(s): State<AppState>) -> ApiResult<Json<Vec<sg_auth::TokenMeta>>> {
    Ok(Json(s.tokens.list()?))
}
async fn revoke_token(State(s): State<AppState>, Param(jti): Param) -> ApiResult<StatusCode> {
    s.tokens.revoke(jti_param(&jti)?)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn revoke_machine(
    State(s): State<AppState>,
    Param(machine): Param,
) -> ApiResult<Json<Value>> {
    let n = s.tokens.revoke_machine(machine_name(&machine)?)?;
    Ok(Json(json!({ "revoked": n })))
}

// ---- CA -------------------------------------------------------------------------------------

async fn ca_status(State(s): State<AppState>) -> Json<Value> {
    Json(json!({ "domains": s.ca.domains() }))
}
async fn ca_cert(State(s): State<AppState>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        s.ca.cert_pem(),
    )
}

// ---- audit ----------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQuery {
    limit: Option<usize>,
    role: Option<String>,
    host: Option<String>,
    since: Option<i64>,
}

async fn audit(
    State(s): State<AppState>,
    Q(q): Q<AuditQuery>,
) -> ApiResult<Json<Vec<sg_core::audit::AuditEntry>>> {
    if q.limit.is_some_and(|l| l == 0 || l > MAX_AUDIT_LIMIT) {
        return Err(ApiError::bad_request("limit must be between 1 and 1000"));
    }
    let role = q
        .role
        .as_deref()
        .map(name_param)
        .transpose()?
        .map(String::from);
    if let Some(h) = &q.host {
        if h.is_empty() || h.len() > 253 || h.chars().any(char::is_control) {
            return Err(ApiError::bad_request("invalid host filter"));
        }
    }
    let f = AuditFilter {
        role,
        host: q.host,
        since: q.since,
        limit: q.limit.unwrap_or(0),
    };
    Ok(Json(s.vault.list_audit(&f)?))
}

/// Mints a single-use web login token; `url` is present when the server knows its public base.
async fn login_token(State(s): State<AppState>) -> impl IntoResponse {
    let token = s.sessions.new_login_token();
    let mut body = serde_json::json!({ "token": token });
    if let Some(base) = &s.web_base_url {
        body["url"] = format!("{}/#t={token}", base.trim_end_matches('/')).into();
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(body))
}
