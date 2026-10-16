use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// API error: a status plus a static, client-safe message. Internal details (SQL, paths)
/// are logged, never returned.
#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);
pub type ApiResult<T> = Result<T, ApiError>;

const INTERNAL: &str = "internal error";

impl ApiError {
    pub fn bad_request(msg: &str) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "not found".into())
    }

    fn internal(e: &dyn std::fmt::Display) -> Self {
        tracing::error!(error = %e, "admin api internal error");
        Self(StatusCode::INTERNAL_SERVER_ERROR, INTERNAL.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<sg_core::CoreError> for ApiError {
    fn from(e: sg_core::CoreError) -> Self {
        use sg_core::CoreError::*;
        match e {
            InvalidSecretValue(m) => Self(
                StatusCode::BAD_REQUEST,
                format!("invalid secret value: {m}"),
            ),
            InvalidName(m) => Self(StatusCode::BAD_REQUEST, format!("invalid name: {m}")),
            InvalidKey => Self::bad_request("invalid key material"),
            NotFound => Self::not_found(),
            AlreadyExists => Self(StatusCode::CONFLICT, "already exists".into()),
            InUse => Self(StatusCode::CONFLICT, "still referenced by a rule".into()),
            // WrongKey, KeySourceMismatch, UnsupportedSchema, Crypto, Db, Io
            other => Self::internal(&other),
        }
    }
}

impl From<sg_policy::PolicyError> for ApiError {
    fn from(e: sg_policy::PolicyError) -> Self {
        use sg_policy::PolicyError::*;
        match e {
            Invalid(m) => Self(StatusCode::BAD_REQUEST, m.into()),
            NotFound => Self::not_found(),
            AlreadyExists => Self(StatusCode::CONFLICT, "already exists".into()),
            Core(c) => c.into(),
            Db(d) => Self::internal(&d),
        }
    }
}

impl From<sg_auth::AuthError> for ApiError {
    fn from(e: sg_auth::AuthError) -> Self {
        use sg_auth::AuthError;
        match e {
            AuthError::Core(sg_core::CoreError::NotFound) => Self::not_found(),
            AuthError::InvalidTtl => Self::bad_request("ttl out of range"),
            other => Self::internal(&other),
        }
    }
}

impl From<sg_ca::CaError> for ApiError {
    fn from(e: sg_ca::CaError) -> Self {
        match e {
            sg_ca::CaError::DomainRejected(m) => {
                Self(StatusCode::BAD_REQUEST, format!("domain rejected: {m}"))
            }
            other => Self::internal(&other),
        }
    }
}
