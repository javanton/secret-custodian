use crate::{upstream::ProxyBody, ProxyState};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sg_auth::{extract_proxy_token, Identity};
use sg_core::audit::AuditEntry;
use sg_policy::{get_role, has_rules_for_host, list_rules, normalize_host, Unmatched};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

/// Longest `Proxy-Authorization` value we are willing to parse (longer means 407).
const MAX_PROXY_AUTH_LEN: usize = 8 * 1024;

/// An authenticated client: who it is and the raw token that proved it.
///
/// The token is kept so that the MITM loop (Task 8) can call `state.verifier.verify(&token)` on
/// every request inside a CONNECT tunnel: revoking a token must stop an already-open tunnel.
pub(crate) struct Session {
    pub identity: Identity,
    #[allow(dead_code)] // consumed by the MITM re-verification added in Task 8
    pub token: Zeroizing<String>,
}

pub async fn handle_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
    header_read_timeout: Duration,
) -> Result<(), hyper::Error> {
    let svc = service_fn(move |req| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(req, state).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades()
        .await
}

pub(crate) fn text(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let mut r = Response::new(
        Full::new(Bytes::from(msg.to_string()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *r.status_mut() = status;
    r
}

fn empty(status: StatusCode) -> Response<ProxyBody> {
    let mut r = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *r.status_mut() = status;
    r
}

fn proxy_auth_required() -> Response<ProxyBody> {
    let mut r = text(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    r.headers_mut().insert(
        "proxy-authenticate",
        "Basic realm=\"secret-guardian\"".parse().unwrap(),
    );
    r
}

fn authenticate<B>(req: &Request<B>, state: &ProxyState) -> Option<Session> {
    let mut values = req
        .headers()
        .get_all(hyper::header::PROXY_AUTHORIZATION)
        .iter();
    let value = values.next()?;
    // Exactly one credential, and bounded, before any parsing or signature work.
    if values.next().is_some() || value.len() > MAX_PROXY_AUTH_LEN {
        return None;
    }
    let token = Zeroizing::new(extract_proxy_token(value.to_str().ok()?)?);
    let identity = state.verifier.verify(&token).ok()?;
    Some(Session { identity, token })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit(
    state: &ProxyState,
    id: &Identity,
    host: &str,
    method: &str,
    path: &str,
    decision: &str,
    status: Option<u16>,
    rule_id: Option<i64>,
) {
    let mut e = AuditEntry::new(host, method, path, decision);
    e.jti = Some(id.jti.clone());
    e.machine = Some(id.machine.clone());
    e.role = Some(id.role.clone());
    e.status = status;
    e.rule_id = rule_id;
    if let Err(err) = state.vault.record_audit(&e) {
        tracing::error!(error = %err, "failed to write audit entry");
    }
}

async fn handle_request(req: Request<Incoming>, state: Arc<ProxyState>) -> Response<ProxyBody> {
    let Some(session) = authenticate(&req, &state) else {
        return proxy_auth_required();
    };
    if req.method() == Method::CONNECT {
        connect(req, session, state).await
    } else {
        text(
            StatusCode::NOT_IMPLEMENTED,
            "plain HTTP proxying is not enabled yet\n",
        )
    }
}

async fn connect(
    req: Request<Incoming>,
    session: Session,
    state: Arc<ProxyState>,
) -> Response<ProxyBody> {
    let identity = &session.identity;
    let Some(authority) = req.uri().authority().cloned() else {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT target\n");
    };
    // `user:pw@host` is never a legitimate CONNECT target.
    if authority.as_str().contains('@') {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT target\n");
    }
    let Some(host) = normalize_host(authority.host()) else {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT host\n");
    };
    let port = authority.port_u16().unwrap_or(443);
    if port == 0 {
        return text(StatusCode::BAD_REQUEST, "bad CONNECT port\n");
    }

    let role = match get_role(&state.vault, &identity.role) {
        Ok(Some(r)) => r,
        _ => {
            audit(
                &state,
                identity,
                &host,
                "CONNECT",
                "/",
                "unknown-role",
                Some(403),
                None,
            );
            return text(StatusCode::FORBIDDEN, "role not found\n");
        }
    };
    let rules = list_rules(&state.vault, Some(&identity.role)).unwrap_or_default();

    if has_rules_for_host(&rules, &host) {
        if !state.ca.is_host_permitted(&host) {
            audit(
                &state,
                identity,
                &host,
                "CONNECT",
                "/",
                "ca-not-permitted",
                Some(502),
                None,
            );
            return text(
                StatusCode::BAD_GATEWAY,
                &format!("the CA does not permit {host}; run `sg ca allow-domain <domain>` and reload the CA certificate\n"),
            );
        }
        audit(
            &state,
            identity,
            &host,
            "CONNECT",
            "/",
            "mitm",
            Some(200),
            None,
        );
        tokio::spawn(crate::mitm::serve(req, host, port, session, state));
        return empty(StatusCode::OK);
    }

    match role.unmatched {
        Unmatched::Deny => {
            audit(
                &state,
                identity,
                &host,
                "CONNECT",
                "/",
                "unmatched-denied",
                Some(403),
                None,
            );
            text(StatusCode::FORBIDDEN, "host not allowed for this role\n")
        }
        Unmatched::Passthrough => {
            // Reach the destination first: only then answer 200.
            let Ok(mut upstream) = state.upstream.connect_tcp(&host, port).await else {
                audit(
                    &state,
                    identity,
                    &host,
                    "CONNECT",
                    "/",
                    "tunnel-connect-failed",
                    Some(502),
                    None,
                );
                return text(StatusCode::BAD_GATEWAY, "could not reach the destination\n");
            };
            audit(
                &state,
                identity,
                &host,
                "CONNECT",
                "/",
                "passthrough",
                Some(200),
                None,
            );
            tokio::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(req).await {
                    let mut client = TokioIo::new(upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
            empty(StatusCode::OK)
        }
    }
}
