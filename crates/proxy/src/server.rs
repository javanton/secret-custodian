use crate::{
    authaudit::AuthAuditLimiter,
    ident::IdentityCounters,
    upstream::{ProxyBody, UpstreamError},
    ProxyState,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sg_auth::{extract_proxy_token, AuthError, Identity};
use sg_core::audit::AuditEntry;
use sg_policy::{get_role, has_rules_for_host, list_rules, normalize_host, Unmatched};
use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::OwnedSemaphorePermit,
    time::Instant,
};
use zeroize::Zeroizing;

/// Longest `Proxy-Authorization` value we are willing to parse (longer means 407).
const MAX_PROXY_AUTH_LEN: usize = 8 * 1024;

/// An authenticated client: who it is and the raw token that proved it.
///
/// The token is kept so that the MITM loop (Task 8) can call `state.verifier.verify(&token)` on
/// every request inside a CONNECT tunnel: revoking a token must stop an already-open tunnel.
pub(crate) struct Session {
    pub identity: Identity,
    pub token: Zeroizing<String>,
}

/// Limits applied to a client connection and to the tunnels and requests it carries.
#[derive(Clone)]
pub(crate) struct Limits {
    pub header_read_timeout: Duration,
    pub tunnel_idle_timeout: Duration,
    pub tunnel_max_lifetime: Duration,
    pub max_tunnels_per_identity: usize,
    pub max_upstream_per_identity: usize,
    pub body_idle_timeout: Duration,
    /// Live tunnels / upstream requests per token identity, shared by every connection.
    pub tunnels: Arc<IdentityCounters>,
    pub upstream: Arc<IdentityCounters>,
    /// Rate limit of the audit of revoked/expired tokens, shared by every connection.
    pub auth_audit: Arc<AuthAuditLimiter>,
}

/// The connection-cap slot. Cloned into every task a CONNECT spawns, so it is released only
/// when the connection AND its tunnel are gone.
pub(crate) type Slot = Arc<OwnedSemaphorePermit>;

/// Wraps a stream and fails reads/writes with `TimedOut` once nothing moved in either direction
/// for `idle`.
///
/// Besides the shared idle timer (reset by progress in either direction), a write that stays
/// pending for `idle` fails on its own: a peer that stopped reading is cut even while the other
/// direction keeps moving.
pub(crate) struct IdleIo<T> {
    inner: T,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    write_stall: Pin<Box<tokio::time::Sleep>>,
    write_pending: bool,
}

impl<T> IdleIo<T> {
    pub fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            write_stall: Box::pin(tokio::time::sleep(idle)),
            write_pending: false,
        }
    }

    fn progressed(&mut self) {
        self.sleep.as_mut().reset(Instant::now() + self.idle);
    }

    fn check_idle(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        self.sleep
            .as_mut()
            .poll(cx)
            .is_ready()
            .then(|| io::Error::new(io::ErrorKind::TimedOut, "tunnel idle timeout"))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                self.progressed();
                Poll::Ready(r)
            }
            Poll::Pending => match self.check_idle(cx) {
                Some(e) => Poll::Ready(Err(e)),
                None => Poll::Pending,
            },
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                self.progressed();
                self.write_pending = false;
                Poll::Ready(r)
            }
            Poll::Pending => {
                if !self.write_pending {
                    self.write_pending = true;
                    let deadline = Instant::now() + self.idle;
                    self.write_stall.as_mut().reset(deadline);
                }
                if self.write_stall.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tunnel write stalled",
                    )));
                }
                match self.check_idle(cx) {
                    Some(e) => Poll::Ready(Err(e)),
                    None => Poll::Pending,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub async fn handle_connection(
    stream: TcpStream,
    state: Arc<ProxyState>,
    limits: Limits,
    slot: Slot,
) -> Result<(), hyper::Error> {
    let (lifetime, header_timeout) = (limits.tunnel_max_lifetime, limits.header_read_timeout);
    let svc = service_fn(move |req| {
        let (state, slot, limits) = (state.clone(), slot.clone(), limits.clone());
        async move { Ok::<_, Infallible>(handle_request(req, state, limits, slot).await) }
    });
    let conn = hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout)
        .serve_connection(TokioIo::new(stream), svc)
        .with_upgrades();
    // A client connection (keep-alive plain requests included) lives at most as long as a
    // tunnel. A CONNECT hands its socket off to the tunnel task, which has its own bound.
    match tokio::time::timeout(lifetime, conn).await {
        Ok(r) => r,
        Err(_) => Ok(()),
    }
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

/// An authenticated request that is malformed: audited (decision `bad-request`) and answered
/// 400. `host` is whatever the target declared (untrusted, truncated). Unauthenticated
/// requests never reach this (they get 407 and write nothing).
fn bad_request(
    state: &ProxyState,
    id: &Identity,
    host: &str,
    method: &str,
    msg: &str,
) -> Response<ProxyBody> {
    let host: String = host.chars().take(255).collect();
    audit(
        state,
        id,
        &host,
        method,
        "/",
        "bad-request",
        Some(400),
        None,
    );
    text(StatusCode::BAD_REQUEST, msg)
}

/// 429 with `Retry-After: 1`, audited as `identity-limit`.
pub(crate) fn identity_limit(
    state: &ProxyState,
    id: &Identity,
    host: &str,
    method: &str,
    path: &str,
    rule_id: Option<i64>,
    msg: &str,
) -> Response<ProxyBody> {
    audit(
        state,
        id,
        host,
        method,
        path,
        "identity-limit",
        Some(429),
        rule_id,
    );
    let mut r = text(StatusCode::TOO_MANY_REQUESTS, msg);
    r.headers_mut()
        .insert("retry-after", hyper::header::HeaderValue::from_static("1"));
    r
}

fn proxy_auth_required() -> Response<ProxyBody> {
    let mut r = text(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    r.headers_mut().insert(
        "proxy-authenticate",
        "Basic realm=\"secret-custodian\"".parse().unwrap(),
    );
    r
}

/// Who a failed authentication was for, when that is known: only a token with a valid signature
/// and issuer that is revoked or expired. It is NEVER a session; its sole use is the rate-limited
/// `token-invalid` audit row. Every other failure (missing, malformed, oversized, duplicated,
/// wrongly signed, wrong issuer, unknown jti, verifier error) is anonymous and writes nothing.
struct Rejected(Option<Identity>);

fn authenticate<B>(req: &Request<B>, state: &ProxyState) -> Result<Session, Rejected> {
    let anonymous = || Rejected(None);
    let mut values = req
        .headers()
        .get_all(hyper::header::PROXY_AUTHORIZATION)
        .iter();
    let value = values.next().ok_or_else(anonymous)?;
    // Exactly one credential, and bounded, before any parsing or signature work.
    if values.next().is_some() || value.len() > MAX_PROXY_AUTH_LEN {
        return Err(anonymous());
    }
    let token = Zeroizing::new(
        value
            .to_str()
            .ok()
            .and_then(extract_proxy_token)
            .ok_or_else(anonymous)?,
    );
    match state.verifier.verify(&token) {
        Ok(identity) => Ok(Session { identity, token }),
        Err(AuthError::Expired(id) | AuthError::Revoked(id)) => Err(Rejected(Some(id))),
        Err(_) => Err(anonymous()),
    }
}

/// Audits (`token-invalid`, 407) a request whose token was validly signed but is revoked or
/// expired, at most once per `jti` per interval and within a bounded map (see `AuthAuditLimiter`).
/// `host` is whatever the request declared: untrusted, truncated. An audit write failure is
/// logged like every other audit; the answer is the same 407 regardless.
fn audit_rejected<B>(req: &Request<B>, rejected: &Identity, state: &ProxyState, limits: &Limits) {
    if !limits
        .auth_audit
        .allow(&rejected.jti, std::time::Instant::now())
    {
        return;
    }
    let host: String = req.uri().host().unwrap_or("").chars().take(255).collect();
    // The method is untrusted too (extension methods): bounded like the host.
    let method: String = req.method().as_str().chars().take(32).collect();
    audit(
        state,
        rejected,
        &host,
        &method,
        "/",
        "token-invalid",
        Some(407),
        None,
    );
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

/// Audits a forwarded request exactly once.
///
/// Created right before the upstream request is dispatched and finished (`finish`) when the
/// outcome is known. If it is dropped first - the agent closed the connection or reset the
/// stream, so the handler future was dropped while the credential may already be on its way -
/// the row is written as `client-aborted` with no status.
pub(crate) struct AuditGuard {
    state: Arc<ProxyState>,
    identity: Identity,
    host: String,
    method: String,
    path: String,
    rule_id: Option<i64>,
    /// `inject` or `passthrough`: the decision recorded when the response head arrives.
    decision: &'static str,
    done: bool,
}

impl AuditGuard {
    pub fn new(
        state: &Arc<ProxyState>,
        identity: &Identity,
        host: &str,
        method: &str,
        path: &str,
        rule_id: Option<i64>,
    ) -> Self {
        Self {
            state: state.clone(),
            identity: identity.clone(),
            host: host.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            rule_id,
            decision: if rule_id.is_none() {
                "passthrough"
            } else {
                "inject"
            },
            done: false,
        }
    }

    /// Writes the row with the guard's own decision (the origin answered with `status`).
    pub fn finish(self, status: Option<u16>) {
        let d = self.decision;
        self.finish_as(d, status);
    }

    /// Writes the row with an explicit decision (e.g. `upstream-error`).
    pub fn finish_as(mut self, decision: &str, status: Option<u16>) {
        self.done = true;
        self.write(decision, status);
    }

    fn write(&self, decision: &str, status: Option<u16>) {
        audit(
            &self.state,
            &self.identity,
            &self.host,
            &self.method,
            &self.path,
            decision,
            status,
            self.rule_id,
        );
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        if !self.done {
            self.write("client-aborted", None);
        }
    }
}

/// 503 for a vault/policy failure: audited as `internal-error` (when the audit table is still
/// writable) and answered with a static body. The error itself is logged by the caller, without
/// request data. Nothing is ever forwarded or tunnelled after this.
pub(crate) fn service_unavailable(
    state: &ProxyState,
    id: &Identity,
    host: &str,
    method: &str,
    path: &str,
) -> Response<ProxyBody> {
    audit(
        state,
        id,
        host,
        method,
        path,
        "internal-error",
        Some(503),
        None,
    );
    text(StatusCode::SERVICE_UNAVAILABLE, "service unavailable\n")
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    limits: Limits,
    slot: Slot,
) -> Response<ProxyBody> {
    let session = match authenticate(&req, &state) {
        Ok(s) => s,
        Err(Rejected(rejected)) => {
            if let Some(id) = &rejected {
                audit_rejected(&req, id, &state, &limits);
            }
            return proxy_auth_required();
        }
    };
    if req.method() == Method::CONNECT {
        connect(req, session, state, limits, slot).await
    } else {
        plain(req, session, state, limits).await
    }
}

/// An absolute-form `http://` request sent to the proxy port.
///
/// Credentials are never injected into plain HTTP, without exception (see `forward`): a host
/// with rules is refused by `forward` (`plaintext-refused`), while a host without rules is
/// forwarded untouched under a `passthrough` role and denied under `deny`.
async fn plain(
    req: Request<Incoming>,
    session: Session,
    state: Arc<ProxyState>,
    limits: Limits,
) -> Response<ProxyBody> {
    let identity = &session.identity;
    let method = req.method().to_string();
    let hint = req.uri().host().unwrap_or("").to_string();
    if req.uri().scheme_str() != Some("http") {
        return bad_request(
            &state,
            identity,
            &hint,
            &method,
            "send absolute-form http:// requests, or CONNECT for https\n",
        );
    }
    let Some(authority) = req.uri().authority().cloned() else {
        return bad_request(&state, identity, &hint, &method, "missing host\n");
    };
    // `user:pw@host` is never legitimate.
    if authority.as_str().contains('@') {
        return bad_request(&state, identity, &hint, &method, "bad request target\n");
    }
    let Some(host) = normalize_host(authority.host()) else {
        return bad_request(&state, identity, &hint, &method, "bad host\n");
    };
    let port = authority.port_u16().unwrap_or(80);
    if port == 0 {
        return bad_request(&state, identity, &host, &method, "bad port\n");
    }
    let target = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    let role = match get_role(&state.vault, &identity.role) {
        Ok(Some(r)) => r,
        Ok(None) => {
            audit(
                &state,
                identity,
                &host,
                &method,
                &target,
                "unknown-role",
                Some(403),
                None,
            );
            return text(StatusCode::FORBIDDEN, "role not found\n");
        }
        Err(e) => {
            tracing::error!(error = %e, "could not load the role");
            return service_unavailable(&state, identity, &host, &method, &target);
        }
    };
    let rules = match list_rules(&state.vault, Some(&identity.role)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "could not load rules");
            return service_unavailable(&state, identity, &host, &method, &target);
        }
    };
    let has_rules = has_rules_for_host(&rules, &host);
    if !has_rules && role.unmatched == Unmatched::Deny {
        audit(
            &state,
            identity,
            &host,
            &method,
            &target,
            "unmatched-denied",
            Some(403),
            None,
        );
        return text(StatusCode::FORBIDDEN, "host not allowed for this role\n");
    }
    let ctx = crate::forward::Ctx {
        state,
        identity: session.identity,
        host,
        port,
        tls: false,
        allow_unruled: !has_rules,
        limits,
    };
    crate::forward::forward(req, &ctx, Vec::new()).await
}

async fn connect(
    req: Request<Incoming>,
    session: Session,
    state: Arc<ProxyState>,
    limits: Limits,
    slot: Slot,
) -> Response<ProxyBody> {
    let identity = &session.identity;
    let hint = req.uri().host().unwrap_or("").to_string();
    let Some(authority) = req.uri().authority().cloned() else {
        return bad_request(&state, identity, &hint, "CONNECT", "bad CONNECT target\n");
    };
    // `user:pw@host` is never a legitimate CONNECT target.
    if authority.as_str().contains('@') {
        return bad_request(&state, identity, &hint, "CONNECT", "bad CONNECT target\n");
    }
    let Some(host) = normalize_host(authority.host()) else {
        return bad_request(&state, identity, &hint, "CONNECT", "bad CONNECT host\n");
    };
    let port = authority.port_u16().unwrap_or(443);
    if port == 0 {
        return bad_request(&state, identity, &host, "CONNECT", "bad CONNECT port\n");
    }

    let role = match get_role(&state.vault, &identity.role) {
        Ok(Some(r)) => r,
        Ok(None) => {
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
        Err(e) => {
            tracing::error!(error = %e, "could not load the role");
            return service_unavailable(&state, identity, &host, "CONNECT", "/");
        }
    };
    let rules = match list_rules(&state.vault, Some(&identity.role)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "could not load rules");
            return service_unavailable(&state, identity, &host, "CONNECT", "/");
        }
    };

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
                &format!("the CA does not permit {host}; its domains follow the rules: re-create the rule or restart `sg serve`, then reload the CA certificate\n"),
            );
        }
        let Some(tunnel) = limits
            .tunnels
            .try_acquire(&identity.jti, limits.max_tunnels_per_identity)
        else {
            return identity_limit(
                &state,
                identity,
                &host,
                "CONNECT",
                "/",
                None,
                "too many open tunnels for this token\n",
            );
        };
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
        tokio::spawn(crate::mitm::serve(
            req, host, port, session, state, limits, slot, tunnel,
        ));
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
            let Some(tunnel) = limits
                .tunnels
                .try_acquire(&identity.jti, limits.max_tunnels_per_identity)
            else {
                return identity_limit(
                    &state,
                    identity,
                    &host,
                    "CONNECT",
                    "/",
                    None,
                    "too many open tunnels for this token\n",
                );
            };
            // Reach the destination first: only then answer 200.
            let upstream = match state.upstream.connect_tcp(&host, port).await {
                Ok(s) => s,
                Err(UpstreamError::TargetDenied) => {
                    audit(
                        &state,
                        identity,
                        &host,
                        "CONNECT",
                        "/",
                        "target-denied",
                        Some(403),
                        None,
                    );
                    return text(StatusCode::FORBIDDEN, "destination not allowed\n");
                }
                Err(_) => {
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
                }
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
                // The tunnel keeps the connection-cap slot and the identity's tunnel budget
                // until it ends.
                let _slot = slot;
                let _tunnel = tunnel;
                let copy = async {
                    if let Ok(upgraded) = hyper::upgrade::on(req).await {
                        // Both sides are bounded, so a stall on either one ends the tunnel.
                        let mut client =
                            IdleIo::new(TokioIo::new(upgraded), limits.tunnel_idle_timeout);
                        let mut upstream = IdleIo::new(upstream, limits.tunnel_idle_timeout);
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                };
                let _ = tokio::time::timeout(limits.tunnel_max_lifetime, copy).await;
            });
            empty(StatusCode::OK)
        }
    }
}
