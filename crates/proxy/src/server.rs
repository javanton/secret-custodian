use crate::{
    upstream::{ProxyBody, UpstreamError},
    ProxyState,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use sg_auth::{extract_proxy_token, Identity};
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

/// Time limits applied to a client connection and to the tunnels it opens.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub header_read_timeout: Duration,
    pub tunnel_idle_timeout: Duration,
    pub tunnel_max_lifetime: Duration,
}

/// The connection-cap slot. Cloned into every task a CONNECT spawns, so it is released only
/// when the connection AND its tunnel are gone.
pub(crate) type Slot = Arc<OwnedSemaphorePermit>;

/// Wraps a stream and fails reads/writes with `TimedOut` once nothing moved in either direction
/// for `idle`.
pub(crate) struct IdleIo<T> {
    inner: T,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<T> IdleIo<T> {
    pub fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
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
                Poll::Ready(r)
            }
            Poll::Pending => match self.check_idle(cx) {
                Some(e) => Poll::Ready(Err(e)),
                None => Poll::Pending,
            },
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
    let svc = service_fn(move |req| {
        let (state, slot) = (state.clone(), slot.clone());
        async move { Ok::<_, Infallible>(handle_request(req, state, limits, slot).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
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

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ProxyState>,
    limits: Limits,
    slot: Slot,
) -> Response<ProxyBody> {
    let Some(session) = authenticate(&req, &state) else {
        return proxy_auth_required();
    };
    if req.method() == Method::CONNECT {
        connect(req, session, state, limits, slot).await
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
    limits: Limits,
    slot: Slot,
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
        tokio::spawn(crate::mitm::serve(
            req, host, port, session, state, limits, slot,
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
            // Reach the destination first: only then answer 200.
            let mut upstream = match state.upstream.connect_tcp(&host, port).await {
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
                let _slot = slot; // the tunnel keeps the connection-cap slot until it ends
                let tunnel = async {
                    if let Ok(upgraded) = hyper::upgrade::on(req).await {
                        let mut client =
                            IdleIo::new(TokioIo::new(upgraded), limits.tunnel_idle_timeout);
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                    }
                };
                let _ = tokio::time::timeout(limits.tunnel_max_lifetime, tunnel).await;
            });
            empty(StatusCode::OK)
        }
    }
}
