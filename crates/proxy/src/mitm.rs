use crate::{
    forward::{forward, Ctx},
    server::{audit, text, Limits, Slot},
    upstream::ProxyBody,
    ProxyState,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    service::service_fn,
    Request, StatusCode,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

/// HTTP/2 PING every 30 s; a peer that does not answer within 20 s is dropped.
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const H2_MAX_CONCURRENT_STREAMS: u32 = 32;

/// Application-level activity of one MITM connection. Transport bytes are not used on purpose:
/// HTTP/2 keep-alive PINGs would otherwise keep an abandoned connection alive forever.
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
    in_flight: AtomicUsize,
    seen_request: AtomicBool,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            seen_request: AtomicBool::new(false),
        })
    }

    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Marks a request (and, once attached to it, its response body) as in flight.
    fn guard(self: &Arc<Self>) -> Guard {
        self.seen_request.store(true, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.touch();
        Guard(self.clone())
    }

    fn idle_for(&self) -> Option<Duration> {
        if self.in_flight.load(Ordering::Relaxed) > 0 {
            return None;
        }
        let last = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        Some(self.start.elapsed().saturating_sub(last))
    }
}

struct Guard(Arc<Activity>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.0.touch();
    }
}

/// A response body that keeps its request "in flight" until it is fully sent or dropped.
struct Tracked {
    inner: ProxyBody,
    guard: Guard,
}

impl Body for Tracked {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_frame(cx);
        if r.is_ready() {
            this.guard.0.touch();
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Terminates TLS inside an upgraded CONNECT and serves the decrypted requests (HTTP/1.1 or
/// HTTP/2 by ALPN) through `forward`.
///
/// The session token is re-verified before EVERY inner request, so revoking it (or letting it
/// expire) stops an already-open tunnel: the request gets 407 and the connection is shut down.
///
/// The connection-cap `slot` is held until this function returns. The TLS handshake is bounded
/// by `header_read_timeout`, an idle connection is closed after `tunnel_idle_timeout` and the
/// whole tunnel after `tunnel_max_lifetime`.
pub(crate) async fn serve(
    req: Request<Incoming>,
    host: String,
    port: u16,
    session: crate::server::Session,
    state: Arc<ProxyState>,
    limits: Limits,
    slot: Slot,
) {
    let _slot = slot;
    let _ = tokio::time::timeout(
        limits.tunnel_max_lifetime,
        serve_inner(req, host, port, session, state, limits),
    )
    .await;
}

async fn serve_inner(
    req: Request<Incoming>,
    host: String,
    port: u16,
    session: crate::server::Session,
    state: Arc<ProxyState>,
    limits: Limits,
) {
    let Ok(upgraded) = hyper::upgrade::on(req).await else {
        return;
    };
    let Ok(cfg) = state.ca.server_config_for(&host) else {
        return;
    };
    let accepted = tokio::time::timeout(
        limits.header_read_timeout,
        TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)),
    )
    .await;
    let Ok(Ok(tls)) = accepted else {
        return;
    };
    let token = Arc::new(session.token);
    let ctx = Arc::new(Ctx {
        state: state.clone(),
        identity: session.identity,
        host,
        port,
        tls: true,
        allow_unruled: false,
    });
    let close = Arc::new(Notify::new());
    let activity = Activity::new();
    let svc = {
        let (ctx, close, activity) = (ctx.clone(), close.clone(), activity.clone());
        service_fn(move |req: Request<Incoming>| {
            let (ctx, close) = (ctx.clone(), close.clone());
            let token = token.clone();
            let guard = activity.guard();
            async move {
                if ctx.state.verifier.verify(&token).is_err() {
                    let path = req.uri().path().to_string();
                    audit(
                        &ctx.state,
                        &ctx.identity,
                        &ctx.host,
                        req.method().as_str(),
                        &path,
                        "token-invalid",
                        Some(407),
                        None,
                    );
                    close.notify_one();
                    return Ok::<_, Infallible>(text(
                        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                        "proxy authentication required\n",
                    ));
                }
                let resp = forward(req, &ctx).await;
                Ok(resp.map(|inner| Tracked { inner, guard }.boxed()))
            }
        })
    };
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(H2_KEEP_ALIVE_INTERVAL))
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    let conn = builder.serve_connection(TokioIo::new(tls), svc);
    tokio::pin!(conn);
    let tick =
        (limits.tunnel_idle_timeout / 4).clamp(Duration::from_millis(20), Duration::from_secs(5));
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut closing = false;
    loop {
        tokio::select! {
            _ = conn.as_mut() => break,
            _ = close.notified(), if !closing => {
                closing = true;
                // Finish the in-flight 407 and then close, for HTTP/1.1 and HTTP/2 alike.
                conn.as_mut().graceful_shutdown();
            }
            _ = ticker.tick() => {
                // Before the first request only the (shorter) header timeout is allowed.
                let limit = if activity.seen_request.load(Ordering::Relaxed) {
                    limits.tunnel_idle_timeout
                } else {
                    limits.tunnel_idle_timeout.min(limits.header_read_timeout)
                };
                if activity.idle_for().is_some_and(|d| d >= limit) {
                    break;
                }
            }
        }
    }
}
