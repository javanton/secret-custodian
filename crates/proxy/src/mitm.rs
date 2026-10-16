use crate::{
    forward::{forward, Ctx},
    server::{audit, text, Session},
    ProxyState,
};
use hyper::{body::Incoming, service::service_fn, Request, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use std::{convert::Infallible, sync::Arc};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

/// Terminates TLS inside an upgraded CONNECT and serves the decrypted requests (HTTP/1.1 or
/// HTTP/2 by ALPN) through `forward`.
///
/// The session token is re-verified before EVERY inner request, so revoking it (or letting it
/// expire) stops an already-open tunnel: the request gets 407 and the connection is shut down.
pub(crate) async fn serve(
    req: Request<Incoming>,
    host: String,
    port: u16,
    session: Session,
    state: Arc<ProxyState>,
) {
    let Ok(upgraded) = hyper::upgrade::on(req).await else {
        return;
    };
    let Ok(cfg) = state.ca.server_config_for(&host) else {
        return;
    };
    let Ok(tls) = TlsAcceptor::from(cfg).accept(TokioIo::new(upgraded)).await else {
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
    let svc = {
        let (ctx, close) = (ctx.clone(), close.clone());
        service_fn(move |req: Request<Incoming>| {
            let (ctx, close) = (ctx.clone(), close.clone());
            let token = token.clone();
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
                Ok(forward(req, &ctx).await)
            }
        })
    };
    let builder = auto::Builder::new(TokioExecutor::new());
    let conn = builder.serve_connection(TokioIo::new(tls), svc);
    tokio::pin!(conn);
    let mut closing = false;
    loop {
        tokio::select! {
            _ = conn.as_mut() => break,
            _ = close.notified(), if !closing => {
                closing = true;
                // Finish the in-flight 407 and then close, for HTTP/1.1 and HTTP/2 alike.
                conn.as_mut().graceful_shutdown();
            }
        }
    }
}
