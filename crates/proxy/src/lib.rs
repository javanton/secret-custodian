mod forward;
mod inject;
mod mitm;
mod server;
mod upstream;

pub use upstream::{NetPolicy, UpstreamConfig};

use sg_auth::TokenVerifier;
use sg_ca::CaService;
use sg_core::Vault;
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};

pub struct ProxyState {
    pub vault: Arc<Vault>,
    pub verifier: Arc<dyn TokenVerifier>,
    pub ca: Arc<CaService>,
    pub upstream: UpstreamConfig,
}

/// Connection-level limits of the proxy listener.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// Maximum number of simultaneously open client connections. A CONNECT tunnel (passthrough
    /// or MITM) keeps its slot until the tunnel itself ends, not just until the CONNECT is
    /// answered. When the cap is reached the accept loop stops accepting: further clients wait
    /// in the kernel listen backlog (they are neither refused nor dropped) until a slot frees up.
    pub max_connections: usize,
    /// Maximum time a client may take to send a complete request head. It also bounds the TLS
    /// handshake inside a MITM tunnel and the wait for the first request after it.
    pub header_read_timeout: Duration,
    /// A tunnel with no traffic for this long is closed: for a passthrough tunnel, no bytes in
    /// either direction; for a MITM connection, no request in flight and none started (default
    /// 10 min).
    pub tunnel_idle_timeout: Duration,
    /// Absolute lifetime of a tunnel, busy or not (default 8 h). Together with the idle timeout
    /// this bounds how long a revoked token can keep using a passthrough tunnel (MITM requests
    /// re-verify the token each time).
    pub tunnel_max_lifetime: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            header_read_timeout: Duration::from_secs(30),
            tunnel_idle_timeout: Duration::from_secs(10 * 60),
            tunnel_max_lifetime: Duration::from_secs(8 * 60 * 60),
        }
    }
}

pub async fn serve(listener: TcpListener, state: Arc<ProxyState>) -> std::io::Result<()> {
    serve_with(listener, state, ServeOptions::default()).await
}

pub async fn serve_with(
    listener: TcpListener,
    state: Arc<ProxyState>,
    opts: ServeOptions,
) -> std::io::Result<()> {
    let slots = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    loop {
        // Take the slot before accepting, so excess clients queue in the kernel backlog.
        let permit = slots
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                // Transient accept failures (e.g. fd exhaustion) must not kill the proxy.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        let limits = server::Limits {
            header_read_timeout: opts.header_read_timeout,
            tunnel_idle_timeout: opts.tunnel_idle_timeout,
            tunnel_max_lifetime: opts.tunnel_max_lifetime,
        };
        // Shared with the tunnel tasks a CONNECT spawns: the slot is freed only when the last
        // of them ends.
        let permit = Arc::new(permit);
        tokio::spawn(async move {
            if let Err(e) = server::handle_connection(stream, state, limits, permit).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}
