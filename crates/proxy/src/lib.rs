mod inject;
mod mitm;
mod server;
mod upstream;

pub use upstream::UpstreamConfig;

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
    /// Maximum number of simultaneously open client connections (a CONNECT tunnel counts as one
    /// for its whole life). When the cap is reached the accept loop stops accepting: further
    /// clients wait in the kernel listen backlog (they are neither refused nor dropped) until a
    /// slot frees up.
    pub max_connections: usize,
    /// Maximum time a client may take to send a complete request head.
    pub header_read_timeout: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            header_read_timeout: Duration::from_secs(30),
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
        let timeout = opts.header_read_timeout;
        tokio::spawn(async move {
            let _permit = permit; // held for the life of the connection
            if let Err(e) = server::handle_connection(stream, state, timeout).await {
                tracing::debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}
