use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("tls failed: {0}")]
    Tls(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("timeout")]
    Timeout,
}

#[derive(Clone)]
pub struct UpstreamConfig {
    pub tls: Arc<rustls::ClientConfig>,
    /// Test/ops knob: connect to this address instead of resolving the host.
    pub resolve_override: HashMap<String, SocketAddr>,
}

impl UpstreamConfig {
    pub fn new(extra_roots: Vec<CertificateDer<'static>>) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        for c in extra_roots {
            let _ = roots.add(c);
        }
        let tls = rustls::ClientConfig::builder_with_provider(sg_ca::crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            tls: Arc::new(tls),
            resolve_override: HashMap::new(),
        }
    }

    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
        let fut = async {
            match self.resolve_override.get(host) {
                Some(addr) => TcpStream::connect(addr).await,
                None => TcpStream::connect((host, port)).await,
            }
        };
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|e| UpstreamError::Connect(e.to_string()))
    }

    pub async fn send(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        req: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        let tcp = self.connect_tcp(host, port).await?;
        let fut = async {
            if tls {
                let name = ServerName::try_from(host.to_string())
                    .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                let s = TlsConnector::from(self.tls.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                roundtrip(TokioIo::new(s), req).await
            } else {
                roundtrip(TokioIo::new(tcp), req).await
            }
        };
        tokio::time::timeout(Duration::from_secs(60), fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

async fn roundtrip<I>(io: I, req: Request<ProxyBody>) -> Result<Response<Incoming>, UpstreamError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))
}
