use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};
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
    #[error("target refused by the network policy")]
    TargetDenied,
}

/// Which destination addresses the proxy may connect to (SSRF defence). Applied to the address
/// that is actually connected to, after resolution, for passthrough tunnels and forwarded
/// requests alike.
///
/// Multicast and broadcast addresses and everything in `denied` are always refused. Unspecified
/// (`0.0.0.0`, `::`), link-local (169.254.0.0/16, fe80::/10: cloud metadata lives there) and
/// loopback are refused unless the matching `allow_*` flag is set. RFC 1918 and ULA ranges stay
/// allowed (homelab).
#[derive(Debug, Clone, Default)]
pub struct NetPolicy {
    /// Allow 127.0.0.0/8 and ::1. Off by default. Forwarded requests whose host is exactly
    /// `localhost` and that matched a rule are exempt (the local-service case), never from `denied`.
    pub allow_loopback: bool,
    pub allow_link_local: bool,
    pub allow_unspecified: bool,
    /// Addresses the proxy itself and the admin API listen on. An entry also blocks its port on
    /// every loopback and unspecified address, so `0.0.0.0:9090` means port 9090 on every local
    /// address.
    pub denied: Vec<SocketAddr>,
}

/// IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) addresses are judged as the
/// IPv4 address they carry.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6 != Ipv6Addr::UNSPECIFIED && v6 != Ipv6Addr::LOCALHOST => {
            v6.to_ipv4().map(IpAddr::V4).unwrap_or(ip)
        }
        other => other,
    }
}

impl NetPolicy {
    pub fn new(denied: Vec<SocketAddr>) -> Self {
        Self {
            denied,
            ..Self::default()
        }
    }

    pub fn with_denied(mut self, denied: Vec<SocketAddr>) -> Self {
        self.denied = denied;
        self
    }

    pub fn with_allow_loopback(mut self, allow: bool) -> Self {
        self.allow_loopback = allow;
        self
    }

    /// Whether the proxy may connect to `addr`. `local_service` grants the loopback exception
    /// (forwarded request to host `localhost` with an applicable rule); `denied` still wins.
    pub fn permits(&self, addr: SocketAddr, local_service: bool) -> bool {
        let ip = canonical(addr.ip());
        let local = ip.is_loopback() || ip.is_unspecified();
        if self
            .denied
            .iter()
            .any(|d| d.port() == addr.port() && (local || canonical(d.ip()) == ip))
        {
            return false;
        }
        if ip.is_multicast() {
            return false;
        }
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_broadcast() {
                    return false;
                }
                if v4.is_link_local() && !self.allow_link_local {
                    return false;
                }
            }
            IpAddr::V6(v6) => {
                if v6.segments()[0] & 0xffc0 == 0xfe80 && !self.allow_link_local {
                    return false;
                }
            }
        }
        if ip.is_unspecified() && !self.allow_unspecified {
            return false;
        }
        if ip.is_loopback() && !(self.allow_loopback || local_service) {
            return false;
        }
        true
    }
}

#[derive(Clone)]
pub struct UpstreamConfig {
    pub tls: Arc<rustls::ClientConfig>,
    /// Test/ops knob: connect to this address instead of resolving the host.
    pub resolve_override: HashMap<String, SocketAddr>,
    /// Bound on the TCP connect to the destination.
    pub connect_timeout: Duration,
    /// Bound on TLS handshake plus sending the request until the response head arrives (default
    /// 120 s). The response body is not bounded (it is streamed). Note that when the origin
    /// waits for the whole request body before answering, this also bounds slow uploads.
    pub response_header_timeout: Duration,
    /// Which destination addresses may be connected to.
    pub net_policy: NetPolicy,
    /// Global limit on simultaneously open upstream connections made for forwarded requests
    /// (default 256). Excess requests wait up to `connect_timeout` and then fail with 502. Read
    /// when the first request is forwarded: set it before serving.
    pub max_upstream_connections: usize,
    slots: Arc<OnceLock<Arc<Semaphore>>>,
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
            connect_timeout: Duration::from_secs(10),
            response_header_timeout: Duration::from_secs(120),
            net_policy: NetPolicy::default(),
            max_upstream_connections: 256,
            slots: Arc::new(OnceLock::new()),
        }
    }

    /// Connects to `host:port` for a passthrough tunnel, subject to the network policy.
    pub async fn connect_tcp(&self, host: &str, port: u16) -> Result<TcpStream, UpstreamError> {
        self.connect_vetted(host, port, false).await
    }

    /// Resolves the target once, filters the addresses through the network policy and connects
    /// to one of the vetted addresses (there is no second resolution between check and connect).
    async fn connect_vetted(
        &self,
        host: &str,
        port: u16,
        local_service: bool,
    ) -> Result<TcpStream, UpstreamError> {
        let fut = async {
            let addrs: Vec<SocketAddr> = match self.resolve_override.get(host) {
                Some(addr) => vec![*addr],
                None => tokio::net::lookup_host((host, port))
                    .await
                    .map_err(|e| UpstreamError::Connect(e.to_string()))?
                    .collect(),
            };
            if addrs.is_empty() {
                return Err(UpstreamError::Connect("no address".into()));
            }
            let vetted: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|a| self.net_policy.permits(*a, local_service))
                .collect();
            if vetted.is_empty() {
                return Err(UpstreamError::TargetDenied);
            }
            let mut last = String::new();
            for a in vetted {
                match TcpStream::connect(a).await {
                    Ok(s) => return Ok(s),
                    Err(e) => last = e.to_string(),
                }
            }
            Err(UpstreamError::Connect(last))
        };
        tokio::time::timeout(self.connect_timeout, fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }

    async fn acquire_slot(&self) -> Result<OwnedSemaphorePermit, UpstreamError> {
        let sem = self
            .slots
            .get_or_init(|| Arc::new(Semaphore::new(self.max_upstream_connections.max(1))))
            .clone();
        tokio::time::timeout(self.connect_timeout, sem.acquire_owned())
            .await
            .map_err(|_| UpstreamError::Timeout)?
            .map_err(|_| UpstreamError::Connect("upstream limiter closed".into()))
    }

    pub async fn send(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        req: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, UpstreamError> {
        self.send_to(host, port, tls, req, false).await
    }

    /// `local_service` grants the loopback exception of the network policy.
    pub(crate) async fn send_to(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        req: Request<ProxyBody>,
        local_service: bool,
    ) -> Result<Response<Incoming>, UpstreamError> {
        // The slot lives as long as the upstream connection (until its response is done).
        let slot = self.acquire_slot().await?;
        let tcp = self.connect_vetted(host, port, local_service).await?;
        let fut = async {
            if tls {
                let name = ServerName::try_from(host.to_string())
                    .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                let s = TlsConnector::from(self.tls.clone())
                    .connect(name, tcp)
                    .await
                    .map_err(|e| UpstreamError::Tls(e.to_string()))?;
                roundtrip(TokioIo::new(s), req, slot).await
            } else {
                roundtrip(TokioIo::new(tcp), req, slot).await
            }
        };
        tokio::time::timeout(self.response_header_timeout, fut)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }
}

async fn roundtrip<I>(
    io: I,
    req: Request<ProxyBody>,
    slot: OwnedSemaphorePermit,
) -> Result<Response<Incoming>, UpstreamError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))?;
    tokio::spawn(async move {
        let _slot = slot;
        let _ = conn.await;
    });
    sender
        .send_request(req)
        .await
        .map_err(|e| UpstreamError::Request(e.to_string()))
}
