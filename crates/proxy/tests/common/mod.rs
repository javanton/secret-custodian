#![allow(dead_code)]
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{pem::PemObject, CertificateDer};
use sg_auth::TokenService;
use sg_auth::TokenVerifier;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use sg_proxy::{ProxyState, ServeOptions, UpstreamConfig};
use std::future::Future;
use std::{net::SocketAddr, sync::Arc, sync::Mutex};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{client::TlsStream, TlsAcceptor, TlsConnector};

pub struct Env {
    pub dir: TempDir,
    pub vault: Arc<Vault>,
    pub tokens: Arc<TokenService>,
    pub ca: Arc<CaService>,
    pub proxy_addr: SocketAddr,
}

impl Env {
    pub async fn new(upstream: UpstreamConfig) -> Env {
        Env::custom(upstream, ServeOptions::default(), None).await
    }

    /// Like `new`, with explicit serve options and an optional verifier replacing the real one.
    pub async fn custom(
        upstream: UpstreamConfig,
        opts: ServeOptions,
        verifier: Option<Arc<dyn TokenVerifier>>,
    ) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(
            Vault::init(
                &dir.path().join("v.db"),
                KeyInput::Raw(crypto::random_key()),
            )
            .unwrap(),
        );
        let tokens = Arc::new(TokenService::new(vault.clone()).unwrap());
        let ca = Arc::new(CaService::init_or_load(vault.clone()).unwrap());
        let verifier = verifier.unwrap_or_else(|| tokens.clone());
        let state = Arc::new(ProxyState {
            vault: vault.clone(),
            verifier,
            ca: ca.clone(),
            upstream,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(sg_proxy::serve_with(listener, state, opts));
        Env {
            dir,
            vault,
            tokens,
            ca,
            proxy_addr,
        }
    }

    pub fn token(&self, machine: &str, role: &str) -> String {
        self.tokens.issue(machine, role, None).unwrap().token
    }
}

pub fn basic(token: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    format!("Basic {}", STANDARD.encode(format!("agent:{token}")))
}

/// Sends a CONNECT and returns the first response line, then (if 200) the raw stream for tunnelling.
pub async fn raw_connect(
    proxy: SocketAddr,
    authority: &str,
    auth: Option<&str>,
) -> (String, TcpStream) {
    let (head, s) = raw_connect_head(proxy, authority, auth).await;
    (head.lines().next().unwrap_or("").to_string(), s)
}

/// Like `raw_connect` but returns the whole response head (status line and headers).
pub async fn raw_connect_head(
    proxy: SocketAddr,
    authority: &str,
    auth: Option<&str>,
) -> (String, TcpStream) {
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    raw_head(proxy, req.as_bytes()).await
}

/// Sends raw bytes and reads until the end of the response head.
pub async fn raw_head(proxy: SocketAddr, raw: &[u8]) -> (String, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(raw).await.unwrap();
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        buf.push(b[0]);
    }
    (String::from_utf8_lossy(&buf).to_string(), s)
}

pub async fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Default config for tests whose fake destinations live on loopback.
pub fn no_extra_roots() -> UpstreamConfig {
    let mut cfg = strict_upstream();
    cfg.net_policy.allow_loopback = true;
    cfg
}

/// Config with the DEFAULT network policy (loopback, link-local, unspecified refused).
pub fn strict_upstream() -> UpstreamConfig {
    UpstreamConfig::new(Vec::<CertificateDer<'static>>::new())
}

/// A TCP listener that only counts accepted connections.
pub async fn counting_listener() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { break };
            n2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::mem::forget(s);
        }
    });
    (addr, n)
}

// ---------------------------------------------------------------------------------------------
// TLS/plain test upstreams
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body_len: usize,
}

pub struct TestUpstream {
    pub addr: SocketAddr,
    pub received: Arc<Mutex<Vec<Recorded>>>,
    pub ca_der: CertificateDer<'static>,
}

impl TestUpstream {
    pub fn header(&self, i: usize, name: &str) -> Vec<String> {
        self.received.lock().unwrap()[i]
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn count(&self) -> usize {
        self.received.lock().unwrap().len()
    }
}

/// Body that yields `first`, waits 1.5 s, then yields `second`: proves responses are streamed.
struct SlowBody {
    step: u8,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl hyper::body::Body for SlowBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        match self.step {
            0 => {
                self.step = 1;
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                    b"first",
                )))))
            }
            1 => match self.sleep.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    self.step = 2;
                    Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                        b"second",
                    )))))
                }
            },
            _ => Poll::Ready(None),
        }
    }
}

type UpBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// Yields `partial` and then fails: the upstream connection dies in the middle of the response.
struct AbortBody {
    sent: bool,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl hyper::body::Body for AbortBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        if !self.sent {
            self.sent = true;
            Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                b"partial",
            )))))
        } else {
            // Let the head and the first chunk reach the wire before dying.
            match self.sleep.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => Poll::Ready(Some(Err(std::io::Error::other("upstream died")))),
            }
        }
    }
}

/// Never-ending response body (64 KiB chunks): a client that does not read it stalls the stream.
struct EndlessBody;

impl hyper::body::Body for EndlessBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from(vec![
            b'e';
            64 * 1024
        ])))))
    }
}

/// Six 6-byte chunks, 300 ms apart: slow but steadily progressing.
struct DripBody {
    left: u8,
    sleep: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl hyper::body::Body for DripBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        if self.left == 0 {
            return Poll::Ready(None);
        }
        match self.sleep.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.left -= 1;
                let next = tokio::time::Instant::now() + std::time::Duration::from_millis(300);
                self.sleep.as_mut().reset(next);
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                    b"chunk\n",
                )))))
            }
        }
    }
}

async fn serve_recording<IO>(io: IO, received: Arc<Mutex<Vec<Recorded>>>)
where
    IO: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let received = received.clone();
        async move {
            let (parts, body) = req.into_parts();
            let n = body
                .collect()
                .await
                .map(|b| b.to_bytes().len())
                .unwrap_or(0);
            received.lock().unwrap().push(Recorded {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts
                    .headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
                body_len: n,
            });
            // `/slow` never answers within the test timeouts; `/stream` answers in two parts.
            if parts.uri.path() == "/slow" {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
            if parts.uri.path() == "/delay" {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            // `/big` answers 8 MiB; `/abort` dies mid-body; HEAD never carries a body.
            let body: UpBody = if parts.uri.path() == "/big" {
                Full::new(Bytes::from(vec![b'b'; 8 * 1024 * 1024]))
                    .map_err(|never| match never {})
                    .boxed()
            } else if parts.uri.path() == "/endless" {
                EndlessBody.boxed()
            } else if parts.uri.path() == "/drip" {
                DripBody {
                    left: 6,
                    sleep: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(300))),
                }
                .boxed()
            } else if parts.uri.path() == "/abort" {
                AbortBody {
                    sent: false,
                    sleep: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(200))),
                }
                .boxed()
            } else if parts.uri.path() == "/stream" {
                SlowBody {
                    step: 0,
                    sleep: Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1500))),
                }
                .boxed()
            } else {
                Full::new(Bytes::from_static(b"ok"))
                    .map_err(|never| match never {})
                    .boxed()
            };
            let mut resp = hyper::Response::new(body);
            // Headers a proxy must not pass back to the agent, plus one it must.
            resp.headers_mut().insert("x-up", "1".parse().unwrap());
            resp.headers_mut()
                .insert("keep-alive", "timeout=5".parse().unwrap());
            resp.headers_mut().insert("proxy-foo", "1".parse().unwrap());
            Ok::<_, std::io::Error>(resp)
        }
    });
    let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}

pub async fn spawn_tls_upstream(host: &str) -> TestUpstream {
    use rcgen::{CertificateParams, DistinguishedName, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca, &ca_key)
        .unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(sg_ca::crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                leaf_key.serialize_der(),
            )),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (acceptor, rec) = (acceptor.clone(), rec.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve_recording(TokioIo::new(tls), rec).await;
                }
            });
        }
    });
    TestUpstream {
        addr,
        received,
        ca_der: ca.der().clone(),
    }
}

pub async fn spawn_plain_upstream() -> TestUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(Vec::new()));
    let rec = received.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let rec = rec.clone();
            tokio::spawn(serve_recording(TokioIo::new(tcp), rec));
        }
    });
    TestUpstream {
        addr,
        received,
        ca_der: CertificateDer::from(Vec::new()),
    }
}

/// Env wired to a TLS test upstream reachable under `host`, with the CA allowing `host`.
pub async fn env_with_upstream(host: &str) -> (Env, TestUpstream) {
    env_with_upstream_cfg(host, |_| {}).await
}

/// Like `env_with_upstream`, letting the test tweak the `UpstreamConfig` (timeouts...).
pub async fn env_with_upstream_cfg(
    host: &str,
    tweak: impl FnOnce(&mut UpstreamConfig),
) -> (Env, TestUpstream) {
    env_with_upstream_opts(host, ServeOptions::default(), tweak).await
}

/// Like `env_with_upstream_cfg`, also choosing the proxy's serve options.
pub async fn env_with_upstream_opts(
    host: &str,
    opts: ServeOptions,
    tweak: impl FnOnce(&mut UpstreamConfig),
) -> (Env, TestUpstream) {
    let up = spawn_tls_upstream(host).await;
    let mut cfg = UpstreamConfig::new(vec![up.ca_der.clone()]);
    cfg.net_policy.allow_loopback = true;
    cfg.resolve_override.insert(host.to_string(), up.addr);
    tweak(&mut cfg);
    let env = Env::custom(cfg, opts, None).await;
    env.ca.allow_domain(host).unwrap();
    (env, up)
}

// ---------------------------------------------------------------------------------------------
// Client side of a MITM tunnel
// ---------------------------------------------------------------------------------------------

pub struct Resp {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// CONNECT through the proxy and complete the TLS handshake trusting the proxy CA.
/// `Err(resp)` carries the proxy's refusal when CONNECT was not answered with 200.
pub async fn tunnel_tls(
    env: &Env,
    token: &str,
    host: &str,
    http2: bool,
) -> Result<TlsStream<TcpStream>, Resp> {
    let (line, tcp) =
        raw_connect(env.proxy_addr, &format!("{host}:443"), Some(&basic(token))).await;
    if !line.contains("200") {
        return Err(Resp {
            status: line
                .split(' ')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            body: line,
            headers: vec![],
        });
    }
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(env.ca.cert_pem().as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(sg_ca::crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![if http2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Ok(TlsConnector::from(Arc::new(cfg))
        .connect(
            rustls::pki_types::ServerName::try_from(host.to_string()).unwrap(),
            tcp,
        )
        .await
        .expect("client must trust the proxy CA for this host"))
}

async fn into_resp(resp: hyper::Response<hyper::body::Incoming>) -> Resp {
    let status = resp.status().as_u16();
    let headers = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body =
        String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string();
    Resp {
        status,
        body,
        headers,
    }
}

fn build_request(
    http2: bool,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> hyper::Request<Full<Bytes>> {
    let mut rb = hyper::Request::builder()
        .method(method)
        .uri(format!("https://{host}{path}"));
    if !http2 {
        rb = rb.header("host", host);
    }
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    rb.body(Full::new(Bytes::from(body))).unwrap()
}

/// CONNECT through the proxy, then send one request (HTTP/1.1 or HTTP/2) through the tunnel.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_request(
    env: &Env,
    token: &str,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
    http2: bool,
) -> Resp {
    let tls = match tunnel_tls(env, token, host, http2).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    let req = build_request(http2, host, method, path, headers, body);
    let resp = if http2 {
        let (mut s, c) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    } else {
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(c);
        s.send_request(req).await.unwrap()
    };
    into_resp(resp).await
}

/// An open HTTP/1.1 keep-alive MITM tunnel on which several requests can be sent in turn.
pub struct Tunnel {
    host: String,
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

pub async fn open_tunnel(env: &Env, token: &str, host: &str) -> Tunnel {
    let tls = tunnel_tls(env, token, host, false)
        .await
        .ok()
        .expect("CONNECT must succeed");
    let (sender, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(c);
    Tunnel {
        host: host.to_string(),
        sender,
    }
}

impl Tunnel {
    /// `None` when the proxy closed the connection instead of answering.
    pub async fn try_request(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Option<Resp> {
        let req = build_request(false, &self.host, method, path, headers, vec![]);
        let resp = self.sender.send_request(req).await.ok()?;
        Some(into_resp(resp).await)
    }

    pub async fn request(&mut self, method: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
        self.try_request(method, path, headers)
            .await
            .expect("tunnel closed")
    }

    /// Sends a GET and returns the response before its body is consumed.
    pub async fn send_streaming(&mut self, path: &str) -> hyper::Response<hyper::body::Incoming> {
        let req = build_request(false, &self.host, "GET", path, &[], vec![]);
        self.sender.send_request(req).await.unwrap()
    }
}

/// Writes raw HTTP/1.1 bytes through a MITM tunnel (for request targets `hyper`'s client cannot
/// build: raw `\`, non-ASCII bytes...) and reads the response until the connection closes. The
/// request must carry `Connection: close`. Status 0 means the proxy closed without a response.
pub async fn proxy_raw_request(env: &Env, token: &str, host: &str, raw: &[u8]) -> Resp {
    let mut tls = match tunnel_tls(env, token, host, false).await {
        Ok(t) => t,
        Err(r) => return r,
    };
    tls.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await; // a reset after the response is fine
    let text = String::from_utf8_lossy(&out).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Resp {
        status,
        body,
        headers: vec![],
    }
}

/// Raw GET with a request target of the test's choosing (`Host` set to `host`).
pub fn raw_get(host: &str, target: &[u8]) -> Vec<u8> {
    let mut v = b"GET ".to_vec();
    v.extend_from_slice(target);
    v.extend_from_slice(
        format!(" HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    v
}
