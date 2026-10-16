#![allow(dead_code)]
use rustls::pki_types::CertificateDer;
use sg_auth::TokenService;
use sg_auth::TokenVerifier;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use sg_proxy::{ProxyState, ServeOptions, UpstreamConfig};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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

pub fn no_extra_roots() -> UpstreamConfig {
    UpstreamConfig::new(Vec::<CertificateDer<'static>>::new())
}
