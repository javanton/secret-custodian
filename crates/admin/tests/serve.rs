use sg_admin::{allowed_hosts_for, bind_unix, is_loopback_bind, serve_unix, AppState, Sessions};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{crypto, KeyInput, Vault};
use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

fn state(dir: &Path) -> AppState {
    let vault =
        Arc::new(Vault::init(&dir.join("v.db"), KeyInput::Raw(crypto::random_key())).unwrap());
    AppState {
        tokens: Arc::new(TokenService::new(vault.clone()).unwrap()),
        ca: Arc::new(CaService::init_or_load(vault.clone()).unwrap()),
        vault,
        sessions: Arc::new(Sessions::new()),
        allowed_hosts: vec![],
    }
}

/// A private (0700) directory to hold sockets.
fn private_dir() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = d.path().join("sg.sock");
    (d, sock)
}

#[tokio::test]
async fn socket_is_0600_and_serves_the_api() {
    let (d, sock) = private_dir();
    let st = state(d.path());
    let task = tokio::spawn({
        let sock = sock.clone();
        async move { serve_unix(&sock, st).await }
    });
    let mut stream = loop {
        match UnixStream::connect(&sock).await {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    };
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    stream
        .write_all(b"GET /ca HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    task.abort();
}

#[tokio::test]
async fn bind_unix_sets_0600() {
    let (_d, sock) = private_dir();
    let _l = bind_unix(&sock).await.unwrap();
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn refuses_a_regular_file_at_the_path() {
    let (_d, sock) = private_dir();
    std::fs::write(&sock, b"precious").unwrap();
    let err = bind_unix(&sock).await.unwrap_err();
    assert!(err.to_string().contains("not a socket"), "{err}");
    assert_eq!(std::fs::read(&sock).unwrap(), b"precious");
}

#[tokio::test]
async fn refuses_a_symlink_at_the_path() {
    let (d, sock) = private_dir();
    let target = d.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &sock).unwrap();
    assert!(bind_unix(&sock).await.is_err());
    assert!(target.exists());
}

#[tokio::test]
async fn refuses_a_live_socket() {
    let (d, sock) = private_dir();
    let _live = UnixListener::bind(&sock).unwrap();
    let err = serve_unix(&sock, state(d.path())).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AddrInUse);
    assert!(err.to_string().contains("already running"), "{err}");
    assert!(sock.exists());
}

#[tokio::test]
async fn replaces_a_stale_socket() {
    let (_d, sock) = private_dir();
    drop(UnixListener::bind(&sock).unwrap()); // leaves the socket file behind
    assert!(sock.exists());
    let _l = bind_unix(&sock).await.unwrap();
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn refuses_a_parent_directory_open_to_group_or_others() {
    for mode in [0o755, 0o750, 0o770, 0o701] {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let sock = d.path().join("sg.sock");
        let err = bind_unix(&sock).await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{mode:o}");
        assert!(err.to_string().contains("directory"), "{err}");
        assert!(!sock.exists());
    }
}

#[test]
fn allowed_hosts_and_loopback_helper() {
    let a = allowed_hosts_for("127.0.0.1:9090".parse().unwrap());
    assert_eq!(a, vec!["localhost:9090", "127.0.0.1:9090", "[::1]:9090"]);
    assert!(is_loopback_bind("127.0.0.1:1".parse().unwrap()));
    assert!(is_loopback_bind("[::1]:1".parse().unwrap()));
    assert!(!is_loopback_bind("0.0.0.0:1".parse().unwrap()));
    assert!(!is_loopback_bind("192.168.1.2:1".parse().unwrap()));
}

#[tokio::test]
async fn serve_web_uses_the_given_listener() {
    let d = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut st = state(d.path());
    st.allowed_hosts = allowed_hosts_for(addr);
    let task = tokio::spawn(sg_admin::serve_web(listener, st));
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    s.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            addr.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    task.abort();
}
