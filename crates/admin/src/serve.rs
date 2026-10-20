use crate::{api::socket_router, state::AppState, web::web_router};
use axum::Router;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{
    future::Future,
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener, UnixStream},
    sync::Semaphore,
};

/// Limits applied to every connection of an admin listener, so idle or stalled clients
/// cannot exhaust file descriptors or tasks.
#[derive(Debug, Clone)]
pub struct AdminServeOptions {
    /// Connections served at once; further clients wait in the kernel accept backlog.
    pub max_connections: usize,
    /// Time a client gets to send a complete request head (also between keep-alive requests).
    /// Short, because this listener is loopback-only (effectively instant round trips): a long
    /// timeout lets another local process exhaust `max_connections` with idle connections and
    /// deny the web UI/API to the operator for that long, repeatably.
    pub header_read_timeout: Duration,
    /// A connection is closed this long after it was accepted, however active it is.
    pub max_connection_lifetime: Duration,
}

impl Default for AdminServeOptions {
    fn default() -> Self {
        Self {
            max_connections: 256,
            header_read_timeout: Duration::from_secs(3),
            max_connection_lifetime: Duration::from_secs(3600),
        }
    }
}

/// The effective uid of this process, read without libc from the owner of `/proc/self`.
/// Fails closed: if it cannot be determined, nothing is bound.
fn effective_uid() -> Result<u32> {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| {
            Error::new(
                e.kind(),
                format!("cannot determine the current user (reading /proc/self): {e}"),
            )
        })
}

/// Errors unless `owner` is `expected`.
fn require_owner(what: &Path, owner: u32, expected: u32) -> Result<()> {
    if owner == expected {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "refusing to use {}: it is owned by uid {owner}, not by the current user (uid {expected})",
                what.display()
            ),
        ))
    }
}

/// Accepts connections with at most `opts.max_connections` in flight. The permit is taken
/// BEFORE `accept`, so over the cap new clients just sit in the backlog.
async fn serve_loop<S, F, Fut>(mut accept: F, app: Router, opts: AdminServeOptions) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<S>>,
{
    let permits = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    loop {
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let stream = match accept().await {
            Ok(s) => s,
            Err(e) => {
                // e.g. EMFILE: back off instead of spinning
                tracing::warn!(error = %e, "admin accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let service = TowerToHyperService::new(app.clone());
        let (header_timeout, lifetime) = (opts.header_read_timeout, opts.max_connection_lifetime);
        tokio::spawn(async move {
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .serve_connection(TokioIo::new(stream), service);
            // dropping the connection future on timeout closes the socket
            let _ = tokio::time::timeout(lifetime, conn).await;
            drop(permit);
        });
    }
}

/// Checks and binds the admin Unix socket, returning it with mode `0600`.
///
/// The socket must never be reachable by other users, not even briefly, so `chmod` after
/// `bind` is not enough on its own: the parent directory must already deny group/other
/// access (`XDG_RUNTIME_DIR` is `0700`), otherwise this refuses with `PermissionDenied`.
/// An existing path is only replaced if it is a socket that nobody accepts connections on.
pub async fn bind_unix(path: &Path) -> Result<UnixListener> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let me = effective_uid()?;
    let parent_meta = std::fs::metadata(parent)?;
    require_owner(parent, parent_meta.uid(), me)?;
    let mode = parent_meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "refusing to create the admin socket: directory {} is accessible to group/others (mode {:o}); use a 0700 directory such as $XDG_RUNTIME_DIR",
                parent.display(),
                mode & 0o7777
            ),
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            require_owner(path, meta.uid(), me)?;
            match UnixStream::connect(path).await {
                Ok(_) => {
                    return Err(Error::new(
                        ErrorKind::AddrInUse,
                        format!("already running: {} accepts connections", path.display()),
                    ))
                }
                Err(e)
                    if e.kind() == ErrorKind::ConnectionRefused
                        || e.kind() == ErrorKind::NotFound =>
                {
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to replace it",
                    path.display()
                ),
            ))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Serves the unauthenticated admin API (plus the socket-only login route) on a Unix socket
/// with the default connection limits; see [`bind_unix`] for the checks.
pub async fn serve_unix(path: &Path, state: AppState) -> Result<()> {
    serve_unix_with(path, state, AdminServeOptions::default()).await
}

/// [`serve_unix`] with explicit connection limits.
pub async fn serve_unix_with(path: &Path, state: AppState, opts: AdminServeOptions) -> Result<()> {
    let listener = bind_unix(path).await?;
    serve_loop(
        || async { listener.accept().await.map(|(s, _)| s) },
        socket_router(state),
        opts,
    )
    .await
}

/// Serves the web UI on an already bound listener with the default connection limits.
///
/// Binding is the caller's responsibility: it must be loopback unless the operator passed
/// `--admin-bind` explicitly (check with [`is_loopback_bind`] and warn). `state.allowed_hosts`
/// must contain every `Host` the browser will use (see [`allowed_hosts_for`]).
pub async fn serve_web(listener: TcpListener, state: AppState) -> Result<()> {
    serve_web_with(listener, state, AdminServeOptions::default()).await
}

/// [`serve_web`] with explicit connection limits.
pub async fn serve_web_with(
    listener: TcpListener,
    state: AppState,
    opts: AdminServeOptions,
) -> Result<()> {
    serve_loop(
        || async { listener.accept().await.map(|(s, _)| s) },
        web_router(state),
        opts,
    )
    .await
}

/// `Host` values accepted for a loopback bind on `addr`'s port.
pub fn allowed_hosts_for(addr: SocketAddr) -> Vec<String> {
    let p = addr.port();
    vec![
        format!("localhost:{p}"),
        format!("127.0.0.1:{p}"),
        format!("[::1]:{p}"),
    ]
}

/// True when the address is a loopback address (the only kind served without `--admin-bind`).
pub fn is_loopback_bind(addr: SocketAddr) -> bool {
    addr.ip().is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_comparison_uses_the_injected_uids() {
        let p = Path::new("/run/user/1000");
        assert!(require_owner(p, 1000, 1000).is_ok());
        let e = require_owner(p, 0, 1000).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert!(e.to_string().contains("owned by uid 0"), "{e}");
        assert!(require_owner(p, 1001, 1000).is_err());
    }

    #[test]
    fn effective_uid_matches_a_file_we_just_created() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            effective_uid().unwrap(),
            std::fs::metadata(d.path()).unwrap().uid()
        );
    }
}
