use crate::{api::api_router, state::AppState, web::web_router};
use std::{
    io::{Error, ErrorKind, Result},
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
};
use tokio::net::{TcpListener, UnixListener, UnixStream};

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
    let mode = std::fs::metadata(parent)?.permissions().mode();
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
        Ok(meta) if meta.file_type().is_socket() => match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::AddrInUse,
                    format!("already running: {} accepts connections", path.display()),
                ))
            }
            Err(e)
                if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound =>
            {
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        },
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

/// Serves the unauthenticated admin API on a Unix socket (see [`bind_unix`] for the checks).
pub async fn serve_unix(path: &Path, state: AppState) -> Result<()> {
    let listener = bind_unix(path).await?;
    axum::serve(listener, api_router(state)).await
}

/// Serves the web UI on an already bound listener.
///
/// Binding is the caller's responsibility: it must be loopback unless the operator passed
/// `--admin-bind` explicitly (check with [`is_loopback_bind`] and warn). `state.allowed_hosts`
/// must contain every `Host` the browser will use (see [`allowed_hosts_for`]).
pub async fn serve_web(listener: TcpListener, state: AppState) -> Result<()> {
    axum::serve(listener, web_router(state)).await
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
