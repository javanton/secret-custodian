use anyhow::{bail, Context};
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};

/// Largest request body the client will send and response body it will read.
const MAX_BODY: usize = 1024 * 1024;
/// Overall deadline for one call (connect, request and response).
const TIMEOUT: Duration = Duration::from_secs(30);

/// Sends one request over the admin Unix socket and returns the status and the raw body.
pub async fn call_raw(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<Bytes>,
) -> anyhow::Result<(StatusCode, Bytes)> {
    let payload = body.unwrap_or_default();
    if payload.len() > MAX_BODY {
        bail!("request body too large (max 1 MiB)");
    }
    match tokio::time::timeout(TIMEOUT, exchange(socket, method, path, payload)).await {
        Ok(r) => r,
        Err(_) => bail!(
            "the vault at {} did not answer within {}s",
            socket.display(),
            TIMEOUT.as_secs()
        ),
    }
}

/// The effective uid, read without libc from the owner of `/proc/self`; fails closed.
fn effective_uid() -> anyhow::Result<u32> {
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .context("cannot determine the current user (reading /proc/self)")
}

/// Pure policy: the admin API has no authentication of its own, so before talking to a
/// socket make sure only we could have created it. The parent directory must be ours and
/// closed to group/others; the socket must be ours and not writable by group/others.
fn check_socket_security(
    socket: &Path,
    parent: (&Path, u32, u32),
    sock: Option<(u32, u32)>,
    me: u32,
) -> anyhow::Result<()> {
    let (dir, dir_uid, dir_mode) = parent;
    if dir_uid != me {
        bail!(
            "refusing to use {}: its directory {} is owned by uid {dir_uid}, not by you (uid {me})",
            socket.display(),
            dir.display()
        );
    }
    if dir_mode & 0o077 != 0 {
        bail!(
            "refusing to use {}: its directory {} is accessible to group/others (mode {:o}); the socket must live in a 0700 directory such as $XDG_RUNTIME_DIR",
            socket.display(),
            dir.display(),
            dir_mode & 0o7777
        );
    }
    if let Some((uid, mode)) = sock {
        if uid != me {
            bail!(
                "refusing to use {}: it is owned by uid {uid}, not by you (uid {me})",
                socket.display()
            );
        }
        if mode & 0o022 != 0 {
            bail!(
                "refusing to use {}: it is writable by group/others (mode {:o})",
                socket.display(),
                mode & 0o7777
            );
        }
    }
    Ok(())
}

/// Runs [`check_socket_security`] on the real filesystem. A missing path is left to `connect`,
/// whose error says how to start the server.
fn ensure_private_socket(socket: &Path) -> anyhow::Result<()> {
    let parent = match socket.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let pm = match std::fs::metadata(parent) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", parent.display())),
    };
    let sm = match std::fs::symlink_metadata(socket) {
        Ok(m) => Some((m.uid(), m.permissions().mode())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", socket.display())),
    };
    check_socket_security(
        socket,
        (parent, pm.uid(), pm.permissions().mode()),
        sm,
        effective_uid()?,
    )
}

async fn exchange(
    socket: &Path,
    method: Method,
    path: &str,
    payload: Bytes,
) -> anyhow::Result<(StatusCode, Bytes)> {
    ensure_private_socket(socket)?;
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| {
            format!(
                "cannot reach the vault at {} (is `sc serve` running?)",
                socket.display()
            )
        })?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("handshake with the vault failed")?;
    tokio::spawn(conn);
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(payload))
        .context("invalid request")?;
    let resp = sender
        .send_request(req)
        .await
        .context("request to the vault failed")?;
    let status = resp.status();
    let bytes = Limited::new(resp.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|e| {
            if e.downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                anyhow::anyhow!("response too large (max 1 MiB)")
            } else {
                anyhow::anyhow!("reading the response failed: {e}")
            }
        })?
        .to_bytes();
    Ok((status, bytes))
}

/// Decodes a response body: empty is `Null`, JSON is parsed, anything else becomes a (lossy)
/// string so that neither invalid JSON nor invalid UTF-8 can panic or abort.
pub(crate) fn parse_body(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).into_owned()))
    }
}

/// JSON convenience wrapper over [`call_raw`].
pub async fn call(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<(StatusCode, Value)> {
    let payload = body
        .map(|b| serde_json::to_vec(&b).map(Bytes::from))
        .transpose()?;
    let (status, bytes) = call_raw(socket, method, path, payload).await?;
    Ok((status, parse_body(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_and_modes_are_checked_with_injected_uids() {
        let sock = Path::new("/run/user/1000/sg.sock");
        let dir = Path::new("/run/user/1000");
        let ok = |p: (u32, u32), s: Option<(u32, u32)>| {
            check_socket_security(sock, (dir, p.0, p.1), s, 1000)
        };
        assert!(ok((1000, 0o700), Some((1000, 0o600))).is_ok());
        assert!(ok((1000, 0o700), None).is_ok());
        assert!(ok((1000, 0o700), Some((1000, 0o775))).is_err());
        let e = ok((0, 0o700), Some((1000, 0o600))).unwrap_err().to_string();
        assert!(e.contains("owned by uid 0"), "{e}");
        let e = ok((1000, 0o755), None).unwrap_err().to_string();
        assert!(e.contains("accessible to group/others"), "{e}");
        let e = ok((1000, 0o700), Some((1001, 0o600)))
            .unwrap_err()
            .to_string();
        assert!(e.contains("owned by uid 1001"), "{e}");
        assert!(ok((1000, 0o700), Some((1000, 0o666))).is_err());
    }

    #[test]
    fn effective_uid_is_ours() {
        assert!(effective_uid().is_ok());
    }
}
