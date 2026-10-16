use anyhow::{bail, Context};
use bytes::Bytes;
use http::{header, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{path::Path, time::Duration};

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

async fn exchange(
    socket: &Path,
    method: Method,
    path: &str,
    payload: Bytes,
) -> anyhow::Result<(StatusCode, Bytes)> {
    let stream = tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| {
            format!(
                "cannot reach the vault at {} (is `sg serve` running?)",
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
