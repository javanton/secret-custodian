//! Progress-timeout body adapter.
use crate::upstream::{BoxError, ProxyBody};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{sync::Notify, time::Instant};

/// Things a body keeps alive until it is done, aborted or dropped (upstream slots, in-flight
/// accounting...).
pub(crate) type Keep = Vec<Box<dyn Send>>;

struct Cell {
    inner: Mutex<Option<ProxyBody>>,
    keep: Mutex<Keep>,
    waker: Mutex<Option<Waker>>,
    start: Instant,
    last_ms: AtomicU64,
    aborted: AtomicBool,
    stop: Notify,
}

impl Cell {
    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn release(&self) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner()).take();
        let keep = std::mem::take(&mut *self.keep.lock().unwrap_or_else(|e| e.into_inner()));
        drop(inner);
        drop(keep);
    }

    /// Drops the inner body and everything kept, and wakes whoever polls so that it sees the
    /// error. A body that already ended is left alone.
    fn abort(&self) {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.is_none() {
                return;
            }
            self.aborted.store(true, Ordering::Relaxed);
            let inner = g.take();
            drop(g);
            drop(inner);
        }
        drop(std::mem::take(
            &mut *self.keep.lock().unwrap_or_else(|e| e.into_inner()),
        ));
        if let Some(w) = self.waker.lock().unwrap_or_else(|e| e.into_inner()).take() {
            w.wake();
        }
    }
}

/// A body that fails with `TimedOut` once it has produced no frame for `idle`.
///
/// The timer runs in a separate task on purpose: when the peer stops reading, the transport
/// stops polling the body altogether, so an in-poll timer would never fire. On timeout the
/// inner body and every `keep` item are dropped immediately (freeing the upstream connection),
/// even though the transport still holds this wrapper.
struct Watched {
    cell: Arc<Cell>,
}

/// Wraps `inner` with the progress timeout. A body with no data to move is returned as is
/// (and `keep` is dropped).
pub(crate) fn watch(inner: ProxyBody, idle: Duration, keep: Keep) -> ProxyBody {
    if inner.is_end_stream() {
        return inner;
    }
    let cell = Arc::new(Cell {
        inner: Mutex::new(Some(inner)),
        keep: Mutex::new(keep),
        waker: Mutex::new(None),
        start: Instant::now(),
        last_ms: AtomicU64::new(0),
        aborted: AtomicBool::new(false),
        stop: Notify::new(),
    });
    let c = cell.clone();
    tokio::spawn(async move {
        loop {
            let last = Duration::from_millis(c.last_ms.load(Ordering::Relaxed));
            tokio::select! {
                _ = c.stop.notified() => return,
                _ = tokio::time::sleep_until(c.start + last + idle) => {}
            }
            let last = Duration::from_millis(c.last_ms.load(Ordering::Relaxed));
            if c.start.elapsed().saturating_sub(last) >= idle {
                c.abort();
                return;
            }
        }
    });
    Watched { cell }.boxed()
}

impl Body for Watched {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let c = &self.cell;
        let mut g = c.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(inner) = g.as_mut() else {
            return if c.aborted.load(Ordering::Relaxed) {
                Poll::Ready(Some(Err(Box::new(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "body idle timeout",
                )))))
            } else {
                Poll::Ready(None)
            };
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Pending => {
                *c.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Some(Ok(f))) => {
                c.touch();
                Poll::Ready(Some(Ok(f)))
            }
            Poll::Ready(other) => {
                // End of body or error: nothing more will be produced.
                let inner = g.take();
                drop(g);
                drop(inner);
                c.stop.notify_one();
                Poll::Ready(other)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self
            .cell
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(b) => b.is_end_stream(),
            None => !self.cell.aborted.load(Ordering::Relaxed),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self
            .cell
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(b) => b.size_hint(),
            None => SizeHint::default(),
        }
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        self.cell.stop.notify_one();
        self.cell.release();
    }
}
