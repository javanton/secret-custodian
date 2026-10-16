use crate::{server::Session, ProxyState};
use hyper::{body::Incoming, Request};
use std::sync::Arc;

// Provisional stub, replaced in Task 8.
// Task 8 MUST re-verify `session.token` with `state.verifier.verify(..)` on every inner request,
// so that revoking a token stops an already-open tunnel.
pub(crate) async fn serve(
    _req: Request<Incoming>,
    _host: String,
    _port: u16,
    _session: Session,
    _state: Arc<ProxyState>,
) {
}
