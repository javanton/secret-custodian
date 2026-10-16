use crate::sessions::Sessions;
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::Vault;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<Vault>,
    pub tokens: Arc<TokenService>,
    pub ca: Arc<CaService>,
    pub sessions: Arc<Sessions>,
    /// Accepted `Host` header values (and, as `http://<host>`, `Origin` values) of the web listener.
    pub allowed_hosts: Vec<String>,
}
