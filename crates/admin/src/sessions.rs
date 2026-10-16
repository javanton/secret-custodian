use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

const MAX_SESSIONS: usize = 16;
const MAX_LOGIN_TOKENS: usize = 8;

/// One-time login tokens and the browser sessions they are exchanged for.
///
/// Both collections are capped (oldest entry evicted first) so a flood of login
/// links or exchanges cannot grow memory without bound.
pub struct Sessions {
    ttl: Duration,
    max_sessions: usize,
    max_login: usize,
    login: Mutex<VecDeque<String>>,
    active: Mutex<HashMap<String, Instant>>,
}

fn random_hex() -> String {
    hex::encode(sg_core::crypto::random_bytes::<32>())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl Sessions {
    /// Session lifetime used by [`Sessions::new`]; matches the cookie `Max-Age`.
    pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

    pub fn new() -> Self {
        Self::with_limits(Self::DEFAULT_SESSION_TTL, MAX_SESSIONS, MAX_LOGIN_TOKENS)
    }

    /// Custom lifetime and caps (a cap below 1 is raised to 1).
    pub fn with_limits(ttl: Duration, max_sessions: usize, max_login_tokens: usize) -> Self {
        Self {
            ttl,
            max_sessions: max_sessions.max(1),
            max_login: max_login_tokens.max(1),
            login: Mutex::new(VecDeque::new()),
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a 256-bit single-use login token; the oldest pending one is dropped at the cap.
    pub fn new_login_token(&self) -> String {
        let t = random_hex();
        let mut q = lock(&self.login);
        while q.len() >= self.max_login {
            q.pop_front();
        }
        q.push_back(t.clone());
        t
    }

    /// Consumes a login token and returns a new session id. Unknown, used and evicted
    /// tokens are indistinguishable (`None`). The removal happens under one lock, so of
    /// any number of concurrent attempts exactly one wins.
    pub fn exchange(&self, token: &str) -> Option<String> {
        {
            let mut q = lock(&self.login);
            let pos = q.iter().position(|t| t == token)?;
            q.remove(pos);
        }
        let s = random_hex();
        let mut a = lock(&self.active);
        let ttl = self.ttl;
        a.retain(|_, at| at.elapsed() < ttl);
        while a.len() >= self.max_sessions {
            let Some(oldest) = a.iter().min_by_key(|(_, at)| **at).map(|(k, _)| k.clone()) else {
                break;
            };
            a.remove(&oldest);
        }
        a.insert(s.clone(), Instant::now());
        Some(s)
    }

    pub fn is_valid(&self, session: &str) -> bool {
        let mut a = lock(&self.active);
        let ttl = self.ttl;
        a.retain(|_, at| at.elapsed() < ttl);
        a.contains_key(session)
    }
}
