use sha2::{Digest as _, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

const MAX_SESSIONS: usize = 16;
const MAX_LOGIN_TOKENS: usize = 8;

type Digest = [u8; 32];

/// One-time login tokens and the browser sessions they are exchanged for.
///
/// Only SHA-256 digests are stored (no raw secret ever sits in a map, and a lookup by digest
/// does not leak how much of a guess was right). Both collections are capped (oldest entry
/// evicted first) so a flood of login links or exchanges cannot grow memory without bound,
/// and pending login tokens expire after [`Sessions::DEFAULT_LOGIN_TTL`].
pub struct Sessions {
    ttl: Duration,
    login_ttl: Duration,
    max_sessions: usize,
    max_login: usize,
    login: Mutex<VecDeque<(Digest, Instant)>>,
    active: Mutex<HashMap<Digest, Instant>>,
}

impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sessions")
            .field("pending_login_tokens", &lock(&self.login).len())
            .field("active_sessions", &lock(&self.active).len())
            .finish()
    }
}

fn random_hex() -> String {
    hex::encode(sg_core::crypto::random_bytes::<32>())
}

fn digest(secret: &str) -> Digest {
    Sha256::digest(secret.as_bytes()).into()
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
    /// Session lifetime used by [`Sessions::new`].
    pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
    /// How long a login token can wait to be exchanged.
    pub const DEFAULT_LOGIN_TTL: Duration = Duration::from_secs(10 * 60);

    pub fn new() -> Self {
        Self::with_limits(
            Self::DEFAULT_SESSION_TTL,
            MAX_SESSIONS,
            MAX_LOGIN_TOKENS,
            Self::DEFAULT_LOGIN_TTL,
        )
    }

    /// Custom lifetimes and caps (a cap below 1 is raised to 1).
    pub fn with_limits(
        ttl: Duration,
        max_sessions: usize,
        max_login_tokens: usize,
        login_ttl: Duration,
    ) -> Self {
        Self {
            ttl,
            login_ttl,
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
        let ttl = self.login_ttl;
        q.retain(|(_, at)| at.elapsed() < ttl);
        while q.len() >= self.max_login {
            q.pop_front();
        }
        q.push_back((digest(&t), Instant::now()));
        t
    }

    /// Consumes a login token and returns a new 256-bit session id. Unknown, used, expired
    /// and evicted tokens are indistinguishable (`None`). The removal happens under one
    /// lock, so of any number of concurrent attempts exactly one wins.
    pub fn exchange(&self, token: &str) -> Option<String> {
        let d = digest(token);
        {
            let mut q = lock(&self.login);
            let ttl = self.login_ttl;
            q.retain(|(_, at)| at.elapsed() < ttl);
            let pos = q.iter().position(|(t, _)| *t == d)?;
            q.remove(pos);
        }
        let s = random_hex();
        let mut a = lock(&self.active);
        let ttl = self.ttl;
        a.retain(|_, at| at.elapsed() < ttl);
        while a.len() >= self.max_sessions {
            let Some(oldest) = a.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) else {
                break;
            };
            a.remove(&oldest);
        }
        a.insert(digest(&s), Instant::now());
        Some(s)
    }

    pub fn is_valid(&self, session: &str) -> bool {
        let d = digest(session);
        let mut a = lock(&self.active);
        let ttl = self.ttl;
        a.retain(|_, at| at.elapsed() < ttl);
        a.contains_key(&d)
    }
}
