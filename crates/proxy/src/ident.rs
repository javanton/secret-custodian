use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Counts a resource (tunnels, upstream requests) per token identity (`jti`).
#[derive(Default)]
pub(crate) struct IdentityCounters {
    map: Mutex<HashMap<String, usize>>,
}

/// One unit of an identity's budget; released on drop.
pub(crate) struct IdentityGuard {
    counters: Arc<IdentityCounters>,
    key: String,
}

impl IdentityCounters {
    /// Takes one unit for `key` unless it already holds `cap` of them (never waits).
    pub fn try_acquire(self: &Arc<Self>, key: &str, cap: usize) -> Option<IdentityGuard> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(key.to_string()).or_insert(0);
        if *n >= cap.max(1) {
            return None;
        }
        *n += 1;
        Some(IdentityGuard {
            counters: self.clone(),
            key: key.to_string(),
        })
    }
}

impl Drop for IdentityGuard {
    fn drop(&mut self) {
        let mut map = self.counters.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_per_key_and_releases_on_drop() {
        let c = Arc::new(IdentityCounters::default());
        let a1 = c.try_acquire("a", 2).unwrap();
        let _a2 = c.try_acquire("a", 2).unwrap();
        assert!(c.try_acquire("a", 2).is_none());
        assert!(c.try_acquire("b", 2).is_some());
        drop(a1);
        assert!(c.try_acquire("a", 2).is_some());
        assert!(
            c.map.lock().unwrap().get("b").is_none(),
            "b's guard was dropped"
        );
    }
}
