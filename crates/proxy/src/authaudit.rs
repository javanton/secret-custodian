//! Rate limit for the audit of rejected-but-signed tokens.
//!
//! A request whose token is validly signed but revoked or expired is audited, at most once per
//! token id (`jti`) per interval. The map is bounded: when it is full of entries that are still
//! inside their interval, a NEW jti is simply not audited (bounded memory beats completeness).
//! Entries older than the interval are evictable and are dropped to make room.

use std::{collections::HashMap, sync::Mutex, time::Duration, time::Instant};

/// Most jtis tracked at once.
pub(crate) const MAX_TRACKED: usize = 4096;

pub(crate) struct AuthAuditLimiter {
    interval: Duration,
    cap: usize,
    last: Mutex<HashMap<String, Instant>>,
}

impl AuthAuditLimiter {
    pub fn new(interval: Duration) -> Self {
        Self::with_cap(interval, MAX_TRACKED)
    }

    pub fn with_cap(interval: Duration, cap: usize) -> Self {
        Self {
            interval,
            cap,
            last: Mutex::new(HashMap::new()),
        }
    }

    /// True when a row for `jti` may be written now (and records that it was).
    pub fn allow(&self, jti: &str, now: Instant) -> bool {
        // A poisoned lock only means another thread panicked mid-update of a plain map.
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        let live = |t: &Instant| now.saturating_duration_since(*t) < self.interval;
        if let Some(t) = last.get_mut(jti) {
            if live(t) {
                return false;
            }
            *t = now;
            return true;
        }
        if last.len() >= self.cap {
            last.retain(|_, t| live(t));
            if last.len() >= self.cap {
                return false;
            }
        }
        last.insert(jti.to_string(), now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const I: Duration = Duration::from_secs(60);

    #[test]
    fn allows_first_denies_repeat_allows_after_interval() {
        let l = AuthAuditLimiter::new(I);
        let t0 = Instant::now();
        assert!(l.allow("a", t0));
        assert!(!l.allow("a", t0));
        assert!(!l.allow("a", t0 + Duration::from_secs(59)));
        assert!(l.allow("a", t0 + I));
        assert!(!l.allow("a", t0 + I + Duration::from_secs(1)));
    }

    #[test]
    fn limit_is_per_jti() {
        let l = AuthAuditLimiter::new(I);
        let t0 = Instant::now();
        assert!(l.allow("a", t0));
        assert!(l.allow("b", t0));
        assert!(!l.allow("a", t0));
        assert!(!l.allow("b", t0));
    }

    #[test]
    fn full_of_live_entries_denies_new_jti_but_not_known_ones_after_interval() {
        let l = AuthAuditLimiter::with_cap(I, 3);
        let t0 = Instant::now();
        for j in ["a", "b", "c"] {
            assert!(l.allow(j, t0));
        }
        assert!(
            !l.allow("d", t0 + Duration::from_secs(1)),
            "map full, all live"
        );
        assert_eq!(l.last.lock().unwrap().len(), 3, "never grows past the cap");
        assert!(
            l.allow("a", t0 + I),
            "a known jti can refresh its own entry"
        );
    }

    #[test]
    fn expired_entries_are_evicted_to_make_room() {
        let l = AuthAuditLimiter::with_cap(I, 3);
        let t0 = Instant::now();
        assert!(l.allow("a", t0));
        assert!(l.allow("b", t0));
        assert!(l.allow("c", t0 + Duration::from_secs(30)));
        // a and b are now older than the interval, c is still live.
        assert!(l.allow("d", t0 + I));
        let map = l.last.lock().unwrap();
        assert!(map.len() <= 3);
        assert!(map.contains_key("c") && map.contains_key("d"));
        assert!(!map.contains_key("a") && !map.contains_key("b"));
    }

    #[test]
    fn default_cap_is_4096() {
        let l = AuthAuditLimiter::new(I);
        let t0 = Instant::now();
        for i in 0..MAX_TRACKED {
            assert!(l.allow(&format!("j{i}"), t0));
        }
        assert!(!l.allow("one-more", t0));
        assert_eq!(l.last.lock().unwrap().len(), MAX_TRACKED);
    }
}
