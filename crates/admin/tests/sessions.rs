use sg_admin::Sessions;
use std::{sync::Arc, time::Duration};

#[test]
fn login_token_is_single_use() {
    let s = Sessions::new();
    let t = s.new_login_token();
    assert_eq!(t.len(), 64);
    let sid = s.exchange(&t).unwrap();
    assert!(s.is_valid(&sid));
    assert!(s.exchange(&t).is_none());
    assert!(s.exchange("nope").is_none());
    assert!(!s.is_valid("nope"));
    assert_ne!(s.new_login_token(), s.new_login_token());
}

#[test]
fn sessions_expire() {
    let s = Sessions::with_limits(Duration::from_millis(40), 16, 8);
    let sid = s.exchange(&s.new_login_token()).unwrap();
    assert!(s.is_valid(&sid));
    std::thread::sleep(Duration::from_millis(80));
    assert!(!s.is_valid(&sid));
}

#[test]
fn default_ttl_is_eight_hours() {
    assert_eq!(Sessions::DEFAULT_SESSION_TTL, Duration::from_secs(8 * 3600));
}

#[test]
fn oldest_session_is_evicted_at_the_cap() {
    let s = Sessions::with_limits(Duration::from_secs(60), 3, 8);
    let ids: Vec<String> = (0..4)
        .map(|_| s.exchange(&s.new_login_token()).unwrap())
        .collect();
    assert!(!s.is_valid(&ids[0]));
    assert!(ids[1..].iter().all(|i| s.is_valid(i)));
}

#[test]
fn oldest_pending_login_token_is_evicted_at_the_cap() {
    let s = Sessions::with_limits(Duration::from_secs(60), 16, 2);
    let (a, b, c) = (
        s.new_login_token(),
        s.new_login_token(),
        s.new_login_token(),
    );
    assert!(s.exchange(&a).is_none());
    assert!(s.exchange(&b).is_some());
    assert!(s.exchange(&c).is_some());
}

#[test]
fn concurrent_exchange_of_one_token_succeeds_exactly_once() {
    for _ in 0..20 {
        let s = Arc::new(Sessions::new());
        let t = s.new_login_token();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (s, t) = (s.clone(), t.clone());
                std::thread::spawn(move || s.exchange(&t).is_some())
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|w| *w)
            .count();
        assert_eq!(wins, 1);
    }
}
