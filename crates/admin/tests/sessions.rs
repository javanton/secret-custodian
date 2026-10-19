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
    let s = Sessions::with_limits(Duration::from_millis(40), 16, 8, Duration::from_secs(60));
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
    let s = Sessions::with_limits(Duration::from_secs(60), 3, 8, Duration::from_secs(60));
    let ids: Vec<String> = (0..4)
        .map(|_| s.exchange(&s.new_login_token()).unwrap())
        .collect();
    assert!(!s.is_valid(&ids[0]));
    assert!(ids[1..].iter().all(|i| s.is_valid(i)));
}

#[test]
fn oldest_pending_login_token_is_evicted_at_the_cap() {
    let s = Sessions::with_limits(Duration::from_secs(60), 16, 2, Duration::from_secs(60));
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

#[test]
fn pending_login_tokens_expire() {
    let s = Sessions::with_limits(Duration::from_secs(60), 16, 8, Duration::from_millis(40));
    let t = s.new_login_token();
    std::thread::sleep(Duration::from_millis(80));
    assert!(s.exchange(&t).is_none());
}

#[test]
fn default_login_token_ttl_is_ten_minutes() {
    assert_eq!(Sessions::DEFAULT_LOGIN_TTL, Duration::from_secs(600));
}

#[test]
fn session_ids_are_256_bit_hex_and_distinct() {
    let s = Sessions::new();
    let a = s.exchange(&s.new_login_token()).unwrap();
    let b = s.exchange(&s.new_login_token()).unwrap();
    for id in [&a, &b] {
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|c| c.is_ascii_hexdigit()));
    }
    assert_ne!(a, b);
}

#[test]
fn default_caps_are_8_pending_tokens_and_16_sessions() {
    let s = Sessions::new();
    let toks: Vec<String> = (0..9).map(|_| s.new_login_token()).collect();
    assert!(s.exchange(&toks[0]).is_none());
    assert!(s.exchange(&toks[8]).is_some());
    let ids: Vec<String> = (0..17)
        .map(|_| s.exchange(&s.new_login_token()).unwrap())
        .collect();
    assert!(!s.is_valid(&ids[0]));
    assert!(s.is_valid(&ids[16]));
}

#[test]
fn secrets_are_not_kept_in_clear_in_memory() {
    let s = Sessions::new();
    let t = s.new_login_token();
    let sid = s.exchange(&t).unwrap();
    let dump = format!("{:?}", s);
    assert!(!dump.contains(&t) && !dump.contains(&sid));
}
