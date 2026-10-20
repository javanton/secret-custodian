#![no_main]
use base64::{engine::general_purpose::STANDARD, Engine};
use libfuzzer_sys::fuzz_target;
use sg_auth::extract_proxy_token;

// Only `Bearer <token>` and `Basic base64(user:<token>)` (scheme case-insensitive) may yield a
// token; anything else is None. A returned token is never empty.
fuzz_target!(|data: &[u8]| {
    let header = sg_fuzz::lossy(data, 4096);
    let got = extract_proxy_token(&header);
    let scheme_ok = header
        .trim()
        .split_once(' ')
        .map(|(s, _)| s.eq_ignore_ascii_case("bearer") || s.eq_ignore_ascii_case("basic"))
        .unwrap_or(false);
    if let Some(t) = &got {
        assert!(scheme_ok, "token from a non Basic/Bearer header: {header:?}");
        assert!(!t.is_empty(), "empty token: {header:?}");
        let (scheme, rest) = header.trim().split_once(' ').unwrap();
        if scheme.eq_ignore_ascii_case("bearer") {
            assert_eq!(t, rest.trim());
        } else {
            let dec = String::from_utf8(STANDARD.decode(rest.trim()).expect("basic must be base64"))
                .expect("basic must be utf-8");
            assert_eq!(dec.split_once(':').map(|(_, p)| p), Some(t.as_str()));
        }
    }
    // Round trip: a well-formed Basic header always yields exactly its password.
    let tok = sg_fuzz::lossy(data, 200);
    if !tok.is_empty() {
        let h = format!("Basic {}", STANDARD.encode(format!("machine:{tok}")));
        assert_eq!(extract_proxy_token(&h).as_deref(), Some(tok.as_str()));
    }
});
