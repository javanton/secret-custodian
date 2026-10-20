#![no_main]
use libfuzzer_sys::fuzz_target;
use sg_policy::normalize_host;

// Invariants: idempotent; when Some the host is non-empty, <= 253 bytes, lowercase, printable
// ASCII from the allowed set, no control characters.
fuzz_target!(|data: &[u8]| {
    let input = sg_fuzz::lossy(data, 1024);
    if let Some(h) = normalize_host(&input) {
        assert!(!h.is_empty() && h.len() <= 253, "length: {input:?} -> {h:?}");
        assert!(h == h.to_ascii_lowercase(), "not lowercase: {input:?} -> {h:?}");
        assert!(
            h.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'_')),
            "bad byte: {input:?} -> {h:?}"
        );
        assert!(!h.chars().any(|c| c.is_control()), "control char");
        assert!(!h.ends_with('.'), "trailing dot: {input:?} -> {h:?}");
        assert_eq!(normalize_host(&h).as_deref(), Some(h.as_str()), "not idempotent for {input:?}");
    }
});
