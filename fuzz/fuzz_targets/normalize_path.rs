#![no_main]
use libfuzzer_sys::fuzz_target;
use sg_policy::normalize_path;

// Invariants (docs/policy-and-rules.md 6.1): absolute output, no `.`/`..`/empty segments, never
// longer than input + 1, idempotent.
fuzz_target!(|data: &[u8]| {
    let input = sg_fuzz::lossy(data, 8192);
    let once = normalize_path(&input);
    assert!(once.starts_with('/'), "not absolute: {input:?} -> {once:?}");
    assert!(once.len() <= input.len() + 1, "grew: {input:?} -> {once:?}");
    let body = once.strip_suffix('/').unwrap_or(&once);
    if !body.is_empty() {
        for seg in body[1..].split('/') {
            assert!(
                !seg.is_empty() && seg != "." && seg != "..",
                "bad segment {seg:?}: {input:?} -> {once:?}"
            );
        }
    }
    let twice = normalize_path(&once);
    assert_eq!(twice, once, "not idempotent for {input:?}");
});
