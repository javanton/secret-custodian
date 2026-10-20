#![no_main]
use libfuzzer_sys::fuzz_target;
use sg_ca::CaService;
use std::sync::{Arc, OnceLock};

fn ca() -> &'static CaService {
    static C: OnceLock<CaService> = OnceLock::new();
    C.get_or_init(|| CaService::init_or_load(Arc::clone(&sg_fuzz::temp_vault())).expect("ca"))
}

/// The documented domain rules, written independently of the library.
fn rules_ok(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 || d.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    if !d.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        return false;
    }
    if d != "localhost" && !d.contains('.') {
        return false;
    }
    let labels_ok = d
        .split('.')
        .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'));
    let last = d.rsplit('.').next().unwrap_or("");
    labels_ok && !last.bytes().all(|b| b.is_ascii_digit()) && d != "invalid" && !d.ends_with(".invalid")
}

// Up to 3 domains of up to 100 bytes (certificate generation is slow); split on 0xFF.
fuzz_target!(|data: &[u8]| {
    let domains: Vec<String> = data
        .split(|&b| b == 0xff)
        .take(3)
        .map(|p| sg_fuzz::lossy(p, 100))
        .collect();
    let normalised: Vec<String> = domains.iter().map(|d| d.trim().to_ascii_lowercase()).collect();
    let all_valid = normalised.iter().all(|d| rules_ok(d));
    match ca().prepare_domains(&domains) {
        Ok(_) => assert!(all_valid, "CA accepted a domain outside the documented rules: {domains:?}"),
        Err(e) => assert!(!all_valid, "documented-valid domains refused ({e}): {domains:?}"),
    }
});
