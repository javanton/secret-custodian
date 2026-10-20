use std::net::IpAddr;

pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Lowercases, strips brackets, port and trailing dot. Returns None for anything that is not a plain hostname or IP.
pub fn normalize_host(input: &str) -> Option<String> {
    let s = input.trim();
    let host = if let Some(rest) = s.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port_ok = after.is_empty()
            || after
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if !port_ok {
            return None;
        }
        inside.to_string()
    } else if s.matches(':').count() == 1 {
        s.split(':').next()?.to_string()
    } else {
        s.to_string()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':' || b == b'_');
    // A colon is only legal inside an IPv6 literal.
    if valid && (!host.contains(':') || is_ip_literal(&host)) {
        Some(host)
    } else {
        None
    }
}

/// Decodes `%XX` escapes of unreserved characters (ASCII letter, digit, `-`, `.`, `_`, `~`) in one
/// linear pass. A naive single left-to-right scan can leave a literal (undecoded) `%` directly
/// before characters produced by decoding a *later*, genuinely separate escape; concatenated,
/// those characters can read as a brand-new `%XX` escape that never existed as one in the input
/// (e.g. `"%2%65"`: the first `%2` fails to decode and stays literal, but the later `%65` decodes
/// to `e` right after it, forming the look-alike `%2e`, which itself decodes further to `.`).
/// This function avoids that by collapsing a freshly completed escape at the *end* of the output
/// immediately after every push, so cascades like that resolve inline, within this single pass,
/// instead of needing a second rescan of the whole string. That also makes it O(n): every byte is
/// pushed into the output at most once net of collapses (each collapse removes exactly the 2 extra
/// bytes it previously added), so the total work across every push and every collapse is linear in
/// the input length, however many escapes cascade. The result is identical to repeatedly
/// rescanning to a fixpoint, because a `%` can never itself be a hex digit, so completed escapes
/// never overlap and the leftmost-first, incremental collapse converges to the same unique normal
/// form that repeated whole-string rescans would.
fn decode_unreserved(segment: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(segment.len());
    for ch in segment.chars() {
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        collapse_trailing_escape(&mut out);
    }
    // Every byte pushed is either a full UTF-8 char's own bytes or a single decoded ASCII byte
    // that replaced a well-formed `%HH` (itself ASCII), so `out` is always valid UTF-8.
    String::from_utf8(out).expect("decode_unreserved only ever appends valid UTF-8")
}

/// If `out` now ends with a `%HH` that decodes to an unreserved character, replaces it with that
/// one byte; repeats, since the replacement can itself complete an escape that was waiting one
/// position further back (e.g. collapsing `%65` to `e` after a literal `3` can then complete a
/// `%33` that was two characters further left). Each iteration removes 2 bytes net, so this is
/// amortized O(1) per character processed by `decode_unreserved`'s loop over the whole segment.
fn collapse_trailing_escape(out: &mut Vec<u8>) {
    loop {
        let len = out.len();
        if len < 3 || out[len - 3] != b'%' {
            return;
        }
        let Ok(hex) = std::str::from_utf8(&out[len - 2..]) else {
            return;
        };
        let Ok(v) = u8::from_str_radix(hex, 16) else {
            return;
        };
        if !(v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~')) {
            return;
        }
        out.truncate(len - 3);
        out.push(v);
    }
}

/// Resolves `.`/`..`, decodes escapes of unreserved characters, collapses `//`. Encoded `/` stays
/// encoded. `decode_unreserved` is both idempotent (running it again on its own output cannot
/// decode anything further — see its doc comment) and linear-time, so this stays fast even on
/// adversarial input that would make a naive rescan-to-fixpoint decode quadratic.
pub fn normalize_path(path: &str) -> String {
    let mut segs: Vec<String> = Vec::new();
    for raw in path.split('/') {
        let seg = decode_unreserved(raw);
        match seg.as_str() {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            _ => segs.push(seg),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if path.ends_with('/') && out != "/" {
        out.push('/');
    }
    out
}

const MAX_DECODE_ROUNDS: usize = 8;

/// One percent-decoding round. `first` is the round applied to the raw path: there a `%` that is
/// not followed by two hex digits makes the path unjudgeable. Later rounds only see `%` that
/// earlier decoding produced (e.g. `%25` -> `%`), which stay literal, except `%u`/`%U` (the
/// IIS-style `%uXXXX` escape some origins honour), which is never judgeable.
fn decode_round(input: &str, first: bool) -> Option<String> {
    let b = input.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            match (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                _ => {
                    if first || matches!(b.get(i + 1), Some(b'u' | b'U')) {
                        return None;
                    }
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    let text = String::from_utf8(out).ok()?;
    if text.contains('\0') {
        return None;
    }
    Some(text)
}

/// `[P, decode(P), decode(decode(P)), ...]` until the string stops changing. `None` when the path
/// cannot be judged safely: malformed `%`, NUL, invalid UTF-8, or more than 8 decoding layers.
pub(crate) fn decode_chain(p: &str) -> Option<Vec<String>> {
    if p.contains('\0') {
        return None;
    }
    let mut chain = vec![p.to_string()];
    for round in 0..=MAX_DECODE_ROUNDS {
        let next = decode_round(chain.last().expect("chain is never empty"), round == 0)?;
        if &next == chain.last().expect("chain is never empty") {
            return Some(chain);
        }
        if round == MAX_DECODE_ROUNDS {
            return None;
        }
        chain.push(next);
    }
    None
}

/// Longest path (bytes) a restricted rule will judge; anything longer is unjudgeable.
pub(crate) const MAX_JUDGED_PATH_LEN: usize = 8192;

/// Allowlist at the mechanism level: a reading is judgeable only if every character is ASCII and
/// not a control character (C0, DEL). Any non-ASCII character (look-alikes of `.`, `/`, `\`,
/// `?`, `#`, invisible and format characters, ordinary accents, CJK, emoji...) makes the path
/// unjudgeable: some origin may fold, normalize or trim it into a separator, a dot or nothing,
/// and an open-ended blocklist of such code points cannot be complete.
fn has_forbidden_char(s: &str) -> bool {
    s.chars().any(|c| !c.is_ascii() || c.is_ascii_control())
}

/// A segment such as `.`, `..`, `...`, `.. `, `..+`: non-empty, has a `.`, only dots, spaces,
/// tabs and `+` (form-style space).
fn is_dot_like(seg: &str) -> bool {
    seg.contains('.') && seg.chars().all(|c| matches!(c, '.' | ' ' | '\t' | '+'))
}

/// True when any segment is dot-like under EVERY separator model at once (`/ \ ; ? #`), so that
/// resolving dot segments is the identity however an origin splits the path.
fn has_dot_segment(s: &str) -> bool {
    s.split(['/', '\\', ';', '?', '#']).any(is_dot_like)
}

/// True when any segment ends with `.` or a space (Windows-style trimming drops them).
fn has_trimmable_segment(s: &str) -> bool {
    s.split(['/', '\\', ';', '?', '#'])
        .any(|seg| seg.ends_with(['.', ' ']))
}

/// Every reading `R_0..R_n` (percent-decoded 0..n times, until stable) of a path, used ONLY for
/// matching a restricted rule (the proxy forwards `normalize_path`). `None` means the path
/// cannot be judged: too long, undecodable, or some reading holds a control character, a
/// confusable, or a dot segment under any separator model. When this returns `Some`, there is
/// nothing to resolve, so no ordering of origin operations (decode, `;` strip, `?`/`#` cut,
/// `\` mapping, dot resolution) can move the request out of a prefix.
pub(crate) fn judge_readings(p: &str) -> Option<Vec<String>> {
    if p.len() > MAX_JUDGED_PATH_LEN {
        return None;
    }
    let chain = decode_chain(p)?;
    if chain
        .iter()
        .any(|c| has_forbidden_char(c) || has_dot_segment(c))
    {
        return None;
    }
    Some(chain)
}

/// Pattern prefix/body readings: decoded until stable (same cap as paths).
pub(crate) fn pattern_readings(body: &str) -> Option<Vec<String>> {
    decode_chain(body)
}

/// True when a path PATTERN could widen itself: at any decoding depth its text contains `;`,
/// `\`, `?`, `#`, NUL or any control character, a forbidden Unicode character, a dot segment
/// (under any separator model), a segment ending in `.` or a space (origins that trim those
/// would reinterpret the prefix), or it cannot be decoded safely or is too long.
pub(crate) fn pattern_is_self_widening(body: &str) -> bool {
    if body.len() > MAX_JUDGED_PATH_LEN {
        return true;
    }
    let Some(chain) = decode_chain(body) else {
        return true;
    };
    chain.iter().any(|c| {
        c.contains([';', '\\', '?', '#'])
            || has_forbidden_char(c)
            || has_dot_segment(c)
            || has_trimmable_segment(c)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_normalization() {
        assert_eq!(
            normalize_host("API.GitHub.com."),
            Some("api.github.com".into())
        );
        assert_eq!(
            normalize_host("api.github.com:443"),
            Some("api.github.com".into())
        );
        assert_eq!(normalize_host("[::1]:8080"), Some("::1".into()));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("bad host"), None);
        assert_eq!(normalize_host("a/b"), None);
    }

    #[test]
    fn path_normalization_resolves_traversal_and_escapes() {
        assert_eq!(normalize_path("/repos/../admin"), "/admin");
        assert_eq!(normalize_path("/repos/%2e%2e/admin"), "/admin");
        assert_eq!(normalize_path("/repos/%2E%2E/admin"), "/admin");
        assert_eq!(normalize_path("//repos///x"), "/repos/x");
        assert_eq!(normalize_path("/a/./b"), "/a/b");
        assert_eq!(normalize_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/../.."), "/");
        assert_eq!(normalize_path("/repos/"), "/repos/");
        assert_eq!(normalize_path("/%41pi"), "/Api");
    }

    #[test]
    fn ip_literals_are_detected() {
        assert!(is_ip_literal("10.0.0.1"));
        assert!(is_ip_literal("::1"));
        assert!(!is_ip_literal("example.com"));
    }

    // --- extra tests (gaps not covered by the plan) ---

    #[test]
    fn host_trailing_dot_with_port_and_case() {
        assert_eq!(
            normalize_host("Example.COM.:8443"),
            Some("example.com".into())
        );
        assert_eq!(
            normalize_host("  example.com  "),
            Some("example.com".into())
        );
        assert_eq!(normalize_host("."), None);
        assert_eq!(normalize_host(":443"), None);
        assert_eq!(normalize_host("10.0.0.1:80"), Some("10.0.0.1".into()));
        assert_eq!(normalize_host("[::1]"), Some("::1".into()));
    }

    #[test]
    fn host_rejects_malformed_forms() {
        assert_eq!(normalize_host("host:80:90"), None);
        assert_eq!(normalize_host("[::1]garbage"), None);
        assert_eq!(normalize_host("[::1"), None);
        assert_eq!(normalize_host("user@host.com"), None);
        assert_eq!(normalize_host("host.com\r\nX: 1"), None);
        assert_eq!(normalize_host("exa\0mple.com"), None);
        assert_eq!(normalize_host("münchen.de"), None);
    }

    #[test]
    fn encoded_slash_stays_encoded_in_any_hex_case() {
        assert_eq!(normalize_path("/a%2fb"), "/a%2fb");
        assert_eq!(normalize_path("/a%2Fb"), "/a%2Fb");
    }

    #[test]
    fn encoded_slash_cannot_smuggle_traversal() {
        // `%2f` stays encoded, so this is ONE literal segment, not a traversal.
        assert_eq!(normalize_path("/repos/%2e%2e%2f.."), "/repos/..%2f..");
        assert_eq!(normalize_path("/repos/..%2fadmin"), "/repos/..%2fadmin");
        assert_eq!(normalize_path("/repos/%2e%2e%5cadmin"), "/repos/..%5cadmin");
    }

    #[test]
    fn dot_segments_with_encoded_dots_and_mixed_forms() {
        assert_eq!(normalize_path("/a/%2e/b"), "/a/b");
        assert_eq!(normalize_path("/a/.%2e/b"), "/b");
        assert_eq!(normalize_path("/a/%2e./b"), "/b");
        assert_eq!(normalize_path("/a/b/.."), "/a");
        assert_eq!(normalize_path("/a/b/../"), "/a/");
        assert_eq!(normalize_path("/a/.."), "/");
        assert_eq!(normalize_path("/a/../"), "/");
    }

    #[test]
    fn malformed_and_reserved_escapes_are_left_alone() {
        assert_eq!(normalize_path("/a%"), "/a%");
        assert_eq!(normalize_path("/a%4"), "/a%4");
        assert_eq!(normalize_path("/a%zz"), "/a%zz");
        assert_eq!(normalize_path("/a%00b"), "/a%00b");
        assert_eq!(normalize_path("/a%3Fb"), "/a%3Fb");
        assert_eq!(normalize_path("/a%23b"), "/a%23b");
    }

    #[test]
    fn non_ascii_after_percent_does_not_panic() {
        assert_eq!(normalize_path("/%é"), "/%é");
        assert_eq!(normalize_path("/é%e"), "/é%e");
    }

    #[test]
    fn decoding_cannot_assemble_a_new_escape() {
        for p in [
            "%2%65",
            "/api/v1/%2%65%2e/admin",
            "/%2%65%2e",
            "/a%%32e",
            "%2%65%2e%65",
        ] {
            let once = normalize_path(p);
            let twice = normalize_path(&once);
            assert_eq!(
                twice, once,
                "not idempotent for {p:?}: {once:?} -> {twice:?}"
            );
        }
    }

    #[test]
    fn documented_examples_hold() {
        assert_eq!(normalize_path("/repos/../admin"), "/admin");
        assert_eq!(normalize_path("/repos/%2e%2e/admin"), "/admin");
        assert_eq!(normalize_path("//repos///x"), "/repos/x");
        assert_eq!(normalize_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(normalize_path("/%41pi"), "/Api");
        assert_eq!(normalize_path("/repos/%2e%2e%2f.."), "/repos/..%2f..");
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn large_percent_run_does_not_blow_up() {
        let input = "%".repeat(8192);
        let start = std::time::Instant::now();
        let once = normalize_path(&input);
        let twice = normalize_path(&once);
        assert_eq!(twice, once);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(1),
            "took too long: {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn decoding_a_cascading_chain_does_not_blow_up() {
        use std::time::{Duration, Instant};
        // Every round of a naive re-scan-to-fixpoint decodes exactly one more unit of this chain
        // (`%3` repeated, followed by `%33`, which decodes to the digit `3` that completes the
        // next unit back): O(n) rounds of O(n) work each is Theta(n^2). The real function took
        // 9.8s at n=30_000 before this fix; it must now be comfortably linear.
        let input = format!("/{}%33", "%3".repeat(30_000));
        let start = Instant::now();
        let out = normalize_path(&input);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "took {elapsed:?}, expected well under 500ms"
        );
        // The whole chain collapses, one unit at a time from the right, down to a single '3'.
        assert_eq!(out, "/3");
    }

    #[test]
    fn decoding_a_non_cascading_percent_run_does_not_blow_up() {
        use std::time::{Duration, Instant};
        // A different adversarial shape: a long run of `%4` units that do NOT chain into each
        // other (unlike the `%3`/`%33` case, `0x44` decodes to `D`, which does not feed a hex
        // pair with the next `%4` to its left, so this collapses only a few units from the
        // right and then stops). Still exercised here as a second, independently-shaped large
        // input to guard against any remaining non-linear behavior elsewhere in the function.
        let input = format!("/{}%34", "%4".repeat(20_000));
        let start = Instant::now();
        let _ = normalize_path(&input);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "took {:?}, expected well under 500ms",
            start.elapsed()
        );
    }

    #[test]
    fn normalization_is_idempotent() {
        for p in [
            "/repos/%2e%2e/admin",
            "//a///b/",
            "/a%2Fb/%41",
            "/x/../../y/.",
            "/%2e%2e%2f..",
            "",
        ] {
            let once = normalize_path(p);
            assert_eq!(normalize_path(&once), once, "not idempotent for {p:?}");
        }
    }
}
