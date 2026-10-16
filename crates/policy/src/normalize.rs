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

fn decode_unreserved(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = String::with_capacity(segment.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let Some(v) = segment
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
                    out.push(v as char);
                    i += 3;
                    continue;
                }
            }
        }
        let ch = segment[i..]
            .chars()
            .next()
            .expect("index is on a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Resolves `.`/`..`, decodes escapes of unreserved characters, collapses `//`. Encoded `/` stays encoded.
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

/// Code points that some origin may fold, normalize or trim into `.`, `/`, `\`, `?`, `#`, a
/// space, or nothing (NFKC/NFKD look-alikes, invisible and format characters).
fn is_forbidden_unicode(c: char) -> bool {
    matches!(c,
        '\u{00A0}' | '\u{00AD}' | '\u{034F}' | '\u{037E}' | '\u{1680}' | '\u{180E}'
        | '\u{2000}'..='\u{200F}'
        | '\u{2024}'..='\u{2026}'
        | '\u{2028}'..='\u{202F}'
        | '\u{2044}'
        | '\u{2047}'..='\u{2049}'
        | '\u{205F}'..='\u{2064}'
        | '\u{2215}' | '\u{2216}' | '\u{29F8}' | '\u{3000}'
        | '\u{FE50}'..='\u{FE6B}'
        | '\u{FEFF}'
        | '\u{FF01}'..='\u{FF65}')
}

/// Control characters (C0, DEL), separator/dot look-alikes and non-ASCII whitespace: never
/// judgeable. Ordinary non-ASCII letters (accents, CJK, emoji) are fine.
fn has_forbidden_char(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_ascii_control() || is_forbidden_unicode(c) || (!c.is_ascii() && c.is_whitespace())
    })
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
