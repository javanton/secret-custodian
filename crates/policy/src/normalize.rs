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

fn decode_all_once(input: &[u8]) -> Vec<u8> {
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex(input[i + 1]), hex(input[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

/// Strict view of a path, used ONLY for matching (the proxy forwards `normalize_path`).
/// Repeatedly percent-decodes everything (cap 8 rounds), maps `\` to `/`, strips `;params`
/// from each segment, then resolves `.`/`..` and collapses `//`. `None` means the path cannot
/// be judged safely (NUL, invalid UTF-8, or encoding that never stabilises).
pub fn strict_path(p: &str) -> Option<String> {
    let mut cur = p.as_bytes().to_vec();
    let mut stable = false;
    for _ in 0..8 {
        let next = decode_all_once(&cur);
        if next == cur {
            stable = true;
            break;
        }
        cur = next;
    }
    if !stable {
        return None;
    }
    let text = String::from_utf8(cur).ok()?;
    if text.contains('\0') {
        return None;
    }
    let text = text.replace('\\', "/");
    let mut segs: Vec<&str> = Vec::new();
    for raw in text.split('/') {
        let seg = raw.split(';').next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            _ => segs.push(seg),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segs.join("/"));
    if text.ends_with('/') && out != "/" {
        out.push('/');
    }
    Some(out)
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

    #[test]
    fn strict_path_decodes_everything_and_resolves_dots() {
        assert_eq!(strict_path("/repos/..%2fadmin").as_deref(), Some("/admin"));
        assert_eq!(strict_path("/repos/..%2Fadmin").as_deref(), Some("/admin"));
        assert_eq!(
            strict_path("/repos/%2e%2e%2fadmin").as_deref(),
            Some("/admin")
        );
        assert_eq!(strict_path("/repos/..%5cadmin").as_deref(), Some("/admin"));
        assert_eq!(strict_path("/repos/..\\admin").as_deref(), Some("/admin"));
        assert_eq!(strict_path("/repos/..;/admin").as_deref(), Some("/admin"));
        assert_eq!(
            strict_path("/repos/%2e%2e;x/admin").as_deref(),
            Some("/admin")
        );
        assert_eq!(
            strict_path("/repos/%252e%252e%252fadmin").as_deref(),
            Some("/admin")
        );
        assert_eq!(
            strict_path("/repos/..%252fadmin").as_deref(),
            Some("/admin")
        );
        assert_eq!(strict_path("/a%2Fb").as_deref(), Some("/a/b"));
        assert_eq!(strict_path("/a;x=1/b/").as_deref(), Some("/a/b/"));
        assert_eq!(strict_path("//a///b").as_deref(), Some("/a/b"));
        assert_eq!(strict_path("").as_deref(), Some("/"));
    }

    #[test]
    fn strict_path_gives_up_on_nul_bad_utf8_and_deep_encoding() {
        assert_eq!(strict_path("/repos/%00"), None);
        assert_eq!(strict_path("/repos/%2500"), None);
        assert_eq!(strict_path("/repos/%ff"), None);
        // 9 layers of encoding never stabilise within the cap.
        let mut s = String::from("/a/%2e");
        for _ in 0..9 {
            s = s.replace('%', "%25");
        }
        assert_eq!(strict_path(&s), None);
    }
}
