use base64::{engine::general_purpose::STANDARD, Engine};

/// Extracts the token from a `Proxy-Authorization` value: `Bearer <t>` or `Basic base64(user:<t>)`.
pub fn extract_proxy_token(header: &str) -> Option<String> {
    let (scheme, rest) = header.trim().split_once(' ')?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(rest.to_string());
    }
    if scheme.eq_ignore_ascii_case("basic") {
        let decoded = String::from_utf8(STANDARD.decode(rest).ok()?).ok()?;
        let (_, token) = decoded.split_once(':')?;
        return if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn basic_takes_token_from_password() {
        let h = format!("Basic {}", STANDARD.encode("machine:the.jwt.token"));
        assert_eq!(extract_proxy_token(&h).as_deref(), Some("the.jwt.token"));
    }

    #[test]
    fn bearer_and_case_insensitive_scheme() {
        assert_eq!(
            extract_proxy_token("Bearer abc.def.ghi").as_deref(),
            Some("abc.def.ghi")
        );
        assert_eq!(extract_proxy_token("bearer abc").as_deref(), Some("abc"));
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(extract_proxy_token(""), None);
        assert_eq!(extract_proxy_token("Basic !!!notbase64"), None);
        assert_eq!(extract_proxy_token("Basic bm9jb2xvbg=="), None);
        assert_eq!(extract_proxy_token("Digest abc"), None);
        assert_eq!(extract_proxy_token("Bearer "), None);
    }

    #[test]
    fn extra_garbage_does_not_panic() {
        let long = format!("Bearer {}", "a".repeat(1_000_000));
        assert!(extract_proxy_token(&long).is_some());
        assert_eq!(extract_proxy_token("💥 💥"), None);
        assert_eq!(extract_proxy_token("Basic 💥"), None);
        // password containing ':' keeps everything after the first colon
        let h = format!("Basic {}", STANDARD.encode("u:a:b"));
        assert_eq!(extract_proxy_token(&h).as_deref(), Some("a:b"));
        // empty password
        let h = format!("Basic {}", STANDARD.encode("u:"));
        assert_eq!(extract_proxy_token(&h), None);
        // invalid UTF-8 in decoded credentials
        let h = format!("Basic {}", STANDARD.encode([b'u', b':', 0xff, 0xfe]));
        assert_eq!(extract_proxy_token(&h), None);
    }
}
