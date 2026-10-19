//! Small formatting helpers: RFC 3339 timestamps, aligned tables, URL encoding, durations.

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn rfc3339(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Replaces control characters (terminal escapes, newlines) and bounds the length, for text that
/// comes from the server.
pub fn sanitize(s: &str, max_chars: usize) -> String {
    let mut out: String = s
        .chars()
        .take(max_chars)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

/// Left-aligned table with a header row; columns are separated by two spaces.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| sanitize(c, 200)).collect())
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(&format!("{c:<w$}  ", w = widths[i]));
            }
        }
        s.push('\n');
        s
    };
    let mut out = line(headers.to_vec());
    for r in &rows {
        out.push_str(&line(r.iter().map(String::as_str).collect()));
    }
    out
}

/// Percent-encodes everything except RFC 3986 unreserved characters. A segment made only of dots
/// is encoded too, so `.` and `..` can never be resolved as path navigation.
pub fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let all_dots = !s.is_empty() && s.bytes().all(|b| b == b'.');
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'~') || (b == b'.' && !all_dots)
        {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub const MAX_TTL_SECS: u64 = 315_360_000;

/// `3600`, `90s`, `30m`, `12h` or `7d`; at most 10 years, at least 1 second.
pub fn parse_ttl(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err("expected seconds or a duration like 30m, 12h, 7d".into()),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected seconds or a duration like 30m, 12h, 7d".into());
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| "duration is too large".to_string())?;
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| "duration is too large".to_string())?;
    if secs == 0 {
        return Err("duration must be at least 1 second".into());
    }
    if secs > MAX_TTL_SECS {
        return Err("duration must be at most 10 years".into());
    }
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn encoding() {
        assert_eq!(encode_component("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(encode_component("../x"), "..%2Fx");
        assert_eq!(encode_component(".."), "%2E%2E");
        assert_eq!(encode_component("%2f"), "%252f");
        assert_eq!(encode_component("é"), "%C3%A9");
    }

    #[test]
    fn ttl() {
        assert_eq!(parse_ttl("90"), Ok(90));
        assert_eq!(parse_ttl("30m"), Ok(1800));
        assert_eq!(parse_ttl("12h"), Ok(43_200));
        assert_eq!(parse_ttl("7d"), Ok(604_800));
        assert_eq!(parse_ttl("3650d"), Ok(315_360_000));
        for bad in [
            "",
            "h",
            "0",
            "0m",
            "-5",
            "1.5h",
            "3651d",
            "10y",
            "99999999999999999999d",
            "1 h",
        ] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn table_aligns_and_sanitizes() {
        let t = table(
            &["A", "BB"],
            &[
                vec!["xxx".into(), "1".into()],
                vec!["y\x1b".into(), "2".into()],
            ],
        );
        assert_eq!(t, "A    BB\nxxx  1\ny?   2\n");
    }
}
