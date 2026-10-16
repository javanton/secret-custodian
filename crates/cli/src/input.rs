//! Reading secret values: never from arguments, bounded, validated before anything is sent.

use anyhow::{bail, Context};
use std::io::Read;
use zeroize::Zeroizing;

pub const MAX_VALUE: usize = 8192;

/// Validates raw input and returns the value. `strip_newline` removes exactly one trailing
/// `\n` or `\r\n`. Error messages never contain the value.
fn finish(mut raw: Zeroizing<Vec<u8>>, strip_newline: bool) -> anyhow::Result<Zeroizing<String>> {
    if strip_newline {
        if raw.ends_with(b"\r\n") {
            let n = raw.len() - 2;
            raw.truncate(n);
        } else if raw.ends_with(b"\n") {
            let n = raw.len() - 1;
            raw.truncate(n);
        }
    }
    if raw.is_empty() {
        bail!("the secret value is empty");
    }
    if raw.len() > MAX_VALUE {
        bail!("the secret value is longer than {MAX_VALUE} bytes");
    }
    if raw.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        bail!("the secret value must not contain CR, LF or NUL characters");
    }
    std::str::from_utf8(&raw)
        .map_err(|_| anyhow::anyhow!("the secret value is not valid UTF-8"))?;
    let bytes = std::mem::take(&mut *raw);
    match String::from_utf8(bytes) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(_) => bail!("the secret value is not valid UTF-8"),
    }
}

fn prompt(label: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let s = Zeroizing::new(
        rpassword::prompt_password(label)
            .context("cannot read the secret value from the terminal")?,
    );
    Ok(Zeroizing::new(s.as_bytes().to_vec()))
}

/// Reads a secret value from `stdin` (non-TTY) or from a hidden prompt (TTY, twice when
/// `confirm` is set; both entries must match).
pub fn read_value(
    stdin: &mut dyn Read,
    tty: bool,
    confirm: bool,
) -> anyhow::Result<Zeroizing<String>> {
    if tty {
        let first = finish(prompt("Secret value: ")?, false)?;
        if confirm {
            let second = finish(prompt("Repeat secret value: ")?, false)?;
            if *first != *second {
                bail!("the two values do not match");
            }
        }
        return Ok(first);
    }
    // One byte beyond the maximum plus a possible "\r\n" is enough to detect an oversize value.
    let limit = (MAX_VALUE + 2 + 1) as u64;
    let mut buf = Zeroizing::new(Vec::with_capacity(limit as usize));
    stdin
        .take(limit)
        .read_to_end(&mut buf)
        .context("cannot read the secret value from stdin")?;
    finish(buf, true)
}

/// Builds `{"name":..,"value":..}` (or `{"value":..}`) without intermediate copies of the value.
pub fn secret_body(name: Option<&str>, value: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    // Worst case a byte becomes a six-byte `\u00XX` escape, so the buffer never reallocates.
    let mut out = Zeroizing::new(Vec::with_capacity(
        6 * value.len() + 6 * name.map_or(0, str::len) + 64,
    ));
    out.push(b'{');
    if let Some(n) = name {
        out.extend_from_slice(b"\"name\":");
        serde_json::to_writer(&mut *out, n)?;
        out.push(b',');
    }
    out.extend_from_slice(b"\"value\":");
    serde_json::to_writer(&mut *out, value)?;
    out.push(b'}');
    Ok(out)
}
