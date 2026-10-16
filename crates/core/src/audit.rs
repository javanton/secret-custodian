use crate::{error::CoreError, now, vault::Vault};
use rusqlite::params;
use serde::{Deserialize, Serialize};

const MAX_PATH: usize = 2048;
const MAX_HOST: usize = 253;
const MAX_METHOD: usize = 16;
const MAX_DECISION: usize = 64;
const MAX_IDENT: usize = 256;
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub ts: i64,
    pub jti: Option<String>,
    pub machine: Option<String>,
    pub role: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub rule_id: Option<i64>,
    pub decision: String,
    pub status: Option<u16>,
}

/// Drops everything from the first `?` or `#`; an empty result becomes `/`.
fn strip_query(raw: &str) -> String {
    let p = raw.split(['?', '#']).next().unwrap_or("");
    if p.is_empty() {
        "/".to_string()
    } else {
        p.to_string()
    }
}

/// Truncates to at most `max` bytes, never splitting a UTF-8 character.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn bound_opt(s: &Option<String>) -> Option<String> {
    s.as_deref().map(|v| truncate(v, MAX_IDENT))
}

impl AuditEntry {
    pub fn new(host: &str, method: &str, raw_path_and_query: &str, decision: &str) -> Self {
        Self {
            ts: now(),
            jti: None,
            machine: None,
            role: None,
            host: host.into(),
            method: method.into(),
            path: strip_query(raw_path_and_query),
            rule_id: None,
            decision: decision.into(),
            status: None,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditFilter {
    pub role: Option<String>,
    pub host: Option<String>,
    pub since: Option<i64>,
    /// 0 means 100; values above 1000 are clamped to 1000.
    #[serde(default)]
    pub limit: usize,
}

impl Vault {
    /// Stores one audit row. Fields come from untrusted input, so they are bounded
    /// here and the path is stripped of any query/fragment again (defence in depth).
    pub fn record_audit(&self, e: &AuditEntry) -> Result<(), CoreError> {
        let path = truncate(&strip_query(&e.path), MAX_PATH);
        let host = truncate(&e.host, MAX_HOST);
        let method = truncate(&e.method, MAX_METHOD);
        let decision = truncate(&e.decision, MAX_DECISION);
        let (jti, machine, role) = (bound_opt(&e.jti), bound_opt(&e.machine), bound_opt(&e.role));
        self.conn().execute(
            "INSERT INTO audit (ts, jti, machine, role, host, method, path, rule_id, decision, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![e.ts, jti, machine, role, host, method, path, e.rule_id, decision, e.status],
        )?;
        Ok(())
    }

    pub fn list_audit(&self, f: &AuditFilter) -> Result<Vec<AuditEntry>, CoreError> {
        let limit = if f.limit == 0 {
            DEFAULT_LIMIT
        } else {
            f.limit.min(MAX_LIMIT)
        } as i64;
        let conn = self.conn();
        let mut st = conn.prepare(
            "SELECT ts, jti, machine, role, host, method, path, rule_id, decision, status FROM audit
             WHERE (?1 IS NULL OR role = ?1) AND (?2 IS NULL OR host = ?2) AND (?3 IS NULL OR ts >= ?3)
             ORDER BY id DESC LIMIT ?4",
        )?;
        let rows = st
            .query_map(params![f.role, f.host, f.since, limit], |r| {
                Ok(AuditEntry {
                    ts: r.get(0)?,
                    jti: r.get(1)?,
                    machine: r.get(2)?,
                    role: r.get(3)?,
                    host: r.get(4)?,
                    method: r.get(5)?,
                    path: r.get(6)?,
                    rule_id: r.get(7)?,
                    decision: r.get(8)?,
                    status: r.get::<_, Option<i64>>(9)?.map(|s| s as u16),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}
