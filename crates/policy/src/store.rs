use crate::model::*;
use crate::normalize::{is_ip_literal, normalize_path, pattern_is_self_widening};
use rusqlite::{params, Connection, OptionalExtension};
use sg_core::Vault;

const FORBIDDEN_TARGET_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];

/// `*` only as the single last character, no `?`/`#`, and already in normalized form
/// (uppercase hex in every escape, so what is authorized is exactly what is forwarded).
fn valid_path_pattern(p: &str) -> bool {
    if p == "*" {
        return true;
    }
    let body = p.strip_suffix('*').unwrap_or(p);
    let b = body.as_bytes();
    let escapes_ok = b.iter().enumerate().all(|(i, &c)| {
        c != b'%'
            || (b.len() > i + 2
                && b[i + 1..i + 3]
                    .iter()
                    .all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(h)))
    });
    body.starts_with('/')
        && !body.contains(['*', '?', '#'])
        && escapes_ok
        && normalize_path(body) == body
        && !pattern_is_self_widening(body)
}

fn valid_host_pattern(p: &str) -> bool {
    let wildcard = p.starts_with("*.");
    let body = p.strip_prefix("*.").unwrap_or(p);
    // `*.com` is too broad; bare labels are only allowed for `localhost`.
    let labels_ok = if body.contains('.') {
        true
    } else {
        !wildcard && body == "localhost"
    };
    labels_ok
        && !body.is_empty()
        && !is_ip_literal(body)
        && body.contains(|c: char| c.is_ascii_alphabetic())
        && !body.contains('*')
        && body.split('.').all(|l| {
            !l.is_empty()
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && p == p.to_ascii_lowercase()
}

fn validate(conn: &Connection, r: &NewRule) -> Result<(), PolicyError> {
    if !valid_host_pattern(&r.host_pattern) {
        return Err(PolicyError::Invalid(
            "host_pattern must be a lowercase hostname or *.hostname (no IPs)",
        ));
    }
    if !valid_path_pattern(&r.path_pattern) {
        return Err(PolicyError::Invalid(
            "path_pattern must be * or a normalized path starting with / (optional trailing *)",
        ));
    }
    if r.methods
        .iter()
        .any(|m| m.is_empty() || !m.bytes().all(|b| b.is_ascii_alphabetic()))
    {
        return Err(PolicyError::Invalid(
            "methods must be alphabetic HTTP methods",
        ));
    }
    let name_ok = match r.kind {
        InjectionKind::Header => {
            http::HeaderName::from_bytes(r.target_name.as_bytes()).is_ok()
                && !FORBIDDEN_TARGET_HEADERS
                    .iter()
                    .any(|h| r.target_name.eq_ignore_ascii_case(h))
                && !r.target_name.to_ascii_lowercase().starts_with("proxy-")
        }
        InjectionKind::Query => {
            !r.target_name.is_empty()
                && r.target_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        }
    };
    if !name_ok {
        return Err(PolicyError::Invalid("invalid target_name"));
    }
    if !r.template.contains("{secret}")
        || r.template
            .bytes()
            .any(|b| b == b'\r' || b == b'\n' || b == 0)
    {
        return Err(PolicyError::Invalid(
            "template must contain {secret} and no CR/LF/NUL",
        ));
    }
    if r.kind == InjectionKind::Query && r.template != "{secret}" {
        return Err(PolicyError::Invalid(
            "query template must be exactly {secret}",
        ));
    }
    if get_role_in(conn, &r.role)?.is_none() {
        return Err(PolicyError::Invalid("unknown role"));
    }
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM secrets WHERE id = ?1",
        [r.secret_id],
        |x| x.get(0),
    )?;
    if exists == 0 {
        return Err(PolicyError::Invalid("unknown secret"));
    }
    Ok(())
}

pub fn add_role(v: &Vault, name: &str, unmatched: Unmatched) -> Result<Role, PolicyError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !ok {
        return Err(PolicyError::Invalid("role name must be [a-z0-9_-]"));
    }
    if get_role(v, name)?.is_some() {
        return Err(PolicyError::AlreadyExists);
    }
    v.conn().execute(
        "INSERT INTO roles (name, unmatched_policy) VALUES (?1, ?2)",
        params![name, unmatched.as_str()],
    )?;
    Ok(Role {
        name: name.into(),
        unmatched,
    })
}

// The `*_in` functions below run inside `Vault::in_transaction` with the connection already locked;
// they must not call Vault methods or wrappers that lock the connection (non-reentrant mutex).

pub fn get_role(v: &Vault, name: &str) -> Result<Option<Role>, PolicyError> {
    get_role_in(&v.conn(), name)
}

pub fn get_role_in(conn: &Connection, name: &str) -> Result<Option<Role>, PolicyError> {
    let row: Option<String> = conn
        .query_row(
            "SELECT unmatched_policy FROM roles WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .optional()?;
    Ok(row.map(|p| Role {
        name: name.into(),
        unmatched: p.parse().unwrap_or(Unmatched::Deny),
    }))
}

pub fn list_roles(v: &Vault) -> Result<Vec<Role>, PolicyError> {
    let conn = v.conn();
    let mut st = conn.prepare("SELECT name, unmatched_policy FROM roles ORDER BY name")?;
    let rows = st
        .query_map([], |r| {
            let p: String = r.get(1)?;
            Ok(Role {
                name: r.get(0)?,
                unmatched: p.parse().unwrap_or(Unmatched::Deny),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn remove_role(v: &Vault, name: &str) -> Result<(), PolicyError> {
    remove_role_in(&v.conn(), name)
}

pub fn remove_role_in(conn: &Connection, name: &str) -> Result<(), PolicyError> {
    let n = conn.execute("DELETE FROM roles WHERE name = ?1", [name])?;
    if n == 0 {
        Err(PolicyError::NotFound)
    } else {
        Ok(())
    }
}

pub fn add_rule(v: &Vault, r: NewRule) -> Result<Rule, PolicyError> {
    insert_rule_in(&v.conn(), r)
}

pub fn insert_rule_in(conn: &Connection, r: NewRule) -> Result<Rule, PolicyError> {
    validate(conn, &r)?;
    let methods: Vec<String> = r.methods.iter().map(|m| m.to_ascii_uppercase()).collect();
    conn.execute(
        "INSERT INTO rules (role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![r.role, r.host_pattern, r.path_pattern, methods.join(","), r.kind.as_str(), r.target_name, r.template, r.secret_id],
    )?;
    Ok(Rule {
        id: conn.last_insert_rowid(),
        role: r.role,
        host_pattern: r.host_pattern,
        path_pattern: r.path_pattern,
        methods,
        kind: r.kind,
        target_name: r.target_name,
        template: r.template,
        secret_id: r.secret_id,
    })
}

pub fn list_rules(v: &Vault, role: Option<&str>) -> Result<Vec<Rule>, PolicyError> {
    list_rules_in(&v.conn(), role)
}

pub fn list_rules_in(conn: &Connection, role: Option<&str>) -> Result<Vec<Rule>, PolicyError> {
    let mut st = conn.prepare(
        "SELECT id, role, host_pattern, path_pattern, methods, injection_kind, target_name, template, secret_id
         FROM rules WHERE (?1 IS NULL OR role = ?1) ORDER BY id",
    )?;
    let rows = st
        .query_map([role], |r| {
            let methods: String = r.get(4)?;
            let kind: String = r.get(5)?;
            Ok(Rule {
                id: r.get(0)?,
                role: r.get(1)?,
                host_pattern: r.get(2)?,
                path_pattern: r.get(3)?,
                methods: methods
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(String::from)
                    .collect(),
                kind: if kind == "query" {
                    InjectionKind::Query
                } else {
                    InjectionKind::Header
                },
                target_name: r.get(6)?,
                template: r.get(7)?,
                secret_id: r.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn remove_rule(v: &Vault, id: i64) -> Result<(), PolicyError> {
    remove_rule_in(&v.conn(), id)
}

pub fn remove_rule_in(conn: &Connection, id: i64) -> Result<(), PolicyError> {
    let n = conn.execute("DELETE FROM rules WHERE id = ?1", [id])?;
    if n == 0 {
        Err(PolicyError::NotFound)
    } else {
        Ok(())
    }
}

pub fn rule_count_for_secret_in(conn: &Connection, secret_id: i64) -> Result<i64, PolicyError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM rules WHERE secret_id = ?1",
        [secret_id],
        |r| r.get(0),
    )?)
}

pub fn secret_of_rule_in(conn: &Connection, rule_id: i64) -> Result<i64, PolicyError> {
    conn.query_row(
        "SELECT secret_id FROM rules WHERE id = ?1",
        [rule_id],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(PolicyError::NotFound)
}

/// Names of the secrets whose every rule belongs to `role`: deleting the role would orphan them.
pub fn secrets_orphaned_by_role_in(
    conn: &Connection,
    role: &str,
) -> Result<Vec<String>, PolicyError> {
    let mut st = conn.prepare(
        "SELECT s.name FROM secrets s
         WHERE EXISTS (SELECT 1 FROM rules r WHERE r.secret_id = s.id AND r.role = ?1)
           AND NOT EXISTS (SELECT 1 FROM rules r WHERE r.secret_id = s.id AND r.role <> ?1)
         ORDER BY s.name",
    )?;
    let rows = st
        .query_map([role], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(rows)
}
