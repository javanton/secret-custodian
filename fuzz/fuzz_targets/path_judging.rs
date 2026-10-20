#![no_main]
use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use sg_core::Vault;
use sg_policy::{
    add_role, evaluate, insert_rule_in, normalize_path, remove_rule_in, Decision, InjectionKind,
    NewRule, Rule, Unmatched,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

const HOST: &str = "api.example.com";

struct Fixture {
    vault: Arc<Vault>,
    secret_id: i64,
    /// pattern -> accepted by the policy's own validation (inserting is slow, so memoised).
    verdicts: Mutex<HashMap<String, bool>>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let vault = sg_fuzz::temp_vault();
        // Fuzz-only: durability is irrelevant for a throwaway vault and fsync dominates the cost.
        vault
            .conn()
            .execute_batch("PRAGMA synchronous=OFF; PRAGMA journal_mode=MEMORY;")
            .expect("pragma");
        add_role(&vault, "r", Unmatched::Deny).expect("role");
        let secret_id = vault.add_secret("s", "value").expect("secret").id;
        Fixture { vault, secret_id, verdicts: Mutex::new(HashMap::new()) }
    })
}

/// Lenient percent-decoding of every valid `%HH`, one round. None on invalid UTF-8 / NUL.
fn decode_once(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c))) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    let t = String::from_utf8(out).ok()?;
    (!t.contains('\0')).then_some(t)
}

/// `[s, decode(s), ...]` until stable (at most 10 rounds). None if a round fails or never settles.
fn readings(s: &str) -> Option<Vec<String>> {
    let mut v = vec![s.to_string()];
    for _ in 0..10 {
        let next = decode_once(v.last().unwrap())?;
        if &next == v.last().unwrap() {
            return Some(v);
        }
        v.push(next);
    }
    None
}

/// Dot-segment resolution only (no decoding, empty segments kept): what an origin does to a
/// reading that still holds `.` / `..`.
fn resolve_dots(r: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in r.split('/') {
        match seg {
            "." => {}
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
            }
            _ => out.push(seg),
        }
    }
    out.join("/")
}

fn dot_like(seg: &str) -> bool {
    seg.contains('.') && seg.chars().all(|c| matches!(c, '.' | ' ' | '\t' | '+'))
}

// A prefix rule must never let through a request that, at ANY decoding depth, leaves the prefix
// once dot segments are resolved, or that still contains something an origin could resolve.
fn check_allowed(rule: &Rule, evaluated: &str) {
    let (body, prefix) = match rule.path_pattern.strip_suffix('*') {
        Some(b) => (b, true),
        None => (rule.path_pattern.as_str(), false),
    };
    let Some(req) = readings(evaluated) else { return };
    let pat = readings(body).unwrap_or_else(|| vec![body.to_string()]);
    for (d, r) in req.iter().enumerate() {
        assert!(
            r.chars().all(|c| c.is_ascii() && !c.is_ascii_control()),
            "allowed {evaluated:?} by {:?}: reading {d} {r:?} has non-ASCII/control",
            rule.path_pattern
        );
        assert!(
            !r.split(['/', '\\', ';', '?', '#']).any(dot_like),
            "allowed {evaluated:?} by {:?}: reading {d} {r:?} holds a dot segment",
            rule.path_pattern
        );
        let want = &pat[d.min(pat.len() - 1)];
        let norm = resolve_dots(r);
        let ok = if prefix { norm.starts_with(want.as_str()) } else { &norm == want };
        assert!(
            ok,
            "allowed {evaluated:?} by {:?}: reading {d} resolves to {norm:?}, outside {want:?}",
            rule.path_pattern
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let f = fixture();
    let mut verdicts = f.verdicts.lock().unwrap_or_else(|e| e.into_inner());
    if verdicts.len() > 20_000 {
        verdicts.clear();
    }
    let n = u.int_in_range(1..=3).unwrap_or(1);
    let mut rules: Vec<Rule> = Vec::new();
    for i in 0..n {
        let star: bool = u.arbitrary().unwrap_or(false);
        let raw = u.arbitrary::<String>().unwrap_or_default();
        let raw: String = raw.chars().take(48).collect();
        // Mostly rooted patterns so the validator accepts some; keep a few raw ones.
        let mut pat = if raw.starts_with('/') { raw } else { format!("/{raw}") };
        if star {
            pat.push('*');
        }
        let verdict = match verdicts.get(&pat) {
            Some(v) => *v,
            None => {
                let new = NewRule {
                    role: "r".into(),
                    host_pattern: HOST.into(),
                    path_pattern: pat.clone(),
                    methods: vec![],
                    kind: InjectionKind::Header,
                    target_name: "x-fuzz-probe".into(),
                    template: "{secret}".into(),
                    secret_id: f.secret_id,
                };
                // Only patterns the policy's own validation accepts.
                let conn = f.vault.conn();
                let ok = match insert_rule_in(&conn, new) {
                    Ok(r) => {
                        let _ = remove_rule_in(&conn, r.id);
                        true
                    }
                    Err(_) => false,
                };
                verdicts.insert(pat.clone(), ok);
                ok
            }
        };
        if verdict {
            rules.push(Rule {
                id: i as i64 + 1,
                role: "r".into(),
                host_pattern: HOST.into(),
                path_pattern: pat,
                methods: vec![],
                kind: InjectionKind::Header,
                target_name: format!("x-fuzz-{i}"),
                template: "{secret}".into(),
                secret_id: f.secret_id,
            });
        }
    }
    let raw_path: String = u.arbitrary::<String>().unwrap_or_default().chars().take(200).collect();
    for path in [normalize_path(&raw_path), raw_path] {
        if let Decision::Inject(chosen) = evaluate(&rules, HOST, "GET", &path) {
            for r in chosen {
                if r.path_pattern != "*" {
                    check_allowed(r, &path);
                }
            }
        }
    }
});
