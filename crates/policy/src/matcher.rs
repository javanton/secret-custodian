use crate::model::{InjectionKind, Rule};
use crate::normalize::PathView;
use std::collections::HashMap;

pub enum Decision<'a> {
    NoRuleForHost,
    Forbidden,
    Inject(Vec<&'a Rule>),
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .and_then(|h| h.strip_suffix('.'))
            .map(|label| !label.is_empty() && !label.contains('.'))
            .unwrap_or(false),
        None => false,
    }
}

/// Path matching on ALL readings: every percent-decoding depth (0..=8) crossed with every parsing
/// variant (query cut, `;` strip, `\` as `/`). EVERY reading of the path must match the reading of
/// the pattern at the same position. `*` matches everything. An unjudgeable path (`view` is
/// `None`) or pattern matches no other pattern.
fn path_matches(pattern: &str, path: &PathView) -> bool {
    if pattern == "*" {
        return true;
    }
    let (body, prefix) = match pattern.strip_suffix('*') {
        Some(p) => (p, true),
        None => (pattern, false),
    };
    let Some(pat) = PathView::new(body) else {
        return false;
    };
    let depths = path.depths().max(pat.depths());
    let full = path.needs_variants() || pat.needs_variants();
    (0..depths).all(|d| {
        let want = pat.readings_at(d, full);
        let got = path.readings_at(d, full);
        got.iter().zip(&want).all(|(g, w)| {
            if prefix {
                g.starts_with(w.as_str())
            } else {
                g == w
            }
        })
    })
}

/// (exact host, wildcard suffix length, exact path, path pattern length): higher wins.
fn specificity(r: &Rule, host: &str) -> (bool, usize, bool, usize) {
    (
        r.host_pattern == host,
        if r.host_pattern.starts_with("*.") {
            r.host_pattern.len()
        } else {
            0
        },
        !r.path_pattern.ends_with('*'),
        r.path_pattern.len(),
    )
}

pub fn has_rules_for_host(rules: &[Rule], host: &str) -> bool {
    rules.iter().any(|r| host_matches(&r.host_pattern, host))
}

pub fn evaluate<'a>(rules: &'a [Rule], host: &str, method: &str, path: &str) -> Decision<'a> {
    if !has_rules_for_host(rules, host) {
        return Decision::NoRuleForHost;
    }
    let view = PathView::new(path);
    // Candidates match host and path (both views); methods are applied only AFTER the
    // specificity comparison so a narrower rule is never shadowed by a broader one.
    let mut groups: HashMap<(InjectionKind, String), Vec<&Rule>> = HashMap::new();
    for r in rules {
        if host_matches(&r.host_pattern, host)
            && (r.path_pattern == "*"
                || view
                    .as_ref()
                    .is_some_and(|v| path_matches(&r.path_pattern, v)))
        {
            groups
                .entry((r.kind, r.target_name.to_ascii_lowercase()))
                .or_default()
                .push(r);
        }
    }
    let mut chosen: Vec<&Rule> = Vec::new();
    for cands in groups.values() {
        let Some(top) = cands.iter().map(|r| specificity(r, host)).max() else {
            continue;
        };
        let winner = cands
            .iter()
            .filter(|r| specificity(r, host) == top)
            .filter(|r| {
                r.methods.is_empty() || r.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
            })
            .min_by_key(|r| r.id);
        if let Some(r) = winner {
            chosen.push(r);
        }
    }
    if chosen.is_empty() {
        return Decision::Forbidden;
    }
    chosen.sort_by_key(|r| r.id);
    Decision::Inject(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{InjectionKind::*, Rule};

    fn rule(
        id: i64,
        host: &str,
        path: &str,
        methods: &[&str],
        kind: crate::model::InjectionKind,
        target: &str,
    ) -> Rule {
        Rule {
            id,
            role: "r".into(),
            host_pattern: host.into(),
            path_pattern: path.into(),
            methods: methods.iter().map(|m| m.to_string()).collect(),
            kind,
            target_name: target.into(),
            template: "{secret}".into(),
            secret_id: 1,
        }
    }

    #[test]
    fn no_rule_for_host() {
        let rules = [rule(1, "api.github.com", "*", &[], Header, "Authorization")];
        assert!(matches!(
            evaluate(&rules, "example.com", "GET", "/"),
            Decision::NoRuleForHost
        ));
    }

    #[test]
    fn method_and_path_restrict() {
        let rules = [rule(
            1,
            "api.github.com",
            "/repos/*",
            &["GET"],
            Header,
            "Authorization",
        )];
        assert!(matches!(
            evaluate(&rules, "api.github.com", "GET", "/repos/x"),
            Decision::Inject(_)
        ));
        assert!(matches!(
            evaluate(&rules, "api.github.com", "POST", "/repos/x"),
            Decision::Forbidden
        ));
        assert!(matches!(
            evaluate(&rules, "api.github.com", "GET", "/admin"),
            Decision::Forbidden
        ));
    }

    #[test]
    fn wildcard_host_matches_exactly_one_label() {
        let rules = [rule(1, "*.example.com", "*", &[], Header, "X-Key")];
        assert!(matches!(
            evaluate(&rules, "api.example.com", "GET", "/"),
            Decision::Inject(_)
        ));
        assert!(matches!(
            evaluate(&rules, "a.b.example.com", "GET", "/"),
            Decision::NoRuleForHost
        ));
        assert!(matches!(
            evaluate(&rules, "example.com", "GET", "/"),
            Decision::NoRuleForHost
        ));
    }

    #[test]
    fn header_and_query_rules_both_apply() {
        let rules = [
            rule(1, "api.x.com", "*", &[], Header, "Authorization"),
            rule(2, "api.x.com", "*", &[], Query, "api_key"),
        ];
        match evaluate(&rules, "api.x.com", "GET", "/") {
            Decision::Inject(v) => assert_eq!(v.len(), 2),
            _ => panic!("expected injection"),
        }
    }

    #[test]
    fn more_specific_rule_wins_for_same_target() {
        let rules = [
            rule(1, "*.x.com", "*", &[], Header, "Authorization"),
            rule(2, "api.x.com", "*", &[], Header, "authorization"),
        ];
        match evaluate(&rules, "api.x.com", "GET", "/") {
            Decision::Inject(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].id, 2);
            }
            _ => panic!("expected injection"),
        }
    }

    #[test]
    fn traversal_cannot_escape_a_path_restricted_rule() {
        let rules = [rule(
            1,
            "api.github.com",
            "/repos/*",
            &["GET"],
            Header,
            "Authorization",
        )];
        let p = crate::normalize::normalize_path("/repos/../admin");
        assert!(matches!(
            evaluate(&rules, "api.github.com", "GET", &p),
            Decision::Forbidden
        ));
    }

    // --- extra tests (gaps not covered by the plan) ---

    fn ids(d: Decision<'_>) -> Vec<i64> {
        match d {
            Decision::Inject(v) => v.iter().map(|r| r.id).collect(),
            Decision::Forbidden => vec![-1],
            Decision::NoRuleForHost => vec![-2],
        }
    }

    #[test]
    fn empty_methods_means_any_method() {
        let rules = [rule(1, "a.com", "*", &[], Header, "X")];
        for m in ["GET", "POST", "DELETE", "PATCH", "FOO"] {
            assert_eq!(
                ids(evaluate(&rules, "a.com", m, "/")),
                vec![1],
                "method {m}"
            );
        }
    }

    #[test]
    fn method_match_is_case_insensitive() {
        let rules = [rule(1, "a.com", "*", &["GET"], Header, "X")];
        assert_eq!(ids(evaluate(&rules, "a.com", "get", "/")), vec![1]);
    }

    #[test]
    fn wildcard_does_not_match_apex_or_lookalike_suffix() {
        let rules = [rule(1, "*.example.com", "*", &[], Header, "X")];
        assert_eq!(ids(evaluate(&rules, "example.com", "GET", "/")), vec![-2]);
        assert_eq!(
            ids(evaluate(&rules, "evilexample.com", "GET", "/")),
            vec![-2]
        );
        assert_eq!(ids(evaluate(&rules, ".example.com", "GET", "/")), vec![-2]);
        assert_eq!(
            ids(evaluate(&rules, "api.example.com.evil.com", "GET", "/")),
            vec![-2]
        );
    }

    #[test]
    fn exact_and_wildcard_rules_for_different_targets_both_apply() {
        let rules = [
            rule(1, "*.x.com", "*", &[], Header, "X-A"),
            rule(2, "api.x.com", "*", &[], Header, "X-B"),
        ];
        assert_eq!(ids(evaluate(&rules, "api.x.com", "GET", "/")), vec![1, 2]);
    }

    #[test]
    fn exact_host_beats_wildcard_even_with_shorter_path() {
        let rules = [
            rule(1, "*.x.com", "/very/long/path/*", &[], Header, "A"),
            rule(2, "api.x.com", "*", &[], Header, "A"),
        ];
        assert_eq!(
            ids(evaluate(&rules, "api.x.com", "GET", "/very/long/path/z")),
            vec![2]
        );
    }

    #[test]
    fn longer_path_pattern_wins_for_same_host_and_target() {
        let rules = [
            rule(1, "a.com", "*", &[], Header, "A"),
            rule(2, "a.com", "/v1/*", &[], Header, "A"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/v1/x")), vec![2]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/v2/x")), vec![1]);
        // Same result regardless of rule order.
        let rev = [rules[1].clone(), rules[0].clone()];
        assert_eq!(ids(evaluate(&rev, "a.com", "GET", "/v1/x")), vec![2]);
    }

    #[test]
    fn identical_specificity_keeps_first_rule() {
        let rules = [
            rule(1, "a.com", "*", &[], Header, "A"),
            rule(2, "a.com", "*", &[], Header, "A"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/")), vec![1]);
    }

    #[test]
    fn same_target_name_in_header_and_query_does_not_collide() {
        let rules = [
            rule(1, "a.com", "*", &[], Header, "token"),
            rule(2, "a.com", "*", &[], Query, "token"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/")), vec![1, 2]);
    }

    #[test]
    fn query_target_names_are_case_insensitively_deduplicated() {
        let rules = [
            rule(1, "a.com", "*", &[], Query, "api_key"),
            rule(2, "a.com", "/x/*", &[], Query, "API_KEY"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/x/y")), vec![2]);
    }

    #[test]
    fn path_prefix_glob_requires_the_slash_boundary() {
        let rules = [rule(1, "a.com", "/repos/*", &[], Header, "A")];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/repos")), vec![-1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/reposx")), vec![-1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/repos/")), vec![1]);
    }

    #[test]
    fn path_without_glob_is_exact() {
        let rules = [rule(1, "a.com", "/v1/me", &[], Header, "A")];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/v1/me")), vec![1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/v1/me/x")), vec![-1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/v1/me/")), vec![-1]);
    }

    /// Evaluates a RAW request path the way the proxy does: normalize, then evaluate.
    fn evaluate_raw<'a>(rules: &'a [Rule], host: &str, method: &str, raw: &str) -> Decision<'a> {
        let p = crate::normalize::normalize_path(raw);
        evaluate(rules, host, method, &p)
    }

    #[test]
    fn encoded_separators_and_path_params_cannot_escape_a_prefix_rule() {
        let rules = [rule(
            1,
            "api.github.com",
            "/repos/*",
            &["GET"],
            Header,
            "Authorization",
        )];
        for raw in [
            "/repos/%2e%2e/admin",
            "/repos/%2E%2E/admin",
            "/repos//../admin",
            "/repos/./../admin",
            "/repos/..%2fadmin",
            "/repos/..%2Fadmin",
            "/repos/%2e%2e%2fadmin",
            "/repos/..%5cadmin",
            "/repos/..\\admin",
            "/repos/..;/admin",
            "/repos/%2e%2e;x/admin",
            "/repos/%252e%252e%252fadmin",
            "/repos/..%252fadmin",
            "/repos/%00",
            "/repos/%2e%2e%2f..",
            "/repos/%u002e%u002e/admin",
        ] {
            assert_eq!(
                ids(evaluate_raw(&rules, "api.github.com", "GET", raw)),
                vec![-1],
                "{raw}"
            );
        }
    }

    #[test]
    fn legitimate_encoded_slashes_inside_the_prefix_still_inject() {
        let gl = [rule(1, "a.com", "/api/v4/*", &[], Header, "A")];
        assert_eq!(
            ids(evaluate_raw(
                &gl,
                "a.com",
                "GET",
                "/api/v4/projects/a%2Fb/issues"
            )),
            vec![1]
        );
        let gh = [rule(1, "a.com", "/repos/*", &[], Header, "A")];
        assert_eq!(
            ids(evaluate_raw(&gh, "a.com", "GET", "/repos/a%2Fb")),
            vec![1]
        );
        assert_eq!(ids(evaluate_raw(&gh, "a.com", "GET", "/repos/ok")), vec![1]);
    }

    #[test]
    fn exact_rule_requires_both_views_to_match() {
        let rules = [rule(1, "a.com", "/v1/me", &[], Header, "A")];
        assert_eq!(ids(evaluate_raw(&rules, "a.com", "GET", "/v1/me")), vec![1]);
        assert_eq!(
            ids(evaluate_raw(&rules, "a.com", "GET", "/v1%2fme")),
            vec![-1]
        );
        assert_eq!(
            ids(evaluate_raw(&rules, "a.com", "GET", "/v1/me;x")),
            vec![-1]
        );
    }

    #[test]
    fn star_pattern_still_matches_unjudgeable_paths() {
        let rules = [rule(1, "a.com", "*", &[], Header, "A")];
        assert_eq!(ids(evaluate_raw(&rules, "a.com", "GET", "/x/%00")), vec![1]);
    }

    #[test]
    fn narrower_rule_is_not_shadowed_by_broader_rule_for_excluded_method() {
        let rules = [
            rule(1, "a.com", "/repos/*", &["GET"], Header, "A"),
            rule(2, "a.com", "*", &[], Header, "A"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "POST", "/repos/x")), vec![-1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/repos/x")), vec![1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "POST", "/other")), vec![2]);
    }

    #[test]
    fn same_specificity_rules_with_different_methods_coexist() {
        let rules = [
            rule(1, "a.com", "/x/*", &["GET"], Header, "A"),
            rule(2, "a.com", "/x/*", &["POST"], Header, "A"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/x/y")), vec![1]);
        assert_eq!(ids(evaluate(&rules, "a.com", "POST", "/x/y")), vec![2]);
        assert_eq!(ids(evaluate(&rules, "a.com", "PUT", "/x/y")), vec![-1]);
    }

    #[test]
    fn exact_path_beats_prefix_of_equal_length() {
        let rules = [
            rule(1, "a.com", "/a*", &[], Header, "A"),
            rule(2, "a.com", "/ab", &[], Header, "A"),
        ];
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/ab")), vec![2]);
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", "/ac")), vec![1]);
    }

    #[test]
    fn forbidden_when_host_matches_but_nothing_else_does() {
        let rules = [rule(1, "a.com", "/x", &["GET"], Header, "A")];
        assert_eq!(ids(evaluate(&rules, "a.com", "POST", "/x")), vec![-1]);
    }

    #[test]
    fn every_decoding_depth_and_parsing_variant_is_judged() {
        let rules = [rule(
            1,
            "api.github.com",
            "/repos/*",
            &["GET"],
            Header,
            "Authorization",
        )];
        for raw in [
            "/repos/x%252F..%252F..%252Frepos%252Fz%252Fw%2F..%2F..%2Fadmin",
            "/repos/..;%2Frepos%2Fx/..;/admin",
            "/repos/..%2F..%2Fadmin%3F%2F..%2F..%2Frepos%2Fy",
            "/repos/%u002e%u002e/admin",
            "/repos/..%2f",
            "/repos/%2e%2e%2f",
            "/repos/%252e%252e%252f",
        ] {
            assert_eq!(
                ids(evaluate_raw(&rules, "api.github.com", "GET", raw)),
                vec![-1],
                "{raw}"
            );
        }
        // Legitimate shapes keep working.
        for raw in [
            "/repos/ok",
            "/repos/a%2Fb",
            "/repos/a%20b",
            "/repos/100%25",
            "/repos/caf%C3%A9",
            "/repos/a;b",
            "/repos/a%2Fb/issues",
        ] {
            assert_eq!(
                ids(evaluate_raw(&rules, "api.github.com", "GET", raw)),
                vec![1],
                "{raw}"
            );
        }
        let gl = [rule(1, "a.com", "/api/v4/*", &[], Header, "A")];
        assert_eq!(
            ids(evaluate_raw(
                &gl,
                "a.com",
                "GET",
                "/api/v4/projects/a%2Fb/issues"
            )),
            vec![1]
        );
    }

    /// Independent oracle (deliberately shares no code with the matcher): one lenient decoding round.
    fn oracle_decode(s: &str) -> Option<String> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let h = s
                    .get(i + 1..i + 3)
                    .and_then(|x| u8::from_str_radix(x, 16).ok());
                if let Some(v) = h {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8(out).ok()
    }

    fn oracle_strip(s: &str) -> String {
        s.split('/')
            .map(|seg| seg.split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("/")
    }

    fn oracle_resolve(s: &str) -> String {
        let mut st: Vec<&str> = Vec::new();
        for seg in s.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    st.pop();
                }
                x => st.push(x),
            }
        }
        let last = s.rsplit('/').next().unwrap_or("");
        let dir = matches!(last, "" | "." | "..");
        let body = st.join("/");
        if dir && !body.is_empty() {
            format!("/{body}/")
        } else {
            format!("/{body}")
        }
    }

    /// Every way an origin might read `p`; returns the resolved paths.
    fn oracle_views(p: &str) -> Vec<String> {
        let mut out = Vec::new();
        for depth in 0..=3 {
            for strip_mode in 0..3 {
                for cut in [false, true] {
                    for slash in [false, true] {
                        let mut s = p.to_string();
                        if strip_mode == 1 {
                            s = oracle_strip(&s);
                        }
                        let mut ok = true;
                        for _ in 0..depth {
                            match oracle_decode(&s) {
                                Some(d) => s = d,
                                None => ok = false,
                            }
                        }
                        if !ok {
                            continue;
                        }
                        if strip_mode == 2 {
                            s = oracle_strip(&s);
                        }
                        if cut {
                            if let Some(i) = s.find(['?', '#']) {
                                s.truncate(i);
                            }
                        }
                        if slash {
                            s = s.replace('\\', "/");
                        }
                        out.push(oracle_resolve(&s));
                    }
                }
            }
        }
        out
    }

    #[test]
    fn oracle_sanity() {
        assert!(oracle_views("/repos/..%2Fadmin")
            .iter()
            .any(|v| v == "/admin"));
        assert!(oracle_views("/repos/x").iter().all(|v| v == "/repos/x"));
    }

    fn walk(
        rules: &[Rule],
        toks: &[&str],
        depth: usize,
        cur: &mut String,
        count: &mut (u64, u64),
    ) -> Option<String> {
        if !cur.is_empty() {
            count.0 += 1;
            if matches!(
                evaluate(rules, "api.github.com", "GET", cur),
                Decision::Inject(_)
            ) {
                count.1 += 1;
                for v in oracle_views(cur) {
                    if !v.starts_with("/repos/") {
                        return Some(format!("{cur:?} injects but an origin reads {v:?}"));
                    }
                }
            }
        }
        if depth == 0 {
            return None;
        }
        for t in toks {
            let len = cur.len();
            cur.push_str(t);
            let r = walk(rules, toks, depth - 1, cur, count);
            cur.truncate(len);
            if r.is_some() {
                return r;
            }
        }
        None
    }

    #[test]
    fn exhaustive_prefix_rule_never_authorizes_an_escaping_path() {
        let rules = [rule(
            1,
            "api.github.com",
            "/repos/*",
            &["GET"],
            Header,
            "Authorization",
        )];
        let toks = [
            "/repos/", "x", "..", ".", "%2F", "%252F", ";", "\\", "%3F", "/",
        ];
        let mut count = (0, 0);
        // Length 6 (about 1.1M paths) in release; length 5 (about 111k) in debug, where it is ~10x slower.
        let max_len = if cfg!(debug_assertions) { 5 } else { 6 };
        let r = walk(&rules, &toks, max_len, &mut String::new(), &mut count);
        assert!(r.is_none(), "{}", r.unwrap());
        assert!(count.0 > 100_000, "enumerated only {}", count.0);
        assert!(
            count.1 > 100,
            "only {} paths injected: test is vacuous",
            count.1
        );
    }

    #[test]
    fn more_specific_wildcard_host_wins_regardless_of_order() {
        let a = rule(1, "*.corp.com", "*", &[], Header, "Authorization");
        let b = rule(2, "*.prod.corp.com", "*", &["GET"], Header, "Authorization");
        for rules in [[a.clone(), b.clone()], [b.clone(), a.clone()]] {
            assert_eq!(
                ids(evaluate(&rules, "api.prod.corp.com", "POST", "/")),
                vec![-1]
            );
            assert_eq!(
                ids(evaluate(&rules, "api.prod.corp.com", "GET", "/")),
                vec![2]
            );
            assert_eq!(ids(evaluate(&rules, "api.corp.com", "POST", "/")), vec![1]);
        }
    }

    #[test]
    fn has_rules_for_host_matches_exact_and_wildcard() {
        let rules = [
            rule(1, "a.com", "*", &[], Header, "A"),
            rule(2, "*.b.com", "*", &[], Header, "A"),
        ];
        assert!(has_rules_for_host(&rules, "a.com"));
        assert!(has_rules_for_host(&rules, "x.b.com"));
        assert!(!has_rules_for_host(&rules, "b.com"));
        assert!(!has_rules_for_host(&rules, "x.a.com"));
        assert!(!has_rules_for_host(&[], "a.com"));
    }

    #[test]
    fn has_rules_for_host_ignores_method_and_path() {
        let rules = [rule(1, "a.com", "/only/*", &["GET"], Header, "A")];
        assert!(has_rules_for_host(&rules, "a.com"));
    }
}
