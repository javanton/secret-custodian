use crate::model::{InjectionKind, Rule};
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

fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => pattern == path,
    }
}

fn specificity(r: &Rule, host: &str) -> (u8, usize) {
    (u8::from(r.host_pattern == host), r.path_pattern.len())
}

pub fn has_rules_for_host(rules: &[Rule], host: &str) -> bool {
    rules.iter().any(|r| host_matches(&r.host_pattern, host))
}

pub fn evaluate<'a>(rules: &'a [Rule], host: &str, method: &str, path: &str) -> Decision<'a> {
    let for_host: Vec<&Rule> = rules
        .iter()
        .filter(|r| host_matches(&r.host_pattern, host))
        .collect();
    if for_host.is_empty() {
        return Decision::NoRuleForHost;
    }
    let mut best: HashMap<(InjectionKind, String), &Rule> = HashMap::new();
    for r in for_host {
        let method_ok =
            r.methods.is_empty() || r.methods.iter().any(|m| m.eq_ignore_ascii_case(method));
        if !method_ok || !path_matches(&r.path_pattern, path) {
            continue;
        }
        let key = (r.kind, r.target_name.to_ascii_lowercase());
        match best.get(&key) {
            Some(cur) if specificity(cur, host) >= specificity(r, host) => {}
            _ => {
                best.insert(key, r);
            }
        }
    }
    if best.is_empty() {
        return Decision::Forbidden;
    }
    let mut v: Vec<&Rule> = best.into_values().collect();
    v.sort_by_key(|r| r.id);
    Decision::Inject(v)
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

    #[test]
    fn encoded_traversal_cannot_escape_after_normalization() {
        let rules = [rule(1, "a.com", "/repos/*", &["GET"], Header, "A")];
        for raw in [
            "/repos/%2e%2e/admin",
            "/repos/%2E%2E/admin",
            "/repos//../admin",
            "/repos/./../admin",
        ] {
            let p = crate::normalize::normalize_path(raw);
            assert_eq!(
                ids(evaluate(&rules, "a.com", "GET", &p)),
                vec![-1],
                "{raw} -> {p}"
            );
        }
        // Encoded slash stays one literal segment under /repos/, so it is still within the rule's prefix
        // and is forwarded exactly as authorized.
        let p = crate::normalize::normalize_path("/repos/%2e%2e%2f..");
        assert_eq!(p, "/repos/..%2f..");
        assert_eq!(ids(evaluate(&rules, "a.com", "GET", &p)), vec![1]);
    }

    #[test]
    fn forbidden_when_host_matches_but_nothing_else_does() {
        let rules = [rule(1, "a.com", "/x", &["GET"], Header, "A")];
        assert_eq!(ids(evaluate(&rules, "a.com", "POST", "/x")), vec![-1]);
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
