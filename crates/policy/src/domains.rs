use crate::model::Rule;

/// Domains the CA must permit: the host of every rule (`*.x` becomes `x`, which also covers
/// subdomains), sorted and without duplicates.
pub fn derive_ca_domains(rules: &[Rule]) -> Vec<String> {
    let mut d: Vec<String> = rules
        .iter()
        .map(|r| {
            r.host_pattern
                .strip_prefix("*.")
                .unwrap_or(&r.host_pattern)
                .to_string()
        })
        .collect();
    d.sort();
    d.dedup();
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InjectionKind;

    fn rule(host: &str) -> Rule {
        Rule {
            id: 1,
            role: "r".into(),
            host_pattern: host.into(),
            path_pattern: "*".into(),
            methods: vec![],
            kind: InjectionKind::Header,
            target_name: "X".into(),
            template: "{secret}".into(),
            secret_id: 1,
        }
    }

    #[test]
    fn wildcards_collapse_into_their_domain_without_duplicates() {
        let rules = [
            rule("*.habbi.cc"),
            rule("habbi.cc"),
            rule("api.github.com"),
            rule("api.github.com"),
        ];
        assert_eq!(
            derive_ca_domains(&rules),
            vec!["api.github.com", "habbi.cc"]
        );
        assert!(derive_ca_domains(&[]).is_empty());
    }
}
