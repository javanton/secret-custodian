use crate::model::{InjectionKind, PolicyError};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

pub fn render(template: &str, secret: &str, kind: InjectionKind) -> Result<String, PolicyError> {
    let value = match kind {
        InjectionKind::Header => secret.to_string(),
        InjectionKind::Query => utf8_percent_encode(secret, NON_ALPHANUMERIC).to_string(),
    };
    let out = template.replace("{secret}", &value);
    if out.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(PolicyError::Invalid(
            "rendered value contains CR, LF or NUL",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::InjectionKind::*;

    #[test]
    fn header_template() {
        assert_eq!(
            render("Bearer {secret}", "tok", Header).unwrap(),
            "Bearer tok"
        );
    }

    #[test]
    fn query_value_is_percent_encoded() {
        assert_eq!(
            render("{secret}", "a b&c=d", Query).unwrap(),
            "a%20b%26c%3Dd"
        );
    }

    #[test]
    fn crlf_in_rendered_header_is_rejected() {
        assert!(render("Bearer {secret}", "x\r\nInjected: 1", Header).is_err());
        assert!(render("{secret}", "x\0y", Header).is_err());
    }

    // --- extra tests (gaps not covered by the plan) ---

    #[test]
    fn lone_cr_or_lf_in_header_is_rejected() {
        assert!(render("{secret}", "a\rb", Header).is_err());
        assert!(render("{secret}", "a\nb", Header).is_err());
    }

    #[test]
    fn crlf_in_template_is_rejected_even_with_clean_secret() {
        assert!(render("Bearer\r\n{secret}", "tok", Header).is_err());
        assert!(render("{secret}\n", "tok", Query).is_err());
    }

    #[test]
    fn crlf_in_query_secret_is_neutralised_by_encoding() {
        assert_eq!(
            render("{secret}", "a\r\nb\0", Query).unwrap(),
            "a%0D%0Ab%00"
        );
    }

    #[test]
    fn multiple_placeholders_are_all_replaced_once() {
        assert_eq!(render("{secret}:{secret}", "k", Header).unwrap(), "k:k");
    }

    #[test]
    fn secret_containing_placeholder_is_not_re_expanded() {
        assert_eq!(render("{secret}", "{secret}", Header).unwrap(), "{secret}");
    }

    #[test]
    fn non_ascii_secret_in_query_is_utf8_percent_encoded() {
        assert_eq!(render("{secret}", "é", Query).unwrap(), "%C3%A9");
    }
}
