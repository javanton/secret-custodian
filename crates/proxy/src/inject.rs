use http::{header::HeaderName, request::Parts, HeaderMap, HeaderValue, Uri};
use percent_encoding::percent_decode_str;
use sg_policy::InjectionKind;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum InjectError {
    #[error("invalid header name or value")]
    Header,
    #[error("invalid uri")]
    Uri,
}

pub struct ResolvedInjection {
    pub kind: InjectionKind,
    pub name: String,
    /// Header: the full value. Query: already percent-encoded.
    pub value: Zeroizing<String>,
}

/// Hop-by-hop headers (RFC 9110 7.6.1 plus the de-facto `Proxy-Connection`). `Proxy-*` headers
/// are handled by prefix.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.contains(&name) || name.starts_with("proxy-")
}

/// Removes hop-by-hop headers, including the ones nominated by `Connection`. The `framing`
/// headers `hyper` computes itself (`Transfer-Encoding`) go too.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    let doomed: Vec<HeaderName> = headers
        .keys()
        .filter(|k| is_hop_by_hop(k.as_str()))
        .cloned()
        .collect();
    for h in doomed.iter().chain(nominated.iter()) {
        headers.remove(h);
    }
}

/// Headers that tell the origin (or a fronting framework) to route, rewrite or re-attribute the
/// request. The agent must not be able to steer the injected request with them.
const ROUTING_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
    "x-real-ip",
    "forwarded",
    "x-original-host",
    "x-host",
    "via",
    "front-end-https",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-cluster-client-ip",
    "x-original-uri",
];

/// Lowercases and maps `_` to `-`: many frameworks (CGI-style `HTTP_X_FOO`) treat both
/// spellings of a header name as the same header.
fn normalize_header_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '_' {
                '-'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

/// Removes routing-override and forwarding headers (every `X-Forwarded-*` included), whatever
/// the mix of `_`/`-` and case in their names.
pub(crate) fn strip_routing_headers(headers: &mut HeaderMap) {
    let doomed: Vec<HeaderName> = headers
        .keys()
        .filter(|k| {
            let n = normalize_header_name(k.as_str());
            ROUTING_HEADERS.contains(&n.as_str()) || n.starts_with("x-forwarded-")
        })
        .cloned()
        .collect();
    for h in doomed {
        headers.remove(h);
    }
}

pub fn apply(
    parts: &mut Parts,
    path: &str,
    injections: &[ResolvedInjection],
) -> Result<(), InjectError> {
    strip_hop_by_hop(&mut parts.headers);
    strip_routing_headers(&mut parts.headers);
    let mut query: Vec<String> = parts
        .uri
        .query()
        .map(|q| {
            q.split('&')
                .filter(|p| !p.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    for inj in injections {
        match inj.kind {
            InjectionKind::Header => {
                let name =
                    HeaderName::from_bytes(inj.name.as_bytes()).map_err(|_| InjectError::Header)?;
                // `remove` drops every value under this (case-insensitive) name.
                parts.headers.remove(&name);
                let mut v = HeaderValue::from_str(&inj.value).map_err(|_| InjectError::Header)?;
                v.set_sensitive(true);
                parts.headers.insert(name, v);
            }
            InjectionKind::Query => {
                // Some origins also split parameters on `;`: judge every sub-parameter, but keep
                // the text of the surviving ones untouched.
                query = query
                    .into_iter()
                    .filter_map(|pair| {
                        let kept: Vec<&str> = pair
                            .split(';')
                            .filter(|sub| {
                                let key = sub.split('=').next().unwrap_or("");
                                !percent_decode_str(key)
                                    .decode_utf8_lossy()
                                    .eq_ignore_ascii_case(&inj.name)
                            })
                            .collect();
                        (!kept.is_empty()).then(|| kept.join(";"))
                    })
                    .collect();
                // Names are validated as [A-Za-z0-9_.-] at rule creation.
                query.push(format!("{}={}", inj.name, *inj.value));
            }
        }
    }

    let pq = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{}", query.join("&"))
    };
    parts.uri = pq.parse::<Uri>().map_err(|_| InjectError::Uri)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sg_policy::InjectionKind::*;
    use zeroize::Zeroizing;

    fn parts(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder().uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn inj(kind: sg_policy::InjectionKind, name: &str, value: &str) -> ResolvedInjection {
        ResolvedInjection {
            kind,
            name: name.into(),
            value: Zeroizing::new(value.into()),
        }
    }

    #[test]
    fn header_overwrites_every_agent_supplied_variant() {
        let mut p = parts(
            "/x",
            &[
                ("authorization", "Bearer AGENT-1"),
                ("Authorization", "Bearer AGENT-2"),
                ("x-keep", "1"),
            ],
        );
        apply(&mut p, "/x", &[inj(Header, "Authorization", "Bearer REAL")]).unwrap();
        let all: Vec<_> = p.headers.get_all("authorization").iter().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "Bearer REAL");
        assert!(all[0].is_sensitive());
        assert_eq!(p.headers.get("x-keep").unwrap(), "1");
    }

    #[test]
    fn query_param_is_replaced_not_duplicated() {
        let mut p = parts("/x?API_KEY=agent&a=1&api_key=agent2&b=2", &[]);
        apply(&mut p, "/x", &[inj(Query, "api_key", "a%20b")]).unwrap();
        assert_eq!(p.uri.to_string(), "/x?a=1&b=2&api_key=a%20b");
    }

    #[test]
    fn query_param_with_encoded_name_is_also_replaced() {
        let mut p = parts("/x?api%5Fkey=agent&a=1&%61pi_key", &[]);
        apply(&mut p, "/x", &[inj(Query, "api_key", "v")]).unwrap();
        assert_eq!(p.uri.to_string(), "/x?a=1&api_key=v");
    }

    #[test]
    fn path_is_rewritten_to_the_normalized_one() {
        let mut p = parts("/repos/../admin?z=1", &[]);
        apply(&mut p, "/admin", &[]).unwrap();
        assert_eq!(p.uri.to_string(), "/admin?z=1");
    }

    #[test]
    fn proxy_headers_are_stripped() {
        let mut p = parts(
            "/x",
            &[
                ("proxy-authorization", "Basic x"),
                ("proxy-connection", "keep-alive"),
                ("connection", "close"),
            ],
        );
        apply(&mut p, "/x", &[]).unwrap();
        assert!(p.headers.get("proxy-authorization").is_none());
        assert!(p.headers.get("proxy-connection").is_none());
        assert!(p.headers.get("connection").is_none());
    }

    #[test]
    fn headers_nominated_by_connection_and_other_proxy_headers_are_stripped() {
        let mut p = parts(
            "/x",
            &[
                ("connection", "X-Hop, close"),
                ("x-hop", "1"),
                ("proxy-whatever", "1"),
                ("te", "trailers"),
                ("trailer", "x"),
                ("upgrade", "websocket"),
                ("x-keep", "1"),
            ],
        );
        apply(&mut p, "/x", &[]).unwrap();
        let left: Vec<_> = p.headers.keys().map(|k| k.as_str()).collect();
        assert_eq!(left, vec!["x-keep"]);
    }

    #[test]
    fn invalid_header_value_is_an_error_and_never_panics() {
        let mut p = parts("/x", &[]);
        assert!(apply(&mut p, "/x", &[inj(Header, "Authorization", "a\nb")]).is_err());
        assert!(apply(&mut p, "/x", &[inj(Header, "bad name", "v")]).is_err());
    }
}
