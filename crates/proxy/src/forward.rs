use crate::{
    body::{watch, Keep},
    inject,
    server::{audit, identity_limit, text, Limits},
    upstream::{BoxError, ProxyBody, UpstreamError},
    ProxyState,
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, header::HOST, Request, Response, StatusCode};
use sg_auth::Identity;
use sg_policy::{evaluate, list_rules, normalize_host, normalize_path, render, Decision};
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct Ctx {
    pub state: Arc<ProxyState>,
    pub identity: Identity,
    /// Normalized hostname (what rules are matched against).
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// True only for plain-HTTP requests to hosts with no rules under a `passthrough` role.
    pub allow_unruled: bool,
    pub limits: Limits,
}

/// Every host the request declares (`Host` header values and the URI authority) must normalize
/// to the host the tunnel was opened for, and at least one must be present.
fn host_is_consistent(parts: &http::request::Parts, expected: &str) -> bool {
    let mut seen = false;
    for v in parts.headers.get_all(HOST) {
        seen = true;
        if v.to_str().ok().and_then(normalize_host).as_deref() != Some(expected) {
            return false;
        }
    }
    if let Some(a) = parts.uri.authority() {
        seen = true;
        if normalize_host(a.as_str()).as_deref() != Some(expected) {
            return false;
        }
    }
    seen
}

fn fail(
    ctx: &Ctx,
    method: &str,
    target: &str,
    decision: &str,
    status: StatusCode,
    rule_id: Option<i64>,
    msg: &str,
) -> Response<ProxyBody> {
    audit(
        &ctx.state,
        &ctx.identity,
        &ctx.host,
        method,
        target,
        decision,
        Some(status.as_u16()),
        rule_id,
    );
    text(status, msg)
}

/// Judges one request against the role's rules, injects, and relays it to the destination.
///
/// The audit row is written before the response is returned (so before its first byte reaches
/// the agent). The path judged by `evaluate` is `normalize_path(uri.path())` and exactly that
/// path is forwarded.
///
/// `keep` is held by the response body until it is done, aborted or dropped. Bodies in both
/// directions are aborted when they stop moving for `limits.body_idle_timeout`.
pub(crate) async fn forward(req: Request<Incoming>, ctx: &Ctx, keep: Keep) -> Response<ProxyBody> {
    let (mut parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let raw_target = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let st = &ctx.state;

    // Never legitimate for an API client, and TRACE/TRACK would reflect the injected credentials.
    if ["TRACE", "TRACK", "CONNECT"]
        .iter()
        .any(|m| parts.method.as_str().eq_ignore_ascii_case(m))
    {
        return fail(
            ctx,
            &method,
            &raw_target,
            "method-refused",
            StatusCode::METHOD_NOT_ALLOWED,
            None,
            "method not allowed\n",
        );
    }

    if !host_is_consistent(&parts, &ctx.host) {
        return fail(
            ctx,
            &method,
            &raw_target,
            "host-mismatch",
            StatusCode::MISDIRECTED_REQUEST,
            None,
            "Host does not match the CONNECT target\n",
        );
    }

    let path = normalize_path(parts.uri.path());
    // Reloaded for every request, so rule changes apply to open tunnels immediately.
    let rules = match list_rules(&st.vault, Some(&ctx.identity.role)) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "could not load rules");
            return fail(
                ctx,
                &method,
                &raw_target,
                "upstream-error",
                StatusCode::BAD_GATEWAY,
                None,
                "internal error\n",
            );
        }
    };
    let (matched, rule_id) = match evaluate(&rules, &ctx.host, &method, &path) {
        Decision::Inject(m) => {
            // Credentials are NEVER injected over plain HTTP (no exception, not even localhost).
            if !ctx.tls {
                return fail(
                    ctx,
                    &method,
                    &raw_target,
                    "plaintext-refused",
                    StatusCode::FORBIDDEN,
                    None,
                    "refusing to inject credentials over plain HTTP\n",
                );
            }
            // WebDAV `Destination` is an uncontrolled second target: COPY/MOVE only when every
            // matched rule names the method explicitly.
            let webdav = ["COPY", "MOVE"]
                .iter()
                .any(|w| method.eq_ignore_ascii_case(w));
            if webdav
                && !m
                    .iter()
                    .all(|r| r.methods.iter().any(|x| x.eq_ignore_ascii_case(&method)))
            {
                return fail(
                    ctx,
                    &method,
                    &raw_target,
                    "forbidden",
                    StatusCode::FORBIDDEN,
                    None,
                    "not allowed for this role\n",
                );
            }
            let rid = m.first().map(|r| r.id);
            (m, rid)
        }
        Decision::NoRuleForHost if ctx.allow_unruled => (vec![], None),
        Decision::NoRuleForHost | Decision::Forbidden => {
            return fail(
                ctx,
                &method,
                &raw_target,
                "forbidden",
                StatusCode::FORBIDDEN,
                None,
                "not allowed for this role\n",
            );
        }
    };

    let mut resolved = Vec::new();
    for r in matched {
        // Decrypted per request; the Zeroizing wrappers wipe it when `resolved` is dropped.
        let secret = match st.vault.reveal_for_injection(r.secret_id) {
            Ok(s) => s,
            Err(_) => {
                return fail(
                    ctx,
                    &method,
                    &raw_target,
                    "upstream-error",
                    StatusCode::BAD_GATEWAY,
                    rule_id,
                    "secret unavailable\n",
                );
            }
        };
        match render(&r.template, &secret, r.kind) {
            Ok(v) => resolved.push(inject::ResolvedInjection {
                kind: r.kind,
                name: r.target_name.clone(),
                value: Zeroizing::new(v),
            }),
            Err(_) => {
                return fail(
                    ctx,
                    &method,
                    &raw_target,
                    "upstream-error",
                    StatusCode::BAD_GATEWAY,
                    rule_id,
                    "invalid injection value\n",
                );
            }
        }
    }

    if inject::apply(&mut parts, &path, &resolved).is_err() {
        return fail(
            ctx,
            &method,
            &raw_target,
            "upstream-error",
            StatusCode::BAD_GATEWAY,
            rule_id,
            "could not build the upstream request\n",
        );
    }
    let default_port = if ctx.tls { 443 } else { 80 };
    let bare = if ctx.host.contains(':') {
        format!("[{}]", ctx.host)
    } else {
        ctx.host.clone()
    };
    let host_header = if ctx.port == default_port {
        bare
    } else {
        format!("{bare}:{}", ctx.port)
    };
    match host_header.parse() {
        Ok(v) => {
            parts.headers.insert(HOST, v);
        }
        Err(_) => {
            return fail(
                ctx,
                &method,
                &raw_target,
                "upstream-error",
                StatusCode::BAD_GATEWAY,
                rule_id,
                "could not build the upstream request\n",
            );
        }
    }
    parts.version = hyper::Version::HTTP_11;

    // One identity may only have so many requests towards upstream at once; the share is
    // returned when the response body is done (or aborted).
    let Some(up_guard) = ctx
        .limits
        .upstream
        .try_acquire(&ctx.identity.jti, ctx.limits.max_upstream_per_identity)
    else {
        return identity_limit(
            &ctx.state,
            &ctx.identity,
            &ctx.host,
            &method,
            &raw_target,
            rule_id,
            "too many concurrent requests for this token\n",
        );
    };
    let idle = ctx.limits.body_idle_timeout;
    let req_body: ProxyBody = body.map_err(|e| -> BoxError { Box::new(e) }).boxed();
    let outgoing = Request::from_parts(parts, watch(req_body, idle, Vec::new()));
    // Local services: loopback is reachable only over TLS (an agent cannot forge a certificate
    // trusted for `localhost`), for the exact host `localhost` and with an applicable rule.
    let local_service = ctx.tls && ctx.host == "localhost" && rule_id.is_some();
    let result = st
        .upstream
        .send_to(&ctx.host, ctx.port, ctx.tls, outgoing, local_service)
        .await;
    drop(resolved); // wipe the decrypted values as soon as the request is on its way
    match result {
        Ok(resp) => {
            let decision = if rule_id.is_none() {
                "passthrough"
            } else {
                "inject"
            };
            audit(
                st,
                &ctx.identity,
                &ctx.host,
                &method,
                &raw_target,
                decision,
                Some(resp.status().as_u16()),
                rule_id,
            );
            let (mut rparts, rbody) = resp.into_parts();
            inject::strip_hop_by_hop(&mut rparts.headers);
            let rbody: ProxyBody = rbody.map_err(|e| -> BoxError { Box::new(e) }).boxed();
            let mut keep = keep;
            keep.push(Box::new(up_guard));
            Response::from_parts(rparts, watch(rbody, idle, keep))
        }
        Err(UpstreamError::TargetDenied) => fail(
            ctx,
            &method,
            &raw_target,
            "target-denied",
            StatusCode::FORBIDDEN,
            rule_id,
            "destination not allowed\n",
        ),
        Err(e) => {
            // `e` carries no request data: only connect/TLS/IO descriptions.
            tracing::warn!(error = %e, host = %ctx.host, "upstream failure");
            fail(
                ctx,
                &method,
                &raw_target,
                "upstream-error",
                StatusCode::BAD_GATEWAY,
                rule_id,
                "upstream request failed\n",
            )
        }
    }
}
