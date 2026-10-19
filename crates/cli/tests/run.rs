//! End-to-end behaviour of the commands against a fake admin server on a Unix socket.
use axum::{body::Body, http::Request, Router};
use clap::Parser;
use sg_cli::{run_io, ClientCommand, ClientOpts, Io};
use std::{
    io::Read,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::net::UnixListener;

#[derive(Parser)]
struct W {
    #[command(flatten)]
    opts: ClientOpts,
    #[command(subcommand)]
    cmd: ClientCommand,
}

#[derive(Clone, Debug)]
struct Rec {
    method: String,
    uri: String,
    ctype: Option<String>,
    body: Vec<u8>,
}

struct Fake {
    _dir: tempfile::TempDir,
    sock: PathBuf,
    log: Arc<Mutex<Vec<Rec>>>,
}

impl Fake {
    fn log(&self) -> Vec<Rec> {
        self.log.lock().unwrap().clone()
    }
}

/// Starts a server that records every request and answers with `respond(&rec) -> (status, body)`.
fn fake(respond: impl Fn(&Rec) -> (u16, Vec<u8>) + Clone + Send + Sync + 'static) -> Fake {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = dir.path().join("t.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let log: Arc<Mutex<Vec<Rec>>> = Default::default();
    let l2 = log.clone();
    let app = Router::new().fallback(move |req: Request<Body>| {
        let (l2, respond) = (l2.clone(), respond.clone());
        async move {
            let (parts, body) = req.into_parts();
            let body = axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec();
            let rec = Rec {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                ctype: parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from),
                body,
            };
            let (st, resp) = respond(&rec);
            l2.lock().unwrap().push(rec);
            axum::http::Response::builder()
                .status(st)
                .body(Body::from(resp))
                .unwrap()
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Fake {
        _dir: dir,
        sock,
        log,
    }
}

fn ok_json(v: serde_json::Value) -> (u16, Vec<u8>) {
    (200, v.to_string().into_bytes())
}

struct Out {
    res: anyhow::Result<()>,
    out: Vec<u8>,
    err: String,
}
impl Out {
    fn ok(&self) {
        if let Err(e) = &self.res {
            panic!("command failed: {e:#}");
        }
    }
    fn err_msg(&self) -> String {
        format!("{:#}", self.res.as_ref().unwrap_err())
    }
    fn out(&self) -> String {
        String::from_utf8(self.out.clone()).unwrap()
    }
}

async fn cli_with(sock: &std::path::Path, args: &[&str], stdin: &mut dyn Read) -> Out {
    let mut full = vec!["sg"];
    full.extend_from_slice(args);
    let w = W::try_parse_from(full).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let res = {
        let mut io = Io {
            stdin,
            tty: false,
            out: &mut out,
            err: &mut err,
        };
        run_io(sock, &w.opts, w.cmd, &mut io).await
    };
    Out {
        res,
        out,
        err: String::from_utf8(err).unwrap(),
    }
}

async fn cli(f: &Fake, args: &[&str], stdin: &[u8]) -> Out {
    let mut s = stdin;
    cli_with(&f.sock, args, &mut s).await
}

fn echo_ok() -> Fake {
    fake(|_| {
        ok_json(serde_json::json!({"id": 1, "name": "gh", "created_at": 0, "rotated_at": null}))
    })
}

// ---- secret values -------------------------------------------------------------------------

#[tokio::test]
async fn secret_add_reads_stdin_strips_one_newline_and_never_prints_it() {
    let f = echo_ok();
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"ghp_sekrit value \n",
    )
    .await;
    r.ok();
    let log = f.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].method, "POST");
    assert_eq!(log[0].uri, "/secrets");
    assert_eq!(log[0].ctype.as_deref(), Some("application/json"));
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert_eq!(body["name"], "gh");
    assert_eq!(body["value"], "ghp_sekrit value ");
    assert!(!r.out().contains("sekrit") && !r.err.contains("sekrit"));
}

#[tokio::test]
async fn secret_add_strips_crlf() {
    let f = echo_ok();
    cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"abc\r\n",
    )
    .await
    .res
    .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&f.log()[0].body).unwrap();
    assert_eq!(body["value"], "abc");
}

#[tokio::test]
async fn secret_rotate_puts_the_value() {
    let f = echo_ok();
    cli(&f, &["secret", "rotate", "gh"], b"new\n")
        .await
        .res
        .unwrap();
    let log = f.log();
    assert_eq!(
        (log[0].method.as_str(), log[0].uri.as_str()),
        ("PUT", "/secrets/gh")
    );
    let body: serde_json::Value = serde_json::from_slice(&log[0].body).unwrap();
    assert_eq!(body, serde_json::json!({"value": "new"}));
}

#[tokio::test]
async fn invalid_values_are_refused_before_any_request() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", b"\n".to_vec()),
        ("empty-eof", vec![]),
        ("two newlines", b"abc\n\n".to_vec()),
        ("embedded newline", b"ab\ncd".to_vec()),
        ("embedded cr", b"ab\rcd".to_vec()),
        ("nul", b"ab\0cd".to_vec()),
        ("non-utf8", vec![0xff, 0xfe, 0xfd]),
        ("too long", vec![b'a'; 8193]),
    ];
    cases.push(("long with newline", {
        let mut v = vec![b'a'; 8193];
        v.push(b'\n');
        v
    }));
    for (label, input) in cases {
        let f = echo_ok();
        let r = cli(
            &f,
            &[
                "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
            ],
            &input,
        )
        .await;
        assert!(r.res.is_err(), "{label} must fail");
        assert!(f.log().is_empty(), "{label}: request was sent");
        let msg = r.err_msg();
        assert!(
            !msg.contains("aaaa") && !msg.contains("abc"),
            "{label}: error leaks value: {msg}"
        );
    }
}

#[tokio::test]
async fn a_value_of_exactly_8192_bytes_is_accepted() {
    let f = echo_ok();
    let mut input = vec![b'a'; 8192];
    input.push(b'\n');
    cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        &input,
    )
    .await
    .res
    .unwrap();
    assert_eq!(f.log().len(), 1);
}

struct Endless(usize);
impl Read for Endless {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(b'a');
        self.0 += buf.len();
        Ok(buf.len())
    }
}

#[tokio::test]
async fn oversize_stdin_is_rejected_without_reading_it_all() {
    let f = echo_ok();
    let mut src = Endless(0);
    let r = cli_with(
        &f.sock,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        &mut src,
    )
    .await;
    assert!(r.res.is_err());
    assert!(src.0 <= 8193 + 8192, "read {} bytes", src.0);
    assert!(f.log().is_empty());
}

#[tokio::test]
async fn server_errors_that_echo_the_value_never_reach_the_output() {
    let f = fake(|rec| {
        let body = String::from_utf8_lossy(&rec.body).to_string();
        (
            400,
            serde_json::json!({"error": format!("bad request: {body}")})
                .to_string()
                .into_bytes(),
        )
    });
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"ghp_TOPSECRET\n",
    )
    .await;
    let msg = r.err_msg();
    assert!(!msg.contains("TOPSECRET"), "{msg}");
    assert!(!r.out().contains("TOPSECRET") && !r.err.contains("TOPSECRET"));
    assert!(msg.contains("bad request"), "{msg}");
}

#[tokio::test]
async fn short_values_do_not_mangle_ordinary_words_in_server_errors() {
    let f = fake(|_| (409, br#"{"error":"secret already exists"}"#.to_vec()));
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"x\n",
    )
    .await;
    assert!(
        r.err_msg().contains("secret already exists"),
        "{}",
        r.err_msg()
    );
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"ist\n",
    )
    .await;
    assert!(
        r.err_msg().contains("secret already exists"),
        "{}",
        r.err_msg()
    );
}

#[tokio::test]
async fn short_values_are_still_never_echoed_as_the_whole_message() {
    let f = fake(|rec| {
        let v: serde_json::Value = serde_json::from_slice(&rec.body).unwrap();
        (
            400,
            serde_json::json!({"error": v["value"]})
                .to_string()
                .into_bytes(),
        )
    });
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"hunter2\n",
    )
    .await;
    assert!(!r.err_msg().contains("hunter2"), "{}", r.err_msg());
}

#[tokio::test]
async fn values_of_eight_bytes_are_redacted_inside_longer_messages() {
    let f = fake(|rec| {
        let body = String::from_utf8_lossy(&rec.body).to_string();
        (
            400,
            serde_json::json!({"error": format!("bad: {body}")})
                .to_string()
                .into_bytes(),
        )
    });
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"12345678\n",
    )
    .await;
    assert!(!r.err_msg().contains("12345678"), "{}", r.err_msg());
    assert!(r.err_msg().contains("bad"), "{}", r.err_msg());
}

// ---- errors ---------------------------------------------------------------------------------

#[tokio::test]
async fn server_error_message_is_surfaced_without_control_characters() {
    let f = fake(|_| (409, br#"{"error":"already exists\u001b[31m"}"#.to_vec()));
    let r = cli(&f, &["role", "add", "dev"], b"").await;
    let msg = r.err_msg();
    assert!(msg.contains("already exists"), "{msg}");
    assert!(!msg.contains('\u{1b}'));
}

#[tokio::test]
async fn non_json_error_bodies_fall_back_to_the_status() {
    let f = fake(|_| (500, vec![0xff, 0xfe]));
    let r = cli(&f, &["secret", "ls"], b"").await;
    assert!(r.err_msg().contains("500"));
}

#[tokio::test]
async fn unreachable_vault_message_names_the_socket() {
    let mut s: &[u8] = b"";
    let r = cli_with(
        std::path::Path::new("/nonexistent/x.sock"),
        &["secret", "ls"],
        &mut s,
    )
    .await;
    let msg = r.err_msg();
    assert!(
        msg.contains("sg serve") && msg.contains("/nonexistent/x.sock"),
        "{msg}"
    );
}

// ---- output ---------------------------------------------------------------------------------

#[tokio::test]
async fn secret_ls_renders_an_aligned_table_with_rfc3339_utc() {
    let f = fake(|_| {
        ok_json(serde_json::json!([
            {"id": 1, "name": "gh", "created_at": 1700000000, "rotated_at": null},
            {"id": 2, "name": "a-much-longer-name", "created_at": 0, "rotated_at": 1700000000}
        ]))
    });
    let r = cli(&f, &["secret", "ls"], b"").await;
    r.ok();
    let out = r.out();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(out.contains("2023-11-14T22:13:20Z"), "{out}");
    assert!(out.contains("1970-01-01T00:00:00Z"), "{out}");
    let col = lines[0].find("CREATED").unwrap();
    assert_eq!(lines[1].find("2023-11-14T22:13:20Z"), Some(col), "{out}");
    assert_eq!(lines[2].find("1970-01-01T00:00:00Z"), Some(col), "{out}");
}

#[tokio::test]
async fn json_flag_prints_the_raw_server_json() {
    let f = fake(|_| {
        ok_json(
            serde_json::json!([{"jti": "j", "machine": "m", "role": "r", "created_at": 5, "expires_at": null, "revoked_at": null}]),
        )
    });
    let r = cli(&f, &["--json", "token", "ls"], b"").await;
    r.ok();
    let v: serde_json::Value = serde_json::from_str(&r.out()).unwrap();
    assert_eq!(v[0]["created_at"], 5);
}

#[tokio::test]
async fn token_ls_never_prints_a_token_value_and_shows_status() {
    let f = fake(|_| {
        ok_json(serde_json::json!([
            {"jti": "j1", "machine": "m", "role": "r", "created_at": 5, "expires_at": null, "revoked_at": 9},
            {"jti": "j2", "machine": "m", "role": "r", "created_at": 5, "expires_at": 4102444800i64, "revoked_at": null}
        ]))
    });
    let out = cli(&f, &["token", "ls"], b"").await.out();
    assert!(out.contains("revoked") && out.contains("active"), "{out}");
}

#[tokio::test]
async fn role_and_rule_and_audit_tables() {
    let f = fake(|rec| {
        if rec.uri.starts_with("/roles") {
            ok_json(serde_json::json!([{"name": "dev", "unmatched": "passthrough"}]))
        } else if rec.uri.starts_with("/rules") {
            ok_json(
                serde_json::json!([{"id": 3, "role": "dev", "host_pattern": "api.github.com", "path_pattern": "/repos/*", "methods": ["GET", "HEAD"], "kind": "header", "target_name": "Authorization", "template": "Bearer {secret}", "secret_id": 1}]),
            )
        } else {
            ok_json(
                serde_json::json!([{"ts": 1700000000, "jti": null, "machine": "m", "role": "dev", "host": "h.com", "method": "GET", "path": "/", "rule_id": 3, "decision": "allow", "status": 200}]),
            )
        }
    });
    let roles = cli(&f, &["role", "ls"], b"").await.out();
    assert!(roles.contains("dev") && roles.contains("passthrough"));
    let rules = cli(&f, &["rule", "ls", "--role", "dev"], b"").await.out();
    assert!(
        rules.contains("GET,HEAD") && rules.contains("Authorization"),
        "{rules}"
    );
    let audit = cli(&f, &["audit"], b"").await.out();
    assert!(
        audit.contains("2023-11-14T22:13:20Z") && audit.contains("allow"),
        "{audit}"
    );
    assert_eq!(f.log()[1].uri, "/rules?role=dev");
}

// ---- roles / rules --------------------------------------------------------------------------

#[tokio::test]
async fn role_add_defaults_to_passthrough() {
    let f = echo_ok();
    cli(&f, &["role", "add", "dev"], b"").await.res.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&f.log()[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"name": "dev", "unmatched": "passthrough"})
    );
}

fn rules_fake() -> Fake {
    fake(|rec| {
        match (rec.method.as_str(), rec.uri.as_str()) {
        ("GET", "/secrets") => ok_json(
            serde_json::json!([{"id": 7, "name": "gh", "created_at": 0, "rotated_at": null}]),
        ),
        ("POST", "/rules") => (
            201,
            serde_json::json!({"rule": {"id": 4}, "ca_changed": true, "notice": "the CA certificate changed: agents must reload it"})
                .to_string()
                .into_bytes(),
        ),
        _ => (404, br#"{"error":"not found"}"#.to_vec()),
    }
    })
}

#[tokio::test]
async fn rule_add_resolves_the_secret_and_prints_the_ca_notice_on_stderr() {
    let f = rules_fake();
    let r = cli(
        &f,
        &[
            "rule",
            "add",
            "--role",
            "dev",
            "--host",
            "h.com",
            "--methods",
            "get, head",
            "--header",
            "Authorization",
            "--template",
            "Bearer {secret}",
            "--secret",
            "gh",
        ],
        b"",
    )
    .await;
    r.ok();
    let log = f.log();
    assert_eq!(log[1].uri, "/rules");
    let body: serde_json::Value = serde_json::from_slice(&log[1].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"role": "dev", "host_pattern": "h.com", "path_pattern": "*", "methods": ["GET", "HEAD"], "kind": "header", "target_name": "Authorization", "template": "Bearer {secret}", "secret_id": 7})
    );
    assert!(r.err.contains("the CA certificate changed"), "{}", r.err);
    assert!(!r.out().contains("certificate changed"));
}

#[tokio::test]
async fn rule_add_with_query_uses_the_plain_secret_template() {
    let f = rules_fake();
    cli(
        &f,
        &[
            "rule", "add", "--role", "dev", "--host", "h.com", "--query", "api_key", "--secret",
            "gh",
        ],
        b"",
    )
    .await
    .res
    .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&f.log()[1].body).unwrap();
    assert_eq!(body["kind"], "query");
    assert_eq!(body["template"], "{secret}");
}

#[tokio::test]
async fn rule_add_with_query_rejects_other_templates_before_any_request() {
    let f = rules_fake();
    let r = cli(
        &f,
        &[
            "rule",
            "add",
            "--role",
            "dev",
            "--host",
            "h.com",
            "--query",
            "k",
            "--template",
            "Bearer {secret}",
            "--secret",
            "gh",
        ],
        b"",
    )
    .await;
    assert!(r.err_msg().contains("{secret}"));
    assert!(f.log().is_empty());
}

#[tokio::test]
async fn rule_add_unknown_secret_is_an_error() {
    let f = rules_fake();
    let r = cli(
        &f,
        &[
            "rule", "add", "--role", "dev", "--host", "h.com", "--header", "A", "--secret", "nope",
        ],
        b"",
    )
    .await;
    assert!(r.err_msg().contains("'nope' not found"));
    assert_eq!(f.log().len(), 1);
}

// ---- tokens ---------------------------------------------------------------------------------

#[tokio::test]
async fn token_create_prints_the_token_env_block_and_ca_hints() {
    let f = fake(|_| {
        (201, serde_json::json!({"token": "TKN.abc_def", "jti": "j", "machine": "my box/1", "role": "dev"}).to_string().into_bytes())
    });
    let r = cli(
        &f,
        &[
            "token",
            "create",
            "--machine",
            "my box/1",
            "--role",
            "dev",
            "--ttl",
            "12h",
            "--proxy-url",
            "http://10.0.0.5:9000",
        ],
        b"",
    )
    .await;
    r.ok();
    let body: serde_json::Value = serde_json::from_slice(&f.log()[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"machine": "my box/1", "role": "dev", "ttl_secs": 43200})
    );
    let out = r.out();
    assert!(out.contains("TKN.abc_def"));
    assert!(
        out.contains("HTTPS_PROXY=http://my%20box%2F1:TKN.abc_def@10.0.0.5:9000"),
        "{out}"
    );
    assert!(out.contains("HTTP_PROXY="));
    assert!(out.contains("NO_PROXY=localhost,127.0.0.1"));
    assert!(out.contains("sg ca export > sg-ca.pem"));
    for v in [
        "SSL_CERT_FILE",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    ] {
        assert!(out.contains(v), "{v}");
    }
}

#[tokio::test]
async fn token_create_default_proxy_and_no_ttl() {
    let f = fake(|_| {
        (
            201,
            serde_json::json!({"token": "T", "jti": "j", "machine": "m", "role": "r"})
                .to_string()
                .into_bytes(),
        )
    });
    let r = cli(
        &f,
        &["token", "create", "--machine", "m", "--role", "r"],
        b"",
    )
    .await;
    r.ok();
    let body: serde_json::Value = serde_json::from_slice(&f.log()[0].body).unwrap();
    assert!(body["ttl_secs"].is_null());
    assert!(r.out().contains("@127.0.0.1:8080"));
}

#[tokio::test]
async fn token_create_rejects_a_bad_proxy_url() {
    let f = fake(|_| unreachable!());
    for bad in [
        "127.0.0.1:8080",
        "ftp://x:1",
        "http://u:p@x:1",
        "http://x y:1",
    ] {
        let r = cli(
            &f,
            &[
                "token",
                "create",
                "--machine",
                "m",
                "--role",
                "r",
                "--proxy-url",
                bad,
            ],
            b"",
        )
        .await;
        assert!(r.res.is_err(), "{bad}");
    }
    assert!(f.log().is_empty());
}

#[tokio::test]
async fn token_revoke_and_revoke_machine() {
    let f = fake(|rec| {
        if rec.method == "DELETE" {
            (204, vec![])
        } else {
            ok_json(serde_json::json!({"revoked": 2}))
        }
    });
    let jti = "123e4567-e89b-12d3-a456-426614174000";
    let r = cli(&f, &["token", "revoke", jti], b"").await;
    r.ok();
    let r2 = cli(&f, &["token", "revoke-machine", "my box"], b"").await;
    r2.ok();
    let log = f.log();
    assert_eq!(
        (log[0].method.as_str(), log[0].uri.clone()),
        ("DELETE", format!("/tokens/{jti}"))
    );
    assert_eq!(
        (log[1].method.as_str(), log[1].uri.as_str()),
        ("POST", "/machines/my%20box/revoke")
    );
    assert!(log[1].body.is_empty());
    assert!(r2.out().contains('2'));
}

// ---- ca / audit -----------------------------------------------------------------------------

#[tokio::test]
async fn ca_export_writes_the_pem_exactly() {
    let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec();
    let p2 = pem.clone();
    let f = fake(move |_| (200, p2.clone()));
    let r = cli(&f, &["ca", "export"], b"").await;
    r.ok();
    assert_eq!(r.out, pem);
    assert_eq!(f.log()[0].uri, "/ca/cert");
}

#[tokio::test]
async fn audit_builds_an_encoded_query() {
    let f = fake(|_| ok_json(serde_json::json!([])));
    cli(
        &f,
        &[
            "audit", "--role", "dev", "--host", "a&b.com", "--since", "100", "--limit", "5",
        ],
        b"",
    )
    .await
    .res
    .unwrap();
    assert_eq!(
        f.log()[0].uri,
        "/audit?limit=5&role=dev&host=a%26b.com&since=100"
    );
}

// ---- login-url ------------------------------------------------------------------------------

#[tokio::test]
async fn login_url_prints_the_url_from_the_socket_route() {
    let f = fake(|_| {
        ok_json(serde_json::json!({"token": "abc", "url": "http://localhost:9090/#t=abc"}))
    });
    let r = cli(&f, &["login-url"], b"").await;
    r.ok();
    assert_eq!(r.out().trim(), "http://localhost:9090/#t=abc");
    assert!(r.out().contains("#t="));
    assert_eq!(
        (f.log()[0].method.as_str(), f.log()[0].uri.as_str()),
        ("POST", "/admin/login-token")
    );
}

#[tokio::test]
async fn login_url_falls_back_to_the_bare_token() {
    let f = fake(|_| ok_json(serde_json::json!({"token": "abc"})));
    let r = cli(&f, &["login-url"], b"").await;
    r.ok();
    assert_eq!(r.out().trim(), "abc");
}

// ---- path safety ----------------------------------------------------------------------------

#[tokio::test]
async fn odd_names_cannot_change_the_route() {
    let f = fake(|_| (204, vec![]));
    for (name, want) in [
        ("../x", "/secrets/..%2Fx"),
        ("%2f", "/secrets/%252f"),
        ("..", "/secrets/%2E%2E"),
        ("a?b#c", "/secrets/a%3Fb%23c"),
    ] {
        cli(&f, &["secret", "rm", name], b"").await.res.unwrap();
        assert_eq!(f.log().last().unwrap().uri, want);
    }
}

fn secrets_fake(roles: serde_json::Value) -> Fake {
    fake(move |rec| {
        match (rec.method.as_str(), rec.uri.as_str()) {
        ("GET", "/roles") => ok_json(roles.clone()),
        ("POST", "/roles") => (
            201,
            br#"{"name":"default","unmatched":"passthrough"}"#.to_vec(),
        ),
        ("POST", "/secrets") => (
            201,
            serde_json::json!({"secret":{"id":1,"name":"gh","created_at":0,"rotated_at":null},
                "rules":[{"id":1}],"ca_changed":true,"notice":"the CA certificate changed: agents must reload it (sg ca export)"})
            .to_string()
            .into_bytes(),
        ),
        _ => (404, br#"{"error":"not found"}"#.to_vec()),
    }
    })
}

#[tokio::test]
async fn secret_add_sends_the_value_and_its_first_rule_in_one_request() {
    let f = secrets_fake(serde_json::json!([{"name":"dev","unmatched":"deny"}]));
    let r = cli(
        &f,
        &[
            "secret",
            "add",
            "gh",
            "--host",
            "api.github.com",
            "--header",
            "Authorization",
            "--template",
            "Bearer {secret}",
        ],
        b"s3cr3t-value\n",
    )
    .await;
    r.ok();
    let log = f.log();
    let post = log
        .iter()
        .find(|r| r.method == "POST" && r.uri == "/secrets")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["name"], "gh");
    assert_eq!(body["value"], "s3cr3t-value");
    assert_eq!(
        body["rules"][0]["role"], "dev",
        "the only role is chosen automatically"
    );
    assert_eq!(body["rules"][0]["host_pattern"], "api.github.com");
    assert_eq!(body["rules"][0]["kind"], "header");
    assert_eq!(body["rules"][0]["template"], "Bearer {secret}");
    assert!(
        r.err.contains("reload"),
        "the CA notice goes to stderr: {}",
        r.err
    );
}

#[tokio::test]
async fn secret_add_creates_the_default_role_when_there_is_none() {
    let f = secrets_fake(serde_json::json!([]));
    cli(
        &f,
        &[
            "secret", "add", "gh", "--host", "a.com", "--header", "X-Key",
        ],
        b"valuevalue\n",
    )
    .await
    .res
    .unwrap();
    let log = f.log();
    assert!(log.iter().any(|r| r.method == "POST" && r.uri == "/roles"));
    let post = log
        .iter()
        .find(|r| r.uri == "/secrets" && r.method == "POST")
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["rules"][0]["role"], "default");
}

#[tokio::test]
async fn secret_add_with_several_roles_demands_one_and_never_leaks_the_value() {
    let f = secrets_fake(
        serde_json::json!([{"name":"a","unmatched":"deny"},{"name":"b","unmatched":"deny"}]),
    );
    let r = cli(
        &f,
        &[
            "secret", "add", "gh", "--host", "a.com", "--header", "X-Key",
        ],
        b"valuevalue\n",
    )
    .await;
    let e = format!("{:#}", r.res.unwrap_err());
    assert!(e.contains("--role") && e.contains("a, b"), "{e}");
    assert!(!e.contains("valuevalue"));
    assert!(
        !f.log().iter().any(|r| r.method == "POST"),
        "nothing is created"
    );
}

#[tokio::test]
async fn secret_add_with_an_invalid_target_fails_before_any_request() {
    let f = secrets_fake(serde_json::json!([]));
    let r = cli(
        &f,
        &[
            "secret",
            "add",
            "gh",
            "--host",
            "a.com",
            "--query",
            "k",
            "--template",
            "Bearer {secret}",
        ],
        b"valuevalue\n",
    )
    .await;
    assert!(r.err_msg().contains("template"), "{}", r.err_msg());
    assert!(f.log().is_empty(), "no request at all: {:?}", f.log().len());
    assert!(!r.err.contains("created role"));
}

#[tokio::test]
async fn secret_add_with_an_explicit_role_does_not_list_roles() {
    let f = secrets_fake(serde_json::json!([]));
    cli(
        &f,
        &[
            "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--header", "X-Key",
        ],
        b"valuevalue\n",
    )
    .await
    .res
    .unwrap();
    assert!(!f.log().iter().any(|r| r.uri == "/roles"));
}
