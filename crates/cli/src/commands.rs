use crate::client::{call_raw, parse_body};
use crate::format::{encode_component as enc, parse_ttl, rfc3339, sanitize, table};
use crate::input::{read_value, secret_body};
use anyhow::{bail, Context};
use bytes::Bytes;
use clap::{Args, Subcommand};
use http::{Method, StatusCode};
use serde_json::{json, Value};
use std::{
    io::{IsTerminal, Read, Write},
    path::Path,
};

/// Options shared by every client command. The `sg` binary flattens this next to
/// [`ClientCommand`]; `--json` is global so it can be given before or after the subcommand.
#[derive(Args, Debug, Clone, Default)]
pub struct ClientOpts {
    /// Print the raw JSON returned by the server instead of tables
    #[arg(long, global = true)]
    pub json: bool,
}

/// The I/O a command works with, injectable for tests.
pub struct Io<'a> {
    pub stdin: &'a mut dyn Read,
    /// Whether stdin is a terminal (hidden prompt instead of reading the pipe).
    pub tty: bool,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

#[derive(Subcommand)]
pub enum ClientCommand {
    /// Manage secrets (values are write-only)
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Manage roles
    #[command(subcommand)]
    Role(RoleCmd),
    /// Manage injection rules
    #[command(subcommand)]
    Rule(RuleCmd),
    /// Manage machine tokens
    #[command(subcommand)]
    Token(TokenCmd),
    /// Manage the certificate authority
    #[command(subcommand)]
    Ca(CaCmd),
    /// Show the audit log
    Audit(AuditArgs),
    /// Print a fresh single-use URL to log in to the web UI (no restart needed)
    LoginUrl,
}

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Add a secret; the value is read from stdin or a hidden prompt, never from arguments
    Add {
        name: String,
        /// Role of the first rule (default: the only role, or a new `default`)
        #[arg(long)]
        role: Option<String>,
        #[command(flatten)]
        target: RuleTarget,
    },
    /// Rotate a secret's value (read from stdin or a hidden prompt)
    Rotate { name: String },
    /// Remove a secret
    Rm { name: String },
    /// List secrets (metadata only)
    Ls,
}

#[derive(Subcommand)]
pub enum RoleCmd {
    /// Create a role
    Add {
        name: String,
        /// What to do with requests no rule matches
        #[arg(long, default_value = "passthrough", value_parser = ["passthrough", "deny"])]
        unmatched: String,
    },
    /// Remove a role
    Rm { name: String },
    /// List roles
    Ls,
}

/// Where and how a secret is injected; shared by `secret add` (first rule) and `rule add`.
#[derive(Args)]
#[command(group(clap::ArgGroup::new("target").required(true).args(["header", "query"])))]
pub struct RuleTarget {
    #[arg(long)]
    host: String,
    #[arg(long, default_value = "*")]
    path: String,
    /// Comma-separated HTTP methods (default: all)
    #[arg(long, value_delimiter = ',')]
    methods: Vec<String>,
    /// Inject into this header
    #[arg(long)]
    header: Option<String>,
    /// Inject into this query parameter (the template must be `{secret}`)
    #[arg(long)]
    query: Option<String>,
    #[arg(long, default_value = "{secret}")]
    template: String,
}

#[derive(Args)]
pub struct RuleAdd {
    #[arg(long)]
    role: String,
    #[command(flatten)]
    target: RuleTarget,
    /// Name of an existing secret
    #[arg(long)]
    secret: String,
}

#[derive(Subcommand)]
pub enum RuleCmd {
    /// Add an injection rule
    Add(RuleAdd),
    /// Remove a rule by id
    Rm { id: i64 },
    /// List rules
    Ls {
        #[arg(long)]
        role: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Issue a token; it is shown once
    Create {
        #[arg(long)]
        machine: String,
        #[arg(long)]
        role: String,
        /// Lifetime: seconds or a duration like 30m, 12h, 7d (max 10 years; omit for no expiry)
        #[arg(long, value_parser = parse_ttl)]
        ttl: Option<u64>,
        /// Address agents use to reach the proxy
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy_url: String,
    },
    /// Revoke one token by id
    Revoke { jti: String },
    /// Revoke every token of a machine
    RevokeMachine { machine: String },
    /// List tokens (metadata only)
    Ls,
}

#[derive(Subcommand)]
pub enum CaCmd {
    /// Print the CA certificate (PEM)
    Export,
    /// Show the domains the CA permits (derived from the rules)
    Status,
}

#[derive(Args)]
pub struct AuditArgs {
    #[arg(long)]
    role: Option<String>,
    #[arg(long)]
    host: Option<String>,
    /// Only entries at or after this Unix timestamp
    #[arg(long)]
    since: Option<i64>,
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(1..=1000))]
    limit: u32,
}

// ---- request helpers -------------------------------------------------------------------------

/// Shorter secret values are never searched for inside server messages.
const MIN_REDACT_LEN: usize = 8;

fn error_message(status: StatusCode, v: &Value, redact: Option<&str>) -> String {
    let mut msg = match v.get("error").and_then(Value::as_str) {
        Some(m) => sanitize(m, 300),
        None => format!("server returned HTTP {status}"),
    };
    if let Some(secret) = redact.filter(|s| !s.is_empty()) {
        if msg.trim() == secret {
            return "[redacted]".to_string();
        }
        // Substring redaction only for values long enough to be secrets: replacing a 1-3 byte
        // value would mangle ordinary words ("exists" for the value "x").
        if secret.len() >= MIN_REDACT_LEN {
            // A server echoing the request body would carry the value raw or JSON-escaped.
            let escaped = serde_json::to_string(secret).unwrap_or_default();
            let escaped = escaped.trim_matches('"');
            msg = msg.replace(secret, "[redacted]");
            if !escaped.is_empty() {
                msg = msg.replace(escaped, "[redacted]");
            }
        }
    }
    msg
}

/// Sends a request and returns the decoded body; non-2xx becomes an error carrying only the
/// server's message. `redact` is a secret value that must never appear in that message.
async fn send(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<Bytes>,
    redact: Option<&str>,
) -> anyhow::Result<Value> {
    let (status, raw) = call_raw(socket, method, path, body).await?;
    let v = parse_body(&raw);
    if !status.is_success() {
        bail!("{}", error_message(status, &v, redact));
    }
    Ok(v)
}

async fn api(
    socket: &Path,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> anyhow::Result<Value> {
    let body = body.map(|b| Bytes::from(b.to_string()));
    send(socket, method, path, body, None).await
}

async fn send_secret(
    socket: &Path,
    method: Method,
    path: &str,
    name: Option<&str>,
    value: &str,
    rules: Option<&Value>,
) -> anyhow::Result<Value> {
    let body = secret_body(name, value, rules)?;
    send(
        socket,
        method,
        path,
        Some(Bytes::from_owner(body)),
        Some(value),
    )
    .await
}

fn print_json(io: &mut Io, v: &Value) -> anyhow::Result<()> {
    writeln!(io.out, "{}", serde_json::to_string_pretty(v)?)?;
    Ok(())
}

/// Prints `msg` in human mode, or the response JSON (when there is one) in `--json` mode.
fn done(io: &mut Io, opts: &ClientOpts, v: &Value, msg: String) -> anyhow::Result<()> {
    if opts.json {
        if !v.is_null() {
            print_json(io, v)?;
        }
    } else {
        writeln!(io.out, "{msg}")?;
    }
    Ok(())
}

fn text(v: &Value, key: &str) -> String {
    match &v[key] {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) if a.is_empty() => "*".into(),
        Value::Array(a) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| x.to_string())
            })
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

fn time(v: &Value, key: &str) -> String {
    v[key].as_i64().map(rfc3339).unwrap_or_else(|| "-".into())
}

fn list_table(
    io: &mut Io,
    opts: &ClientOpts,
    v: &Value,
    headers: &[&str],
    row: impl Fn(&Value) -> Vec<String>,
) -> anyhow::Result<()> {
    if opts.json {
        return print_json(io, v);
    }
    let items = v.as_array().map(Vec::as_slice).unwrap_or_default();
    let rows: Vec<Vec<String>> = items.iter().map(row).collect();
    write!(io.out, "{}", table(headers, &rows))?;
    Ok(())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `http(s)://host:port` -> `(scheme, host:port)`; refuses anything that could smuggle credentials
/// or extra URL parts into the printed proxy address.
fn split_proxy_url(url: &str) -> anyhow::Result<(&str, &str)> {
    let (scheme, rest) = url
        .split_once("://")
        .filter(|(s, _)| matches!(*s, "http" | "https"))
        .context("--proxy-url must start with http:// or https://")?;
    let rest = rest.trim_end_matches('/');
    if rest.is_empty()
        || rest.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '?' | '#' | '\\')
        })
    {
        bail!("--proxy-url must look like http://host:port");
    }
    Ok((scheme, rest))
}

// ---- entry points ----------------------------------------------------------------------------

/// Runs a command with default options and the process's stdio.
pub async fn run(socket: &Path, cmd: ClientCommand) -> anyhow::Result<()> {
    run_with(socket, &ClientOpts::default(), cmd).await
}

/// Runs a command with the process's stdio.
pub async fn run_with(socket: &Path, opts: &ClientOpts, cmd: ClientCommand) -> anyhow::Result<()> {
    let tty = std::io::stdin().is_terminal();
    let (mut stdin, mut stdout, mut stderr) = (
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        std::io::stderr().lock(),
    );
    let mut io = Io {
        stdin: &mut stdin,
        tty,
        out: &mut stdout,
        err: &mut stderr,
    };
    let res = run_io(socket, opts, cmd, &mut io).await;
    let _ = io.out.flush();
    res
}

/// Like [`run_with`] but reports failures as `error: <message>` on stderr and returns the process
/// exit code (0 on success, 1 on failure).
pub async fn run_main(socket: &Path, opts: &ClientOpts, cmd: ClientCommand) -> i32 {
    match run_with(socket, opts, cmd).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    }
}

pub async fn run_io(
    socket: &Path,
    opts: &ClientOpts,
    cmd: ClientCommand,
    io: &mut Io<'_>,
) -> anyhow::Result<()> {
    match cmd {
        ClientCommand::Secret(c) => secret(socket, opts, c, io).await,
        ClientCommand::Role(c) => role(socket, opts, c, io).await,
        ClientCommand::Rule(c) => rule(socket, opts, c, io).await,
        ClientCommand::Token(c) => token(socket, opts, c, io).await,
        ClientCommand::Ca(c) => ca(socket, opts, c, io).await,
        ClientCommand::Audit(a) => audit(socket, opts, a, io).await,
        ClientCommand::LoginUrl => login_url(socket, opts, io).await,
    }
}

/// Wire form of one rule, shared by `secret add` and `rule add`.
fn rule_json(role: &str, t: &RuleTarget) -> anyhow::Result<Value> {
    let (kind, target) = match (&t.header, &t.query) {
        (Some(h), None) => ("header", h.clone()),
        (None, Some(q)) => ("query", q.clone()),
        _ => bail!("use exactly one of --header or --query"),
    };
    if kind == "query" && t.template != "{secret}" {
        bail!(
            "--query injects the bare secret: the template must be `{{secret}}` (got `{}`)",
            t.template
        );
    }
    let methods: Vec<String> = t
        .methods
        .iter()
        .map(|m| m.trim().to_ascii_uppercase())
        .filter(|m| !m.is_empty())
        .collect();
    Ok(json!({
        "role": role, "host_pattern": t.host, "path_pattern": t.path, "methods": methods,
        "kind": kind, "target_name": target, "template": t.template
    }))
}

/// `--role`, else the only existing role, else a new `default`.
async fn resolve_role(
    socket: &Path,
    io: &mut Io<'_>,
    role: Option<String>,
) -> anyhow::Result<String> {
    if let Some(r) = role {
        return Ok(r);
    }
    let roles = api(socket, Method::GET, "/roles", None).await?;
    let names: Vec<String> = roles
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["name"].as_str().map(String::from))
        .collect();
    match names.len() {
        0 => {
            let body = json!({"name": "default", "unmatched": "passthrough"});
            api(socket, Method::POST, "/roles", Some(body)).await?;
            writeln!(
                io.err,
                "note: no role existed, created role 'default' (unmatched = passthrough)"
            )?;
            Ok("default".into())
        }
        1 => Ok(names[0].clone()),
        _ => bail!(
            "several roles exist ({}): choose one with --role",
            names.join(", ")
        ),
    }
}

/// The server's CA notice (agents must reload the certificate), as a warning on stderr.
fn print_notice(io: &mut Io, v: &Value) -> anyhow::Result<()> {
    if let Some(w) = v["notice"].as_str() {
        writeln!(io.err, "warning: {}", sanitize(w, 500))?;
    }
    Ok(())
}

async fn secret(
    socket: &Path,
    opts: &ClientOpts,
    c: SecretCmd,
    io: &mut Io<'_>,
) -> anyhow::Result<()> {
    match c {
        SecretCmd::Add { name, role, target } => {
            let value = read_value(io.stdin, io.tty, true)?;
            let role = resolve_role(socket, io, role).await?;
            let rules = json!([rule_json(&role, &target)?]);
            let v = send_secret(
                socket,
                Method::POST,
                "/secrets",
                Some(&name),
                &value,
                Some(&rules),
            )
            .await?;
            done(
                io,
                opts,
                &v,
                format!("secret '{name}' stored with rule {}", v["rules"][0]["id"]),
            )?;
            print_notice(io, &v)
        }
        SecretCmd::Rotate { name } => {
            let value = read_value(io.stdin, io.tty, false)?;
            let path = format!("/secrets/{}", enc(&name));
            let v = send_secret(socket, Method::PUT, &path, None, &value, None).await?;
            done(io, opts, &v, format!("secret '{name}' rotated"))
        }
        SecretCmd::Rm { name } => {
            let path = format!("/secrets/{}", enc(&name));
            let v = api(socket, Method::DELETE, &path, None).await?;
            done(io, opts, &v, format!("secret '{name}' removed"))
        }
        SecretCmd::Ls => {
            let v = api(socket, Method::GET, "/secrets", None).await?;
            list_table(
                io,
                opts,
                &v,
                &["ID", "NAME", "RULES", "CREATED", "ROTATED"],
                |s| {
                    vec![
                        text(s, "id"),
                        text(s, "name"),
                        text(s, "rules"),
                        time(s, "created_at"),
                        time(s, "rotated_at"),
                    ]
                },
            )
        }
    }
}

async fn role(socket: &Path, opts: &ClientOpts, c: RoleCmd, io: &mut Io<'_>) -> anyhow::Result<()> {
    match c {
        RoleCmd::Add { name, unmatched } => {
            let body = json!({ "name": name, "unmatched": unmatched });
            let v = api(socket, Method::POST, "/roles", Some(body)).await?;
            done(io, opts, &v, format!("role '{name}' created"))
        }
        RoleCmd::Rm { name } => {
            let path = format!("/roles/{}", enc(&name));
            let v = api(socket, Method::DELETE, &path, None).await?;
            done(io, opts, &v, format!("role '{name}' removed"))
        }
        RoleCmd::Ls => {
            let v = api(socket, Method::GET, "/roles", None).await?;
            list_table(io, opts, &v, &["NAME", "UNMATCHED"], |r| {
                vec![text(r, "name"), text(r, "unmatched")]
            })
        }
    }
}

async fn rule(socket: &Path, opts: &ClientOpts, c: RuleCmd, io: &mut Io<'_>) -> anyhow::Result<()> {
    match c {
        RuleCmd::Add(a) => {
            let mut body = rule_json(&a.role, &a.target)?;
            let secrets = api(socket, Method::GET, "/secrets", None).await?;
            let secret_id = secrets
                .as_array()
                .and_then(|l| l.iter().find(|s| s["name"] == a.secret.as_str()))
                .and_then(|s| s["id"].as_i64())
                .with_context(|| format!("secret '{}' not found", a.secret))?;
            body["secret_id"] = json!(secret_id);
            let v = api(socket, Method::POST, "/rules", Some(body)).await?;
            done(io, opts, &v, format!("rule {} created", v["rule"]["id"]))?;
            print_notice(io, &v)
        }
        RuleCmd::Rm { id } => {
            let v = api(socket, Method::DELETE, &format!("/rules/{id}"), None).await?;
            done(io, opts, &v, format!("rule {id} removed"))
        }
        RuleCmd::Ls { role } => {
            let path = match role {
                Some(r) => format!("/rules?role={}", enc(&r)),
                None => "/rules".into(),
            };
            let v = api(socket, Method::GET, &path, None).await?;
            list_table(
                io,
                opts,
                &v,
                &[
                    "ID", "ROLE", "HOST", "PATH", "METHODS", "KIND", "TARGET", "TEMPLATE", "SECRET",
                ],
                |r| {
                    [
                        "id",
                        "role",
                        "host_pattern",
                        "path_pattern",
                        "methods",
                        "kind",
                        "target_name",
                        "template",
                        "secret_id",
                    ]
                    .iter()
                    .map(|k| text(r, k))
                    .collect()
                },
            )
        }
    }
}

async fn token(
    socket: &Path,
    opts: &ClientOpts,
    c: TokenCmd,
    io: &mut Io<'_>,
) -> anyhow::Result<()> {
    match c {
        TokenCmd::Create {
            machine,
            role,
            ttl,
            proxy_url,
        } => {
            let (scheme, hostport) = split_proxy_url(&proxy_url)?;
            let body = json!({ "machine": machine, "role": role, "ttl_secs": ttl });
            let v = api(socket, Method::POST, "/tokens", Some(body)).await?;
            if opts.json {
                return print_json(io, &v);
            }
            let token = v["token"]
                .as_str()
                .filter(|t| !t.is_empty())
                .context("the server did not return a token")?;
            writeln!(io.out, "token (shown once): {token}\n")?;
            writeln!(
                io.out,
                "export HTTPS_PROXY={scheme}://{}:{}@{hostport}",
                enc(&machine),
                enc(token)
            )?;
            writeln!(io.out, "export HTTP_PROXY=$HTTPS_PROXY")?;
            writeln!(io.out, "export NO_PROXY=localhost,127.0.0.1\n")?;
            writeln!(io.out, "# trust the vault CA:")?;
            writeln!(io.out, "sg ca export > sg-ca.pem")?;
            for var in [
                "SSL_CERT_FILE",
                "NODE_EXTRA_CA_CERTS",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
            ] {
                writeln!(io.out, "export {var}=$PWD/sg-ca.pem")?;
            }
            Ok(())
        }
        TokenCmd::Revoke { jti } => {
            let v = api(
                socket,
                Method::DELETE,
                &format!("/tokens/{}", enc(&jti)),
                None,
            )
            .await?;
            done(io, opts, &v, format!("token {jti} revoked"))
        }
        TokenCmd::RevokeMachine { machine } => {
            let path = format!("/machines/{}/revoke", enc(&machine));
            let v = api(socket, Method::POST, &path, None).await?;
            done(
                io,
                opts,
                &v,
                format!("{} token(s) revoked for '{machine}'", v["revoked"]),
            )
        }
        TokenCmd::Ls => {
            let v = api(socket, Method::GET, "/tokens", None).await?;
            let now = now();
            list_table(
                io,
                opts,
                &v,
                &["JTI", "MACHINE", "ROLE", "CREATED", "EXPIRES", "STATUS"],
                |t| {
                    let status = if !t["revoked_at"].is_null() {
                        "revoked"
                    } else if t["expires_at"].as_i64().is_some_and(|e| e <= now) {
                        "expired"
                    } else {
                        "active"
                    };
                    vec![
                        text(t, "jti"),
                        text(t, "machine"),
                        text(t, "role"),
                        time(t, "created_at"),
                        time(t, "expires_at"),
                        status.into(),
                    ]
                },
            )
        }
    }
}

async fn ca(socket: &Path, opts: &ClientOpts, c: CaCmd, io: &mut Io<'_>) -> anyhow::Result<()> {
    match c {
        CaCmd::Export => {
            let (st, raw) = call_raw(socket, Method::GET, "/ca/cert", None).await?;
            if !st.is_success() {
                bail!("{}", error_message(st, &parse_body(&raw), None));
            }
            io.out.write_all(&raw)?;
            Ok(())
        }
        CaCmd::Status => {
            let v = api(socket, Method::GET, "/ca", None).await?;
            if opts.json {
                return print_json(io, &v);
            }
            writeln!(io.out, "permitted domains:")?;
            for d in v["domains"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                writeln!(io.out, "  {}", sanitize(d.as_str().unwrap_or("?"), 253))?;
            }
            Ok(())
        }
    }
}

async fn login_url(socket: &Path, opts: &ClientOpts, io: &mut Io<'_>) -> anyhow::Result<()> {
    let v = api(socket, Method::POST, "/admin/login-token", None).await?;
    let line = v["url"]
        .as_str()
        .or_else(|| v["token"].as_str())
        .ok_or_else(|| anyhow::anyhow!("the vault returned no login token"))?
        .to_owned();
    done(io, opts, &v, line)
}

async fn audit(
    socket: &Path,
    opts: &ClientOpts,
    a: AuditArgs,
    io: &mut Io<'_>,
) -> anyhow::Result<()> {
    let mut q = vec![format!("limit={}", a.limit)];
    if let Some(r) = a.role {
        q.push(format!("role={}", enc(&r)));
    }
    if let Some(h) = a.host {
        q.push(format!("host={}", enc(&h)));
    }
    if let Some(s) = a.since {
        q.push(format!("since={s}"));
    }
    let v = api(
        socket,
        Method::GET,
        &format!("/audit?{}", q.join("&")),
        None,
    )
    .await?;
    list_table(
        io,
        opts,
        &v,
        &[
            "TIME", "MACHINE", "ROLE", "METHOD", "HOST", "PATH", "DECISION", "STATUS", "RULE",
        ],
        |e| {
            vec![
                time(e, "ts"),
                text(e, "machine"),
                text(e, "role"),
                text(e, "method"),
                text(e, "host"),
                text(e, "path"),
                text(e, "decision"),
                text(e, "status"),
                text(e, "rule_id"),
            ]
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrap {
        #[command(flatten)]
        opts: ClientOpts,
        #[command(subcommand)]
        cmd: ClientCommand,
    }

    fn parse<const N: usize>(a: [&str; N]) -> Result<Wrap, clap::Error> {
        Wrap::try_parse_from(a)
    }

    #[test]
    fn rule_add_parses_all_flags() {
        let w = parse([
            "sg",
            "rule",
            "add",
            "--role",
            "reviewer",
            "--host",
            "api.github.com",
            "--path",
            "/repos/*",
            "--methods",
            "GET,HEAD",
            "--header",
            "Authorization",
            "--template",
            "Bearer {secret}",
            "--secret",
            "gh",
        ])
        .unwrap();
        assert!(matches!(w.cmd, ClientCommand::Rule(_)));
    }

    #[test]
    fn rule_needs_header_or_query_but_not_both() {
        assert!(parse([
            "sg",
            "rule",
            "add",
            "--role",
            "r",
            "--host",
            "h.com",
            "--template",
            "{secret}",
            "--secret",
            "s"
        ])
        .is_err());
        assert!(parse([
            "sg",
            "rule",
            "add",
            "--role",
            "r",
            "--host",
            "h.com",
            "--header",
            "A",
            "--query",
            "b",
            "--template",
            "{secret}",
            "--secret",
            "s",
        ])
        .is_err());
    }

    #[test]
    fn secret_add_has_no_value_argument() {
        let add = [
            "sg", "secret", "add", "gh", "--host", "a.com", "--header", "A",
        ];
        assert!(parse(add).is_ok());
        assert!(parse([
            "sg",
            "secret",
            "add",
            "gh",
            "ghp_literal_value",
            "--host",
            "a.com",
            "--header",
            "A"
        ])
        .is_err());
        assert!(parse(["sg", "secret", "rotate", "gh", "ghp_literal_value"]).is_err());
        assert!(parse([
            "sg", "secret", "add", "gh", "--value", "x", "--host", "a.com", "--header", "A"
        ])
        .is_err());
    }

    #[test]
    fn secret_add_requires_a_rule_target_and_a_host() {
        assert!(parse(["sg", "secret", "add", "gh"]).is_err());
        assert!(parse(["sg", "secret", "add", "gh", "--host", "a.com"]).is_err());
        assert!(parse([
            "sg",
            "secret",
            "add",
            "gh",
            "--host",
            "a.com",
            "--header",
            "Authorization",
            "--query",
            "k"
        ])
        .is_err());
        assert!(parse([
            "sg",
            "secret",
            "add",
            "gh",
            "--host",
            "a.com",
            "--header",
            "Authorization"
        ])
        .is_ok());
        assert!(parse([
            "sg", "secret", "add", "gh", "--role", "dev", "--host", "a.com", "--query", "k"
        ])
        .is_ok());
    }

    #[test]
    fn ca_has_no_allow_domain_any_more() {
        assert!(parse(["sg", "ca", "allow-domain", "x.com"]).is_err());
        assert!(parse(["sg", "ca", "status"]).is_ok());
    }

    #[test]
    fn role_unmatched_accepts_only_passthrough_or_deny() {
        assert!(parse(["sg", "role", "add", "r"]).is_ok());
        assert!(parse(["sg", "role", "add", "r", "--unmatched", "deny"]).is_ok());
        assert!(parse(["sg", "role", "add", "r", "--unmatched", "allow"]).is_err());
    }

    #[test]
    fn token_ttl_is_validated_client_side() {
        let ttl = |t: &str| -> Result<Option<u64>, clap::Error> {
            let w = parse([
                "sg",
                "token",
                "create",
                "--machine",
                "m",
                "--role",
                "r",
                "--ttl",
                t,
            ])?;
            match w.cmd {
                ClientCommand::Token(TokenCmd::Create { ttl, .. }) => Ok(ttl),
                _ => unreachable!(),
            }
        };
        assert_eq!(ttl("12h").unwrap(), Some(43_200));
        assert_eq!(ttl("3600").unwrap(), Some(3600));
        assert!(ttl("11y").is_err());
        assert!(ttl("3651d").is_err());
        assert!(ttl("0").is_err());
    }

    #[test]
    fn audit_limit_is_bounded() {
        assert!(parse(["sg", "audit", "--limit", "0"]).is_err());
        assert!(parse(["sg", "audit", "--limit", "1001"]).is_err());
        assert!(parse([
            "sg", "audit", "--limit", "1000", "--role", "r", "--host", "h", "--since", "5"
        ])
        .is_ok());
    }

    #[test]
    fn client_commands_flatten_into_a_larger_cli() {
        #[derive(clap::Subcommand)]
        enum Top {
            Serve,
            #[command(flatten)]
            Client(ClientCommand),
        }
        #[derive(Parser)]
        struct Bin {
            #[command(flatten)]
            opts: ClientOpts,
            #[command(subcommand)]
            cmd: Top,
        }
        let b = Bin::try_parse_from(["sg", "--json", "secret", "ls"]).unwrap();
        assert!(b.opts.json && matches!(b.cmd, Top::Client(ClientCommand::Secret(SecretCmd::Ls))));
        assert!(matches!(
            Bin::try_parse_from(["sg", "serve"]).unwrap().cmd,
            Top::Serve
        ));
    }

    #[test]
    fn json_flag_is_global() {
        assert!(parse(["sg", "--json", "secret", "ls"]).unwrap().opts.json);
        assert!(parse(["sg", "secret", "ls", "--json"]).unwrap().opts.json);
        assert!(!parse(["sg", "secret", "ls"]).unwrap().opts.json);
    }

    #[test]
    fn proxy_url_validation() {
        assert_eq!(
            split_proxy_url("http://127.0.0.1:8080").unwrap(),
            ("http", "127.0.0.1:8080")
        );
        assert_eq!(
            split_proxy_url("https://p.example:1/").unwrap(),
            ("https", "p.example:1")
        );
        for bad in [
            "127.0.0.1:8080",
            "ftp://x",
            "http://",
            "http://u:p@h:1",
            "http://h/path",
            "http://a b",
        ] {
            assert!(split_proxy_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn error_message_redacts_the_value_raw_and_escaped() {
        let v = json!({"error": "bad: {\"value\":\"pass\\\"word\"} and pass\"word"});
        let m = error_message(StatusCode::BAD_REQUEST, &v, Some("pass\"word"));
        assert!(
            !m.contains("pass\"word") && !m.contains("pass\\\"word"),
            "{m}"
        );
    }
}
