//! End-to-end tests: they spawn the real `sc` binary on ephemeral ports.
use assert_cmd::cargo::cargo_bin;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};

const MARKER: &str = "E2E-PLAINTEXT-MARKER";

struct Server {
    child: Child,
    socket: PathBuf,
    data: PathBuf,
    proxy: String,
    login: String,
    key_path: PathBuf,
    stdout: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<String>>,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The socket must live in a 0700 directory, whatever the temp dir defaults are.
fn private_tempdir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn sg_cmd() -> Command {
    let mut c = Command::new(cargo_bin("sc"));
    for v in [
        "SC_SOCKET",
        "SC_KEY_FILE",
        "SC_MASTER_KEY",
        "SC_PROXY_BIND",
        "SC_ADMIN_BIND",
        "SC_UPSTREAM_CA",
        "RUST_LOG",
    ] {
        c.env_remove(v);
    }
    c
}

fn keygen(path: &Path) {
    let out = sg_cmd()
        .args(["keygen", "--out", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

fn start() -> Server {
    start_with("127.0.0.1:0", &[])
}

fn start_with(admin_bind: &str, extra: &[&str]) -> Server {
    let dir = private_tempdir();
    let key = dir.path().join("k.key");
    keygen(&key);
    let socket = dir.path().join("sg.sock");
    // a data dir that does not exist yet, below a parent that does not exist either
    let data = dir.path().join("nested").join("data");
    let mut child = sg_cmd()
        .args([
            "serve",
            "--data-dir",
            data.to_str().unwrap(),
            "--socket",
            socket.to_str().unwrap(),
            "--key-file",
            key.to_str().unwrap(),
            "--proxy-bind",
            "127.0.0.1:0",
            "--admin-bind",
            admin_bind,
        ])
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = mpsc::channel::<String>();
    let (so, out_pipe) = (stdout.clone(), child.stdout.take().unwrap());
    std::thread::spawn(move || {
        for l in BufReader::new(out_pipe).lines().map_while(Result::ok) {
            so.lock().unwrap().push(l.clone());
            let _ = tx.send(l);
        }
    });
    let (se, mut err_pipe) = (stderr.clone(), child.stderr.take().unwrap());
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = err_pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            se.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let (mut proxy, mut login) = (String::new(), String::new());
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let l = rx.recv_timeout(left).unwrap_or_else(|_| {
            panic!(
                "server did not become ready; stderr: {}",
                stderr.lock().unwrap()
            )
        });
        if let Some(r) = l.strip_prefix("proxy: ") {
            proxy = r.into();
        }
        if let Some(r) = l.strip_prefix("admin: ") {
            login = r.into();
        }
        if l == "ready" {
            break;
        }
    }
    assert!(!proxy.is_empty() && !login.is_empty());
    Server {
        child,
        socket,
        data,
        proxy,
        login,
        key_path: key,
        stdout,
        stderr,
        _dir: dir,
    }
}

impl Server {
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn signal(&self, sig: &str) {
        assert!(Command::new("kill")
            .args([&format!("-{sig}"), &self.pid().to_string()])
            .status()
            .unwrap()
            .success());
    }
    fn wait_exit(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < deadline, "server did not exit");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    fn admin_port(&self) -> u16 {
        let rest = self.login.strip_prefix("http://localhost:").unwrap();
        rest.split('/').next().unwrap().parse().unwrap()
    }
    fn login_token(&self) -> String {
        self.login.split("#t=").nth(1).unwrap().trim().to_string()
    }
    fn proxy_addr(&self) -> String {
        self.proxy.strip_prefix("http://").unwrap().to_string()
    }
}

fn sg(s: &Server, args: &[&str], stdin: Option<&str>) -> (bool, String) {
    let mut cmd = sg_cmd();
    cmd.arg("--socket")
        .arg(&s.socket)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    if let Some(i) = stdin {
        child.stdin.take().unwrap().write_all(i.as_bytes()).unwrap();
    } else {
        drop(child.stdin.take());
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Minimal HTTP/1.1 client: one request, `Connection: close`, returns (status, body).
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = String::new();
    let _ = s.read_to_string(&mut raw);
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn login(port: u16, token: &str) -> (u16, String) {
    http(
        port,
        "POST",
        "/login",
        &[("Content-Type", "application/json".into())],
        &format!("{{\"token\":\"{token}\"}}"),
    )
}

fn session_of(body: &str) -> String {
    // {"session":"<id>"}
    body.split("\"session\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_string()
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn machine_token(out: &str) -> String {
    let rest = out.split("HTTPS_PROXY=http://").nth(1).unwrap();
    let after_colon = rest.split_once(':').unwrap().1;
    after_colon.split('@').next().unwrap().to_string()
}

#[test]
fn full_cli_flow_never_echoes_the_secret_and_db_stays_encrypted() {
    let s = start();
    assert!(s.login.contains("/#t="));
    let (ok, url) = sg(&s, &["login-url"], None);
    assert!(ok && url.contains("/#t="), "{url}");
    assert!(
        sg(
            &s,
            &["role", "add", "reviewer", "--unmatched", "deny"],
            None
        )
        .0
    );
    let (ok, out) = sg(
        &s,
        &[
            "secret",
            "add",
            "gh",
            "--role",
            "reviewer",
            "--host",
            "api.github.com",
            "--methods",
            "GET",
            "--header",
            "Authorization",
            "--template",
            "Bearer {secret}",
        ],
        Some(&format!("{MARKER}\n")),
    );
    assert!(ok, "{out}");
    let (ok, ca) = sg(&s, &["ca", "status"], None);
    assert!(ok && ca.contains("api.github.com"), "{ca}");
    let (ok, token_out) = sg(
        &s,
        &[
            "token",
            "create",
            "--machine",
            "laptop",
            "--role",
            "reviewer",
        ],
        None,
    );
    assert!(
        ok && token_out.contains("HTTPS_PROXY=http://laptop:"),
        "{token_out}"
    );
    let mut everything = token_out.clone();
    for args in [
        vec!["secret", "ls"],
        vec!["role", "ls"],
        vec!["rule", "ls"],
        vec!["token", "ls"],
        vec!["ca", "status"],
        vec!["audit"],
        vec!["--json", "secret", "ls"],
    ] {
        everything.push_str(&sg(&s, &args, None).1);
    }
    assert!(!everything.contains(MARKER));
    assert!(
        !sg(
            &s,
            &["secret", "add", "bad", "--role", "reviewer", "--host", "a.com", "--header", "X"],
            Some("x\r\ny\n")
        )
        .0,
        "CRLF values must be refused"
    );
    let (ok, ls) = sg(&s, &["secret", "ls"], None);
    assert!(ok && ls.contains("RULES"), "{ls}");
    assert!(
        sg(&s, &["secret", "rm", "gh"], None).0,
        "removing a secret cascades to its rules"
    );
    assert!(!sg(&s, &["rule", "ls"], None).1.contains("api.github.com"));
    for e in std::fs::read_dir(&s.data).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with("vault.db") {
            let bytes = std::fs::read(e.path()).unwrap();
            assert!(
                !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "{name} holds the secret in clear"
            );
        }
    }
    assert!(s.proxy.starts_with("http://127.0.0.1:"));

    // privacy: nothing sensitive in the server's own output
    let key_text = std::fs::read_to_string(&s.key_path).unwrap();
    let mtoken = machine_token(&token_out);
    let stdout = s.stdout.lock().unwrap().clone();
    let stderr = s.stderr.lock().unwrap().clone();
    for forbidden in [MARKER, key_text.trim(), mtoken.as_str()] {
        assert!(!stderr.contains(forbidden), "stderr leaks {forbidden}");
        assert!(
            !stdout.iter().any(|l| l.contains(forbidden)),
            "stdout leaks {forbidden}"
        );
    }
    let login_token = s.login_token();
    assert!(
        !stderr.contains(&login_token),
        "stderr leaks the login token"
    );
    let minted = url.split("#t=").nth(1).unwrap().trim().to_string();
    assert!(!stderr.contains(&minted));
    assert!(
        stdout.iter().filter(|l| l.contains(&login_token)).count() == 1,
        "the login token is printed exactly once, on the admin line"
    );
    assert!(!stdout.iter().any(|l| l.contains(&minted)));
}

#[test]
fn web_login_flow_works_against_the_live_server() {
    let s = start();
    let port = s.admin_port();
    let token = s.login_token();
    let (st, body) = login(port, &token);
    assert_eq!(st, 200, "{body}");
    let session = session_of(&body);
    let (st, _) = http(port, "GET", "/api/secrets", &[], "");
    assert_eq!(st, 401);
    let (st, body) = http(
        port,
        "GET",
        "/api/secrets",
        &[("Authorization", format!("Bearer {session}"))],
        "",
    );
    assert_eq!(st, 200, "{body}");
    let (st, _) = login(port, &token);
    assert_eq!(st, 401, "a login token is single use");
    // a wrong Host is refused
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    raw.write_all(b"GET /api/secrets HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    let _ = raw.read_to_string(&mut resp);
    assert!(resp.contains(" 421 "), "{resp}");
    // `sc login-url` mints a fresh working token
    let (ok, url) = sg(&s, &["login-url"], None);
    assert!(ok, "{url}");
    let fresh = url.split("#t=").nth(1).unwrap().trim().to_string();
    assert_ne!(fresh, token);
    let (st, _) = login(port, &fresh);
    assert_eq!(st, 200);
}

#[test]
fn key_source_errors_are_clear_and_never_print_the_key() {
    let dir = private_tempdir();
    let data = dir.path().join("data");
    let key_a = dir.path().join("a.key");
    let key_b = dir.path().join("b.key");
    keygen(&key_a);
    keygen(&key_b);
    let sock = dir.path().join("s.sock");
    let serve = |extra: &[&str], envs: &[(&str, &str)]| {
        let mut c = sg_cmd();
        c.args([
            "serve",
            "--data-dir",
            data.to_str().unwrap(),
            "--socket",
            sock.to_str().unwrap(),
        ])
        .args(["--proxy-bind", "127.0.0.1:0", "--admin-bind", "127.0.0.1:0"])
        .args(extra)
        .stdin(Stdio::null());
        for (k, v) in envs {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    let text = |o: &std::process::Output| {
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    };

    // no key source
    let o = serve(&[], &[]);
    assert!(!o.status.success());
    assert!(text(&o).contains("no key source"), "{}", text(&o));
    // two sources
    let o = serve(
        &["--key-file", key_a.to_str().unwrap()],
        &[("SC_MASTER_KEY", "AAAA")],
    );
    assert!(!o.status.success());
    assert!(text(&o).contains("ambiguous"), "{}", text(&o));
    // 0644 key file
    std::fs::set_permissions(&key_b, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = serve(&["--key-file", key_b.to_str().unwrap()], &[]);
    assert!(!o.status.success());
    assert!(text(&o).contains("chmod 600"), "{}", text(&o));
    std::fs::set_permissions(&key_b, std::fs::Permissions::from_mode(0o600)).unwrap();
    // --passphrase without a terminal
    let o = serve(&["--passphrase"], &[]);
    assert!(!o.status.success());
    assert!(text(&o).contains("terminal"), "{}", text(&o));

    // create the vault with key A, then open it with key B
    let mut s = {
        let mut child = sg_cmd()
            .args([
                "serve",
                "--data-dir",
                data.to_str().unwrap(),
                "--socket",
                sock.to_str().unwrap(),
            ])
            .args(["--proxy-bind", "127.0.0.1:0", "--admin-bind", "127.0.0.1:0"])
            .args(["--key-file", key_a.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        while lines.next().unwrap().unwrap() != "ready" {}
        child
    };
    let _ = Command::new("kill")
        .args(["-TERM", &s.id().to_string()])
        .status();
    assert!(s.wait().unwrap().success());
    let o = serve(&["--key-file", key_b.to_str().unwrap()], &[]);
    assert!(!o.status.success());
    let t = text(&o);
    assert!(
        t.contains("could not unlock the vault with the given key source"),
        "{t}"
    );
    let key_b_text = std::fs::read_to_string(&key_b).unwrap();
    assert!(!t.contains(key_b_text.trim()), "{t}");
    // the same vault through SC_MASTER_KEY with the wrong value
    let o = serve(&[], &[("SC_MASTER_KEY", key_b_text.trim())]);
    assert!(!o.status.success());
    assert!(!text(&o).contains(key_b_text.trim()));
    // a corrupt vault file
    std::fs::write(data.join("vault.db"), b"this is not a database at all").unwrap();
    let o = serve(&["--key-file", key_a.to_str().unwrap()], &[]);
    assert!(!o.status.success());
    assert!(!text(&o).contains(std::fs::read_to_string(&key_a).unwrap().trim()));
}

#[test]
fn socket_and_data_dir_are_private() {
    let s = start();
    assert_eq!(mode(&s.socket), 0o600);
    assert_eq!(mode(&s.data), 0o700);
    assert_eq!(
        mode(s.data.parent().unwrap()),
        0o700,
        "created parents are private too"
    );
    assert_eq!(mode(&s.data.join("vault.db")), 0o600);
}

#[test]
fn sigterm_and_sigint_remove_the_socket_and_exit_zero() {
    for sig in ["TERM", "INT"] {
        let mut s = start();
        assert!(s.socket.exists());
        s.signal(sig);
        let status = s.wait_exit();
        assert!(status.success(), "SIG{sig}: {status:?}");
        assert!(!s.socket.exists(), "SIG{sig} must remove the socket");
    }
}

#[test]
fn a_second_instance_on_the_same_dir_fails_without_damaging_the_first() {
    let s = start();
    let out = sg_cmd()
        .args([
            "serve",
            "--data-dir",
            s.data.to_str().unwrap(),
            "--socket",
            s.socket.to_str().unwrap(),
        ])
        .args(["--key-file", s.key_path.to_str().unwrap()])
        .args(["--proxy-bind", "127.0.0.1:0", "--admin-bind", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already running"), "{err}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("ready"));
    assert!(
        s.socket.exists(),
        "the first instance's socket must survive"
    );
    assert!(
        sg(
            &s,
            &["secret", "add", "still-ok", "--host", "a.com", "--header", "X"],
            Some("v\n")
        )
        .0
    );
    assert!(sg(&s, &["secret", "ls"], None).1.contains("still-ok"));
}

#[test]
fn non_loopback_admin_bind_warns_on_stderr_and_hints_the_allowed_host() {
    let s = start_with("0.0.0.0:0", &[]);
    let err = s.stderr.lock().unwrap().clone();
    assert!(err.contains("WARNING"), "{err}");
    assert!(err.contains("no remote login"), "{err}");
    assert!(err.contains("--admin-allowed-host"), "{err}");
    assert!(!s
        .stdout
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.contains("WARNING")));
    // the loopback default prints no warning
    let l = start();
    assert!(!l.stderr.lock().unwrap().contains("WARNING"));
}

#[test]
fn admin_allowed_host_extends_the_host_allowlist() {
    let s = start_with("127.0.0.1:0", &["--admin-allowed-host", "sg.internal:4242"]);
    let port = s.admin_port();
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    raw.write_all(
        b"GET /api/secrets HTTP/1.1\r\nHost: sg.internal:4242\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut resp = String::new();
    let _ = raw.read_to_string(&mut resp);
    assert!(
        resp.contains(" 401 "),
        "allowed host reaches the session guard: {resp}"
    );
}

#[test]
fn the_proxy_and_admin_ports_are_denied_as_connect_targets() {
    for admin_bind in ["127.0.0.1:0", "0.0.0.0:0"] {
        let s = start_with(admin_bind, &[]);
        assert!(
            sg(
                &s,
                &["role", "add", "pt", "--unmatched", "passthrough"],
                None
            )
            .0
        );
        let (ok, out) = sg(
            &s,
            &["token", "create", "--machine", "m1", "--role", "pt"],
            None,
        );
        assert!(ok, "{out}");
        let token = machine_token(&out);
        for target in [s.proxy_addr(), format!("127.0.0.1:{}", s.admin_port())] {
            let mut c = TcpStream::connect(s.proxy_addr()).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            write!(
                c,
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n"
            )
            .unwrap();
            let mut buf = [0u8; 1024];
            let n = c.read(&mut buf).unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                head.starts_with("HTTP/1.1 403"),
                "{admin_bind} {target}: {head}"
            );
        }
        let (_, audit) = sg(&s, &["audit"], None);
        assert!(audit.contains("target-denied"), "{audit}");
    }
}

#[test]
fn admin_public_url_drives_the_printed_and_minted_urls_and_the_host_allowlist() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let bind = format!("127.0.0.1:{port}");
    let s = start_with(&bind, &["--admin-public-url", "http://localhost:12345"]);
    assert!(
        s.login.starts_with("http://localhost:12345/#t="),
        "admin line: {}",
        s.login
    );
    let (ok, url) = sg(&s, &["login-url"], None);
    assert!(
        ok && url.trim().starts_with("http://localhost:12345/#t="),
        "{url}"
    );
    // no --admin-allowed-host needed: the public URL's host:port is accepted
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    raw.write_all(
        b"GET /api/secrets HTTP/1.1\r\nHost: localhost:12345\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut resp = String::new();
    let _ = raw.read_to_string(&mut resp);
    assert!(resp.contains(" 401 "), "Host guard must pass: {resp}");
    // while an unrelated Host is still refused
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    raw.write_all(
        b"GET /api/secrets HTTP/1.1\r\nHost: evil.example:12345\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut resp = String::new();
    let _ = raw.read_to_string(&mut resp);
    assert!(resp.contains(" 421 "), "{resp}");
}

#[test]
fn invalid_admin_public_url_is_refused_at_startup() {
    let dir = private_tempdir();
    let key = dir.path().join("k.key");
    keygen(&key);
    let out = sg_cmd()
        .args(["serve", "--data-dir"])
        .arg(dir.path().join("d"))
        .arg("--socket")
        .arg(dir.path().join("s.sock"))
        .arg("--key-file")
        .arg(&key)
        .args(["--admin-public-url", "http://h:1/path"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--admin-public-url"), "{err}");
}

#[test]
fn an_empty_vault_file_counts_as_a_first_run_and_is_initialised() {
    let dir = private_tempdir();
    let key = dir.path().join("k.key");
    keygen(&key);
    let data = dir.path().join("d");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(data.join("vault.db"), b"").unwrap();
    let mut c = sg_cmd()
        .args(["serve", "--data-dir"])
        .arg(&data)
        .arg("--socket")
        .arg(dir.path().join("s.sock"))
        .arg("--key-file")
        .arg(&key)
        .args(["--proxy-bind", "127.0.0.1:0", "--admin-bind", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(c.stdout.take().unwrap()).lines();
    let mut ready = false;
    for l in lines.by_ref().map_while(Result::ok) {
        if l == "ready" {
            ready = true;
            break;
        }
    }
    let _ = c.kill();
    let _ = c.wait();
    assert!(ready, "serve did not recover from the empty vault file");
    assert!(std::fs::metadata(data.join("vault.db")).unwrap().len() > 0);
}

#[test]
fn help_texts_are_meaningful() {
    let top = sg_cmd().arg("--help").output().unwrap();
    let t = String::from_utf8_lossy(&top.stdout).to_string();
    for needle in [
        "serve",
        "keygen",
        "secret",
        "role",
        "rule",
        "token",
        "ca",
        "audit",
        "login-url",
        "--socket",
        "--json",
    ] {
        assert!(t.contains(needle), "sc --help lacks {needle}:\n{t}");
    }
    assert!(t.contains("SECURITY MODEL") && t.contains("EXAMPLE"), "{t}");
    assert!(
        t.contains("sg.sock") && t.contains("XDG_RUNTIME_DIR"),
        "socket fallback undocumented:\n{t}"
    );
    let serve = sg_cmd().args(["serve", "--help"]).output().unwrap();
    let t = String::from_utf8_lossy(&serve.stdout).to_string();
    for needle in [
        "--data-dir",
        "--proxy-bind",
        "--admin-bind",
        "--key-file",
        "--passphrase",
        "--upstream-ca",
        "--allow-loopback-targets",
        "--admin-allowed-host",
        "--admin-public-url",
        "SC_ADMIN_PUBLIC_URL",
        "SC_MASTER_KEY",
        "SC_KEY_FILE",
    ] {
        assert!(t.contains(needle), "sc serve --help lacks {needle}:\n{t}");
    }
    assert!(!t.contains("RUST_LOG=info"), "nothing logs at info:\n{t}");
    let kg = sg_cmd().args(["keygen", "--help"]).output().unwrap();
    assert!(String::from_utf8_lossy(&kg.stdout).contains("--out"));
}

#[test]
fn keygen_refuses_to_overwrite_and_prints_only_the_path() {
    let dir = private_tempdir();
    let p = dir.path().join("k.key");
    let out = sg_cmd()
        .args(["keygen", "--out", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let key = std::fs::read_to_string(&p).unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains(p.to_str().unwrap()) && text.to_lowercase().contains("back"),
        "{text}"
    );
    assert!(!text.contains(key.trim()));
    assert_eq!(mode(&p), 0o600);
    let again = sg_cmd()
        .args(["keygen", "--out", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        key,
        "existing key untouched"
    );
}
