use crate::keys::{resolve_key, KeySource};
use anyhow::{anyhow, bail, Context};
use clap::Args;
use rustls::pki_types::CertificateDer;
use sg_admin::{
    allowed_hosts_for, bind_unix, is_loopback_bind, serve_unix_with, serve_web_with,
    AdminServeOptions, AppState, Sessions,
};
use sg_auth::TokenService;
use sg_ca::CaService;
use sg_core::{paths, CoreError, Vault};
use sg_proxy::{serve_with, NetPolicy, ProxyState, ServeOptions, UpstreamConfig};
use std::{
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, task::JoinSet};

/// Port the web UI uses unless told otherwise (and so the one a container publishes).
const STANDARD_ADMIN_PORT: u16 = 9090;

#[derive(Args)]
#[command(after_help = "\
KEY SOURCES (exactly one):
  --key-file <file> / SG_KEY_FILE   base64 of 32 bytes, as written by `sg keygen`; must be mode 0600
  SG_MASTER_KEY                     the same base64 value, environment variable only (never a flag)
  --passphrase                      prompt (twice on first creation); needs a terminal

OUTPUT (stdout, one item per line): `proxy: <url>`, `admin: <login url>`, `socket: <path>`, then
`ready` once every listener is bound. Warnings and logs go to stderr (RUST_LOG=info for more).

Stop with SIGINT or SIGTERM (the socket file is removed); a second SIGINT forces the exit.")]
pub struct ServeArgs {
    /// Directory holding vault.db (created with mode 0700). Default: $XDG_DATA_HOME/secret-guardian
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Address of the credential-injecting proxy
    #[arg(long, env = "SG_PROXY_BIND", default_value = "127.0.0.1:8080")]
    proxy_bind: SocketAddr,
    /// Address of the local web UI. Anything but loopback prints a warning: there is no remote login
    #[arg(long, env = "SG_ADMIN_BIND", default_value = "127.0.0.1:9090")]
    admin_bind: SocketAddr,
    /// Extra Host/Origin accepted by the web UI, e.g. when a container publishes it on another
    /// port (repeatable)
    #[arg(long = "admin-allowed-host", value_name = "HOST:PORT")]
    admin_allowed_host: Vec<String>,
    /// File with the master key (base64 of 32 bytes, as written by `sg keygen`; must be mode 0600)
    #[arg(long, env = "SG_KEY_FILE", value_name = "FILE")]
    key_file: Option<PathBuf>,
    /// Master key as base64 of 32 bytes (environment variable only)
    #[arg(skip)]
    master_key: Option<String>,
    /// Derive the master key from a passphrase typed at a prompt (needs a terminal)
    #[arg(long)]
    passphrase: bool,
    /// Extra PEM CA bundle trusted for upstream TLS (internal services with a private CA);
    /// repeatable
    #[arg(long, env = "SG_UPSTREAM_CA", value_name = "PEM")]
    upstream_ca: Vec<PathBuf>,
    /// Allow the proxy to tunnel/forward to loopback addresses (off by default: SSRF defence).
    /// The proxy's and the admin UI's own ports stay denied either way
    #[arg(long)]
    allow_loopback_targets: bool,
}

impl ServeArgs {
    /// `SG_MASTER_KEY` is read straight from the environment so that its value can never
    /// show up in `--help` or in a clap error message.
    pub fn with_env(mut self) -> Self {
        self.master_key = std::env::var("SG_MASTER_KEY")
            .ok()
            .filter(|v| !v.is_empty());
        self
    }
}

/// The effective uid, read without libc from the owner of `/proc/self`.
fn current_uid() -> anyhow::Result<u32> {
    Ok(std::fs::metadata("/proc/self")
        .context("cannot determine the current user (reading /proc/self)")?
        .uid())
}

/// Creates the data directory (and any missing parents) with mode 0700. An existing directory
/// with looser permissions is tightened when we own it; one we do not own is refused.
pub fn prepare_data_dir(dir: &Path) -> anyhow::Result<()> {
    match std::fs::metadata(dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                bail!("{} exists and is not a directory", dir.display());
            }
            let me = current_uid()?;
            if meta.uid() != me {
                bail!(
                    "refusing to use {} as the data directory: it is owned by uid {}, not by the current user (uid {me})",
                    dir.display(),
                    meta.uid()
                );
            }
            if meta.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("cannot restrict {} to mode 0700", dir.display()))?;
                eprintln!("note: tightened {} to mode 0700", dir.display());
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create the data directory {}", dir.display())),
        Err(e) => Err(e).with_context(|| format!("cannot access {}", dir.display())),
    }
}

fn open_error(e: CoreError) -> anyhow::Error {
    match e {
        CoreError::UnsupportedSchema { .. } => anyhow!("{e}"),
        CoreError::WrongKey
        | CoreError::KeySourceMismatch
        | CoreError::InvalidKey
        | CoreError::Crypto => {
            anyhow!("could not unlock the vault with the given key source")
        }
        other => anyhow!("could not open the vault: {other}"),
    }
}

fn load_roots(files: &[PathBuf]) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut roots = Vec::new();
    for p in files {
        let pem = std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?;
        let mut found = 0;
        for c in rustls_pemfile::certs(&mut pem.as_slice()) {
            roots.push(c.with_context(|| format!("{} is not valid PEM", p.display()))?);
            found += 1;
        }
        if found == 0 {
            bail!("{} contains no PEM certificate", p.display());
        }
    }
    Ok(roots)
}

pub async fn run(args: ServeArgs, socket: PathBuf) -> anyhow::Result<()> {
    let args = args.with_env();
    let data_dir = args
        .data_dir
        .clone()
        .unwrap_or_else(paths::default_data_dir);
    prepare_data_dir(&data_dir)?;

    // Fail fast, before touching the vault or prompting: a live instance owns the socket.
    // `bind_unix` checks the directory and refuses a socket someone accepts connections on;
    // the probe socket is removed again so that `serve_unix_with` creates the real one.
    drop(bind_unix(&socket).await.map_err(|e| anyhow!("{e}"))?);
    let _ = std::fs::remove_file(&socket);

    let db = data_dir.join("vault.db");
    let first_run = Vault::needs_init(&db);
    let key = resolve_key(
        &KeySource {
            key_file: args.key_file.clone(),
            master_key: args.master_key.clone(),
            passphrase: args.passphrase,
        },
        first_run,
    )?;
    let vault = Arc::new(Vault::open_or_init(&db, key).map_err(open_error)?);
    let tokens =
        Arc::new(TokenService::new(vault.clone()).context("cannot load the token service")?);
    let ca = Arc::new(CaService::init_or_load(vault.clone()).context("cannot load the CA")?);
    let roots = load_roots(&args.upstream_ca)?;

    let proxy_listener = TcpListener::bind(args.proxy_bind)
        .await
        .with_context(|| format!("cannot bind the proxy address {}", args.proxy_bind))?;
    let admin_listener = TcpListener::bind(args.admin_bind)
        .await
        .with_context(|| format!("cannot bind the admin address {}", args.admin_bind))?;
    let proxy_addr = proxy_listener.local_addr()?;
    let admin_addr = admin_listener.local_addr()?;

    // The proxy and admin addresses (as actually bound) are never valid tunnel/forward targets.
    let mut upstream = UpstreamConfig::new(roots);
    upstream.net_policy = NetPolicy::new(NetPolicy::denied_for_binds(&[proxy_addr, admin_addr]))
        .with_allow_loopback(args.allow_loopback_targets);
    upstream.max_upstream_connections = upstream.max_upstream_connections.max(1);
    let proxy_state = Arc::new(ProxyState {
        vault: vault.clone(),
        verifier: tokens.clone(),
        ca: ca.clone(),
        upstream,
    });

    if !is_loopback_bind(admin_addr) {
        eprintln!(
            "WARNING: the admin interface is bound to {admin_addr}, which is not loopback. There is no remote login in this version: publish it only to 127.0.0.1 of the host."
        );
        if args.admin_allowed_host.is_empty() && admin_addr.port() != STANDARD_ADMIN_PORT {
            eprintln!(
                "hint: the web UI only accepts Host values for port {}; if it is published on another port, add --admin-allowed-host <host:port>.",
                admin_addr.port()
            );
        }
    }

    let sessions = Arc::new(Sessions::new());
    let login = sessions.new_login_token();
    let mut allowed_hosts = allowed_hosts_for(admin_addr);
    allowed_hosts.extend(args.admin_allowed_host.iter().cloned());
    let app = AppState {
        vault,
        tokens,
        ca,
        sessions,
        allowed_hosts,
        web_base_url: Some(format!("http://localhost:{}", admin_addr.port())),
    };

    // Signal handlers first, so a signal during start-up is not lost.
    let mut signals = Signals::new()?;

    let mut tasks: JoinSet<(&'static str, std::io::Result<()>)> = JoinSet::new();
    tasks.spawn(async move {
        (
            "proxy",
            serve_with(proxy_listener, proxy_state, ServeOptions::default()).await,
        )
    });
    let web_app = app.clone();
    tasks.spawn(async move {
        (
            "web admin",
            serve_web_with(admin_listener, web_app, AdminServeOptions::default()).await,
        )
    });
    let sock_path = socket.clone();
    tasks.spawn(async move {
        (
            "admin socket",
            serve_unix_with(&sock_path, app, AdminServeOptions::default()).await,
        )
    });

    // Ready once the socket exists; a task that already ended means start-up failed.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(done) = tasks.try_join_next() {
            let msg = describe(done);
            tasks.abort_all();
            return Err(anyhow!(msg));
        }
        // the socket is chmod 0600 right after it is bound: wait for that too
        if std::fs::symlink_metadata(&socket)
            .is_ok_and(|m| m.file_type().is_socket() && m.permissions().mode() & 0o777 == 0o600)
        {
            break;
        }
        if Instant::now() > deadline {
            tasks.abort_all();
            bail!("the admin socket {} did not come up", socket.display());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("proxy: http://{proxy_addr}");
    println!("admin: http://localhost:{}/#t={login}", admin_addr.port());
    println!("socket: {}", socket.display());
    println!("ready");

    let result = tokio::select! {
        _ = signals.first() => Ok(()),
        done = tasks.join_next() => match done {
            Some(d) => Err(anyhow!(describe(d))),
            None => Ok(()),
        },
    };
    // From here a second signal forces the exit.
    tokio::spawn(async move {
        signals.first().await;
        std::process::exit(130);
    });
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // we bound it (start-up only succeeds once our own socket exists)
    let _ = std::fs::remove_file(&socket);
    result
}

fn describe(done: Result<(&'static str, std::io::Result<()>), tokio::task::JoinError>) -> String {
    match done {
        Ok((name, Ok(()))) => format!("{name} stopped unexpectedly"),
        Ok((name, Err(e))) => format!("{name} failed: {e}"),
        Err(e) => format!("a server task failed: {e}"),
    }
}

struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    /// Resolves on the next SIGINT or SIGTERM.
    async fn first(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn missing_data_dir_and_parents_are_created_private() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("a").join("b").join("data");
        prepare_data_dir(&d).unwrap();
        assert_eq!(mode(&d), 0o700);
        assert_eq!(mode(d.parent().unwrap()), 0o700);
        assert_eq!(mode(&t.path().join("a")), 0o700);
    }

    #[test]
    fn loose_data_dir_we_own_is_tightened() {
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_data_dir(t.path()).unwrap();
        assert_eq!(mode(t.path()), 0o700);
    }

    #[test]
    fn a_file_in_place_of_the_data_dir_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("f");
        std::fs::write(&f, "x").unwrap();
        assert!(prepare_data_dir(&f).is_err());
    }

    #[test]
    fn open_errors_are_non_leaky_but_schema_is_shown() {
        let e = open_error(CoreError::WrongKey).to_string();
        assert_eq!(e, "could not unlock the vault with the given key source");
        let e = open_error(CoreError::UnsupportedSchema {
            found: 9,
            supported: 1,
        })
        .to_string();
        assert!(e.contains("schema version 9"), "{e}");
    }
}
