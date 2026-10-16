mod keys;
mod serve;

use clap::{Parser, Subcommand};
use sg_cli::{ClientCommand, ClientOpts};
use std::{path::PathBuf, process::ExitCode};

const LONG_ABOUT: &str = "\
Secret Guardian is a local credential vault for AI agents. Its proxy injects credentials into \
requests according to the role of the agent's token, so the agent never sees the secret.";

const AFTER_HELP: &str = "\
SECURITY MODEL
  * Secrets are encrypted at rest (AES-256-GCM) under a key that never lives in the database.
  * No command, API or web page ever returns a stored secret value; values are write-only.
  * Agents authenticate to the proxy with a per-machine token bound to a role; the proxy
    injects only what that role's rules allow, over TLS, and denies everything else.
  * The proxy re-signs HTTPS with a local CA restricted (name constraints) to the domains you
    allow; install its certificate only where the agent runs.
  * The admin socket is mode 0600 and the web UI listens on 127.0.0.1 behind one-time logins.

KEY SOURCES (for `sg serve`)
  --key-file <file>   base64 of 32 bytes (create one with `sg keygen --out <file>`), or SG_KEY_FILE
  SG_MASTER_KEY       the same base64 value in the environment
  --passphrase        derive the key from a passphrase typed at a prompt

EXAMPLE WORKFLOW
  sg keygen --out ~/.config/sg.key            # once; back this file up
  sg serve --key-file ~/.config/sg.key &      # prints the proxy address and the web login URL
  echo -n \"$GITHUB_TOKEN\" | sg secret add gh # value from stdin, never from arguments
  sg role add reviewer --unmatched deny
  sg ca allow-domain github.com
  sg rule add --role reviewer --host api.github.com --methods GET \\
      --header Authorization --template 'Bearer {secret}' --secret gh
  sg token create --machine laptop --role reviewer   # prints the HTTPS_PROXY line for the agent
  sg login-url                                 # a fresh link to the web UI";

#[derive(Parser)]
#[command(
    name = "sg",
    version,
    about = "Secret Guardian: a vault whose proxy injects credentials so agents never see them",
    long_about = LONG_ABOUT,
    after_long_help = AFTER_HELP,
    after_help = AFTER_HELP
)]
struct Cli {
    /// Admin socket of a running `sg serve` (default: $XDG_RUNTIME_DIR/secret-guardian.sock)
    #[arg(long, global = true, env = "SG_SOCKET", value_name = "PATH")]
    socket: Option<PathBuf>,
    #[command(flatten)]
    opts: ClientOpts,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the vault: proxy, admin socket and local web UI
    Serve(serve::ServeArgs),
    /// Generate a random master key file (mode 0600, never overwrites)
    Keygen {
        /// File to create; it must not exist yet
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    #[command(flatten)]
    Client(ClientCommand),
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let socket = cli.socket.unwrap_or_else(sg_core::paths::default_socket);
    match cli.command {
        Command::Serve(args) => match serve::run(args, socket).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        Command::Keygen { out } => match keys::write_new_key_file(&out) {
            Ok(()) => {
                println!("wrote {}", out.display());
                println!("Back this file up: without it the vault cannot be opened.");
                ExitCode::SUCCESS
            }
            Err(e) => fail(e),
        },
        Command::Client(cmd) => {
            if sg_cli::run_main(&socket, &cli.opts, cmd).await == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn fail(e: anyhow::Error) -> ExitCode {
    eprintln!("error: {e:#}");
    ExitCode::FAILURE
}
