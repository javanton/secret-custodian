# Secret Custodian

Secret Custodian (`sc`) is a self-hosted credential vault for AI agents and other untrusted automation. Your agents
make ordinary HTTP(S) requests through a local proxy; the proxy looks up the agent's role, and injects the real API
key into the request on the way out. The agent never holds the key, never sees it, and cannot ask for it. It is one
Rust binary (or one Docker image) with a CLI, an admin API and a small local web UI, and it keeps everything in a
single encrypted SQLite file.

Status: phase 1 is complete and tested (see [Status](#status)). [MIT licensed](LICENSE). Linux only.

## Contents

- [Why](#why)
- [How it works](#how-it-works)
- [Try it](#try-it) — build and run the verified [quickstart](docs/quickstart.md)
- [Install](#install) — pre-built binary, or build from source
- [Configure an agent](#configure-an-agent) — trust the CA, set the proxy ([full guide](docs/operations.md#trusting-the-ca-on-agents))
- [Docker](#docker) ([full guide](docs/operations.md#docker))
- [CLI and web UI](#cli-and-web-ui) ([CLI reference](docs/cli-reference.md), [admin API](docs/admin-api.md))
- [Security and limitations](#security-and-limitations) ([threat model](docs/security-model.md))
- [Documentation index](#documentation-index) — every page, one line each
- [Development](#development), [Status](#status), [License](#license)

## Why

- **Agents never see secrets.** An agent with a prompt-injected instruction cannot leak what it never had. It holds a
  proxy URL and a revocable token; the credential only ever exists inside the vault process, for the duration of one
  request.
- **Compared with handing the agent an API key** (environment variable, config file, `.env`): the key is not in the
  agent's memory, its logs, its prompts, its shell history or its crash dumps; you can scope it per role (GET only, only
  `/repos/*`, only this host), revoke the agent without rotating the key, and see every use in an audit log.
- **Compared with a hosted secrets manager:** nothing leaves your machine, there is no account, no central service and no
  telemetry. Each operator runs their own instance, with no multi-tenancy and no synchronisation between instances.
- **Compared with an SDK or wrapper:** no change to the agent. Anything that honours `HTTPS_PROXY` and a CA bundle
  variable (curl, Python, Node, most agent CLIs) works as is.

The honest limit: an agent that can reach the proxy can do whatever its role allows. The vault keeps it from taking the
secret away and bounds what it can do with it; it does not make a dangerous permission safe. See the
[security model](docs/security-model.md).

## How it works

1. You create a **role** (a policy), store a secret (write-only) **together with its first rule** (host, path, methods, and
   which header or query parameter carries it), add more rules if you need them, then issue a **token** for a `(machine, role)`.
   A secret without a rule could never be injected, so the vault does not allow one.
2. The agent runs with `HTTPS_PROXY=http://machine:TOKEN@vault:8080` and trusts the vault's CA certificate.
3. The agent sends `CONNECT api.example.com:443`. The proxy checks the token, then asks whether the role has rules for that host.
4. With rules, the proxy terminates TLS with a short-lived certificate from a **name-constrained CA** that can only sign
   for the hosts your rules name (the CA's permitted domains are derived from the rules); hosts without rules are tunnelled
   untouched or refused, per role.
5. For every request inside the tunnel the proxy re-checks the token, judges method and path against the rules,
   **removes** any credential the agent supplied, injects the real one and forwards the request over verified TLS.
6. Every decision is written to an audit log (no secrets, no query strings).

```mermaid
flowchart LR
    A["Agent (token + CA)"] -->|"HTTPS_PROXY, CONNECT"| P["sc proxy"]
    P -->|"token valid?"| T["Token check and revocation"]
    P -->|"host, path, method"| R["Vault rules for the role"]
    R -->|"decrypt secret for this request"| V[("Encrypted vault.db")]
    P -->|"real credential over TLS"| U["Upstream API"]
    U -->|"response (streamed)"| P
    P -->|"response"| A
    P -.->|"decision"| L["Audit log"]
```

## Try it

```sh
cargo build --release -p sg
export PATH="$PWD/target/release:$PATH"
sc serve --key-file ~/.config/secret-custodian/sg.key   # first run creates the key (back it up)
```

That prints a `proxy:` address, a one-time `admin:` login link for the web UI, and `ready`. From there: `sc role add`,
`sc secret add` (together with its first rule), `sc token create`, point an agent's `HTTPS_PROXY` at the proxy and
trust its CA ([next section](#configure-an-agent)).

**[docs/quickstart.md](docs/quickstart.md) is the full version**: every command run for real against a local test
upstream, with the exact output, roles with different permissions, a refused request, and the audit log proving the
agent never saw the secret.

## Install

Pre-built binaries are attached to each [GitHub release](https://github.com/javanton/secret-custodian/releases): a
**static Linux x86_64 binary** (musl), so it runs on any Linux distribution, including Alpine and minimal containers.
Other platforms are not built; compile from source (above).

```sh
VERSION=0.1.0   # see the releases page for the latest
BASE="https://github.com/javanton/secret-custodian/releases/download/v$VERSION"
curl -fLO "$BASE/sc-v$VERSION-x86_64-linux.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS                       # must print: sc-v0.1.0-x86_64-linux.tar.gz: OK
tar xzf "sc-v$VERSION-x86_64-linux.tar.gz"
install -m 0755 "sc-v$VERSION-x86_64-linux/sc" ~/.local/bin/sc
```

The binary is named `sc`, not `sg`: most Linux systems already ship an unrelated `/usr/bin/sg` (from shadow-utils:
"run a command with another group"), and `sc` avoids that collision.

The release also publishes a Docker image as `:vX.Y.Z` and `:latest` (see [Docker](#docker)). The checksum file
protects against a corrupted download, not against a compromised release page: for that, build from source and
compare. [docs/releasing.md](docs/releasing.md) documents the pipeline that produces these.

## Configure an agent

Give each agent process three things: the proxy URL with its token, the vault CA certificate, and (if needed) the
proxy variables for plain HTTP. `sc token create` prints exactly this block with your token filled in:

```sh
sc ca export > sg-ca.pem
export HTTPS_PROXY=http://laptop:TOKEN@127.0.0.1:8080
export HTTP_PROXY=$HTTPS_PROXY
export SSL_CERT_FILE=$PWD/sg-ca.pem CURL_CA_BUNDLE=$PWD/sg-ca.pem REQUESTS_CA_BUNDLE=$PWD/sg-ca.pem NODE_EXTRA_CA_CERTS=$PWD/sg-ca.pem
```

Trust is **per process**, via environment variables, not the system store, so the CA only works where you point it.
Re-export it whenever a rule adds a new host. Per-language notes (Python, Node, git, Java, what ignores the proxy
entirely) and the combined-bundle trick for agents that also talk to hosts without rules:
[docs/operations.md#trusting-the-ca-on-agents](docs/operations.md#trusting-the-ca-on-agents).

## Docker

```sh
docker build -t secret-custodian:dev .
```

Runs as uid/gid `10001`, `/data` (mode `0700`) as its volume, ports `8080` (proxy) and `9090` (web UI).
`docker-compose.example.yml` is a ready-to-copy, hardened (read-only, no capabilities, resource limits) setup that
publishes only the web UI to the host. The usual stumbling block is key file permissions (the container user must be
able to read it); full walkthrough, the three ways around it, and using the CLI inside the container:
[docs/operations.md#docker](docs/operations.md#docker).

## CLI and web UI

Every operation is available from the CLI (`sc --help`); the web UI (opened from the `admin:` link or `sc login-url`)
covers the same ground with no build step, no cookies, and a session you trade a one-time token for. **The web UI has
not been verified in a real browser by the authors** — server-side behaviour, static-source checks and its JS logic
are tested, but layout and the interactive flow are not; use the CLI if that matters to you.

- **Full CLI reference** (every flag, default, output, error): [docs/cli-reference.md](docs/cli-reference.md)
- **Admin API** (REST routes, authentication, guards): [docs/admin-api.md](docs/admin-api.md)
- **`sc serve` flags and environment variables**: [docs/operations.md](docs/operations.md) (there is no config file)

## Security and limitations

Guaranteed by design and by tests: no route ever returns a secret value; secrets and the CA/token-signing keys are
AES-256-GCM ciphertext under a key outside the database; the agent's own credential for a rule's target is discarded
and replaced; injection only ever happens over TLS, never plain HTTP; the CA can only sign for hosts your rules name;
the web UI uses no cookies and requires a bearer session.

Read before relying on it: an agent can do whatever its role allows (scope roles narrowly); an origin that echoes
your credential back hands it to the agent; rules don't include the port; no request-body injection or request
signing; no WebSockets; key rotation isn't implemented; single operator, no remote administration; Linux only.

Full threat model, attacker analysis and the complete limitations list: [docs/security-model.md](docs/security-model.md).

## Documentation index

| Page | Contents |
|---|---|
| [docs/README.md](docs/README.md) | Index of the documentation with one-line descriptions |
| [docs/quickstart.md](docs/quickstart.md) | The full verified walkthrough: build, configure, call a real upstream, read the audit log |
| [docs/cli-reference.md](docs/cli-reference.md) | Every command, flag, default, output, exit code and error message |
| [docs/admin-api.md](docs/admin-api.md) | Admin API for the socket and the web listener, authentication, guards |
| [docs/proxy-internals.md](docs/proxy-internals.md) | Request lifecycle, network policy, limits, audit decisions, error responses |
| [docs/security-model.md](docs/security-model.md) | Assets, attackers, mitigations, residual risks, hardening history, checklist |
| [docs/operations.md](docs/operations.md) | Install, permissions, keys, backups, upgrades, systemd, Docker, trusting the CA, troubleshooting |
| [docs/dependency-hygiene.md](docs/dependency-hygiene.md) | `cargo-deny`/`cargo-audit` configuration, what they check, how to run them locally |
| [docs/releasing.md](docs/releasing.md) | CI pipeline, publishing a version, the static binary, package registry and Docker image |
| [docs/testing.md](docs/testing.md) | Test strategy, inventory, end-to-end scripts, known gaps |
| [docs/architecture.md](docs/architecture.md) | Crates, request sequence, concurrency, design decisions |
| [docs/database-schema.md](docs/database-schema.md) | Tables, columns, permissions, WAL, backup |
| [docs/crypto-and-keys.md](docs/crypto-and-keys.md) | Key hierarchy, encryption format, AADs, zeroization, failure modes |
| [docs/policy-and-rules.md](docs/policy-and-rules.md) | Roles, rules, matching, path judging |
| [docs/tokens-and-ca.md](docs/tokens-and-ca.md) | Token format and revocation; the CA and certificates |
| [docs/specs/](docs/specs/2026-10-16-secret-guardian-vault.md), [docs/plans/](docs/plans/2026-10-16-secret-guardian-vault.md) | Design spec and implementation plan (Spanish) |

## Development

Repository layout:

| Path | Package | Role |
|---|---|---|
| `crates/core` | `sg-core` | AES-256-GCM sealing, key derivation, the SQLite vault, schema, secrets, audit, default paths |
| `crates/policy` | `sg-policy` | Roles, rules, host/path/method matching, path normalization and judging, template rendering |
| `crates/auth` | `sg-auth` | EdDSA machine tokens, revocation, `Proxy-Authorization` parsing, the `TokenVerifier` trait |
| `crates/ca` | `sg-ca` | The name-constrained CA, leaf certificates and their cache |
| `crates/proxy` | `sg-proxy` | Proxy listener, CONNECT, MITM TLS, injection, upstream relay, network policy, limits |
| `crates/admin` | `sg-admin` | Admin API (Unix socket and web routers), sessions, guards, embedded web assets |
| `crates/cli` | `sg-cli` | The client commands: argument parsing, the socket client, output formatting |
| `crates/sg` | `sg` | The binary: `serve`, `keygen`, and the assembly of everything |
| `web/` | - | The UI (`index.html`, `app.js`, `style.css`), embedded at build time |
| `fuzz/` | - | `cargo-fuzz` targets for the hostile-input parsers ([docs/fuzzing.md](docs/fuzzing.md)) |
| `scripts/` | - | `e2e.sh` (host) and `e2e-docker.sh` (Docker) end-to-end tests |
| `Dockerfile`, `docker-compose.example.yml` | - | Container packaging |
| `docs/` | - | This documentation, the spec (`docs/specs`) and the plan (`docs/plans`) |

Running the checks (details and inventory in [docs/testing.md](docs/testing.md)):

```sh
cargo test -p sg-policy        # scoped, while developing
cargo test --workspace         # everything, once, before integrating
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo deny check
scripts/e2e.sh                 # real curl through the real proxy
```

The work follows a pipeline: brainstorm, then a **spec** in `docs/specs/` (design, threat model), then a **plan** in
`docs/plans/` (step-by-step, test-driven tasks), then implementation on a branch, verification, review and integration.
Both documents are in Spanish; the other documentation is in English. Where the plan or spec and the code differ, the
code wins, and the reference pages under `docs/` describe the code.

## Status

**Phase 1 is complete:** the encrypted vault, name-constrained CA, header and query injection over TLS, tokens per
(machine, role), rules, audit, the CLI, the admin API with a local web UI, Docker packaging and two end-to-end scripts.

Planned for later phases (from the spec; none of it exists yet): a launcher/sidecar (`sc run`) that keeps the token out of
the agent's reach; authenticating agents by OS process identity instead of a token; OIDC federation as a second token
verifier with per-agent tokens; injection into request bodies and request signing (SigV4 and similar).

## License

[MIT](LICENSE), copyright (c) 2026 Javier Anton.
