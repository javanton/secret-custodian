# Operations guide

Installing, running and looking after a Secret Custodian instance. Commands were run against the real binary;
the symptoms in the [troubleshooting table](#troubleshooting) were provoked on purpose and the messages copied.
Sections: [Installing](#installing) · [Directories and permissions](#directories-and-permissions) ·
[Key management](#key-management) · [Backups](#backups) · [Upgrades](#upgrades) (including the [rules migration](#upgrading-from-a-version-without-required-rules)) ·
[systemd user service](#running-as-a-systemd-user-service) · [Containers and networking](#containers-and-networking) ·
[Trusting the CA on agents](#trusting-the-ca-on-agents) · [Routine tasks](#routine-tasks) ·
[Observability](#observability) · [Troubleshooting](#troubleshooting)

## Installing

### From source

Requirements: a Rust toolchain (the repository pins `stable` in `rust-toolchain.toml`, so `rustup` installs it on first
use) and a C compiler (SQLite is bundled and compiled). The end-to-end script also needs `curl`, `openssl` and
`python3`; the Docker image needs only Docker.

```sh
git clone <your clone URL> secret-custodian && cd secret-custodian
cargo build --release -p sg --locked        # binary: target/release/sg
install -m 0755 target/release/sg ~/.local/bin/sg
sg --version                                # sg 0.1.0
```

Or let cargo install it (`cargo install --path crates/sg --locked` puts it in `~/.cargo/bin`).
A release build takes about three minutes on a laptop.

The result is a single binary (about 13 MB) with the web UI embedded; apart from the system C library it needs nothing
else at run time.

### Docker

`docker build -t secret-custodian:dev .` produces a Debian-slim image that runs as uid/gid `10001`, with `/data` (mode
`0700`) as the volume, ports `8080` (proxy) and `9090` (web UI) exposed, `SG_SOCKET=/data/sg.sock` preset so that
`docker exec <ctr> sg ...` works with no flags, and a health check that runs `sg ca status`. The default command is
`serve --data-dir /data --socket /data/sg.sock --key-file /run/secrets/sg_key --proxy-bind 0.0.0.0:8080 --admin-bind 0.0.0.0:9090`.
`SIGTERM` stops it cleanly (exit code 0).

**The key.** The default command reads the key from `/run/secrets/sg_key`. The file must be mode `0600` or `0400` and
**readable by uid 10001**. This is the usual stumbling block: a Docker secret or bind mount of a host file keeps the
host file's owner, so a key you created with your own uid is refused (verified):

```
error: cannot read key file /run/secrets/sg_key: Permission denied (os error 13)
```

Three ways out (the first and third were run):

```sh
# 1. generate the key inside a volume, owned by uid 10001, and mount that volume at /run/secrets
docker volume create sg-key
docker run --rm --user 0 --entrypoint sh -v sg-key:/k secret-custodian:dev \
  -c 'sg keygen --out /k/sg_key && chown 10001:10001 /k/sg_key && chmod 0400 /k/sg_key'
docker run -d --name secret-custodian --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:9090:9090 -v sg-key:/run/secrets:ro -v sg-data:/data secret-custodian:dev

# 2. (compose example's route, needs root, not run here) chown the host file to the container user
sudo chown 10001:10001 sg.key && sudo chmod 0400 sg.key

# 3. no file at all: SG_MASTER_KEY (the same base64 value) and override the command without --key-file
docker run -d --name secret-custodian -e SG_MASTER_KEY="$(cat sg.key)" -p 127.0.0.1:9090:9090 -v sg-data:/data \
  secret-custodian:dev serve --data-dir /data --socket /data/sg.sock \
  --proxy-bind 0.0.0.0:8080 --admin-bind 0.0.0.0:9090
```

Environment variables are visible in `docker inspect`; prefer the file. **Back the key up outside Docker**; losing it
loses every secret. (Note: `docker run -v "$PWD":/out ... keygen --out /out/sg.key` fails with `Permission denied`
unless that host directory is writable by uid 10001. Run `sg keygen` on the host, or use route 1.)

**Compose.** Copy `docker-compose.example.yml` to `docker-compose.yml`, put the key where it says, and
`docker compose up -d --build`. It builds the image, publishes the web UI on `127.0.0.1:9090` of the host only, does
**not** publish the proxy (agents reach it as `http://secret-custodian:8080` over an internal Docker network with no
internet route), and runs read-only, without capabilities, with resource limits. The file validates with
`docker compose config`.

**Using it.** The CLI runs inside the container over the in-container socket:

```sh
docker compose exec secret-custodian sg secret ls
printf %s "$GITHUB_TOKEN" | docker compose exec -T secret-custodian sg secret add github
docker compose exec secret-custodian sg token create --machine agent1 --role reviewer --proxy-url http://secret-custodian:8080
docker compose exec secret-custodian sg ca export > sg-ca.pem
docker compose exec secret-custodian sg login-url
```

`sg login-url` prints `http://localhost:9090/#t=...`; open it in a browser on the Docker host. The URL names the port
the process bound *inside* the container, so if you publish the UI on a different host port, add
`--admin-public-url http://localhost:<hostport>` to the command (or set `SG_ADMIN_PUBLIC_URL`): `sg login-url` and
the `admin:` line then print that URL and its host:port is accepted as `Host`/`Origin` (otherwise the UI answers
`421 unexpected Host header`). The container logs `WARNING: the admin interface is bound to 0.0.0.0:9090` at start:
expected, because there is no remote login and the port must stay published to `127.0.0.1` only. More in
[Containers and networking](#containers-and-networking) below.

## Directories and permissions

| Path | Mode | Owner | Why it matters |
|---|---|---|---|
| Data directory (default `$XDG_DATA_HOME/secret-custodian`, else `~/.local/share/secret-custodian`) | `0700` | the server's user | Holds the database. `sg serve` creates it `0700` (and missing parents), tightens a looser directory you own (printing `note: tightened ... to mode 0700`) and refuses one owned by someone else |
| `vault.db`, `vault.db-wal`, `vault.db-shm` | `0600` | the server's user | Ciphertext plus plaintext metadata (rule hosts, names, audit). The main file is created `0600` before SQLite opens it; SQLite gives the sidecar files the same mode |
| Key file | `0600` (**enforced**: any group/other bit is refused) | the server's user | The master key. Anyone who can read it plus the database owns all secrets |
| Admin socket (default `$XDG_RUNTIME_DIR/secret-custodian.sock`, else `<data dir>/sg.sock`) | socket `0600` in a directory that is `0700` and owned by the server's user | the server's user | The socket **is** the admin credential. The server refuses to create it in a directory open to others, and the CLI refuses to use one |
| Exported CA certificate (`sg ca export`) | anything | - | Public; distribute freely, but only to the agents that need it |

Logging: warnings and errors go to stderr (default `RUST_LOG=warn`); only connection-level `debug` events exist beyond
that, nothing is logged at `info`. First-run detection: `sg serve` treats a missing, empty or table-less `vault.db` (what a
crashed first start leaves behind) as uninitialised, removes the leftovers and initialises again, so the passphrase is asked
twice in that case; a database with tables but no `meta` row is reported as corrupt, never silently replaced.

Why `XDG_RUNTIME_DIR` by default: it is `0700`, per user and cleaned at logout. If it is not set the fallback is
inside the data directory (already `0700`). A shared directory such as `/tmp` is refused unless it is a private
subdirectory you created with `chmod 700`.

In a container the same rules hold: `/data` must be `0700`, owned by uid 10001 (the image does this), because the socket
lives there.

## Key management

The **master key** protects a random data key, which protects every secret, the token signing key and the CA key
(see [crypto-and-keys.md](crypto-and-keys.md)). Choose exactly one source per vault; the vault remembers which kind it
was created with.

| Source | How | Notes |
|---|---|---|
| Key file | `sg keygen --out ~/.config/secret-custodian/sg.key` once, then `sg serve --key-file <file>` (or `SG_KEY_FILE`) | Base64 of 32 random bytes, mode `0600`. Best for services and containers (Docker secret) |
| Environment variable | `SG_MASTER_KEY=<same base64>` | Never a flag (flags show up in `ps`). Visible to the same user via `/proc/<pid>/environ`, and in `docker inspect` (verified). Prefer the file route |
| Passphrase | `sg serve --passphrase` | Argon2id-derived. Prompted on every start (twice the first time), so it cannot run unattended; strength is the passphrase's |

Facts you should plan around:

- **Back the key up separately from the database.** The database alone reveals no secret; the key alone is useless
  without it; together they are everything. Losing the key means losing every stored secret: there is no recovery
  path and no master password reset. You would re-create the vault and re-enter each secret.
- **The key cannot be changed.** Rotation of the master key, the data key, the token signing key and the CA key is
  **not implemented** (the design allows re-wrapping the data key cheaply, but no command does it). The same goes
  for switching between a key file and a passphrase. If you must change the key, create a new vault (new
  `--data-dir`), re-add secrets, roles, rules and tokens, re-export the new CA to the agents, and delete the old vault.
- A key file is the same bytes as `SG_MASTER_KEY`: `SG_MASTER_KEY=$(cat sg.key)` works.
- Errors never print key material; a wrong key, wrong kind of key and a damaged vault all give
  `could not unlock the vault with the given key source`.

## Backups

What to back up: **the database and the key source, stored separately.** The CA certificate and signing key are inside
the database; restoring a database restores tokens, rules, audit and the CA (agents do not need a new certificate, and
issued tokens stay valid subject to expiry and revocation).

The database runs in WAL mode, so the consistent state is `vault.db` **plus** `vault.db-wal`. A raw copy of only
`vault.db` while the server runs is not a backup: on a freshly started server `vault.db` was 4096 bytes while its
`-wal` was 70 KB, holding everything. Safe ways:

1. **Stop the server, copy the three files** (`vault.db*`) with their `0600` modes, restart.
2. **Online backup through SQLite's backup API** (safe while the server runs). `sqlite3` is not installed on every
   machine; Python's standard library has the same API, and this is the command that was run and tested:

   ```sh
   python3 - <<'EOF'
   import sqlite3
   src = sqlite3.connect("file:/path/to/data/vault.db?mode=ro", uri=True)
   dst = sqlite3.connect("/path/to/backup/vault.db")
   src.backup(dst); dst.close(); src.close()
   EOF
   chmod 600 /path/to/backup/vault.db        # the new file gets your umask (0644 here), so tighten it
   ```

   With the `sqlite3` command-line tool the equivalent is `sqlite3 /path/to/data/vault.db ".backup /path/to/backup/vault.db"`
   (the same backup API; the CLI itself was not available on the machine used for this guide, so that line is untested).
   The result is a single self-contained file (the backup of a live vault restored fine: secrets, tokens and the exact
   same CA certificate were present).

Restore: stop the server, put the backup at `<data dir>/vault.db` (mode `0600`, directory `0700`, no stale `-wal`/`-shm`
files), start with the same key source. Test a restore before you need it.

Read-only inspection of a live database also works (`sqlite3.connect("file:...vault.db?mode=ro", uri=True)`), but
remember it holds plaintext metadata.

**Pruning the audit log** (there is no built-in retention): stop the server, then for example
`DELETE FROM audit WHERE ts < <unix time>; VACUUM;` through SQLite, and start it again (tested on a copy; the vault
opened normally). Do this only with the server stopped.

## Upgrades

- The database has a schema version (`1` today), checked **after** the key is verified. A vault written by a build with a
  different schema version is refused with:

  ```
  error: database schema version 99 is not supported by this build (supports 1)
  ```

  (This message was provoked by editing `meta.schema_version` in a copy.) There is no migration framework, so a build that
  changes the schema would need to bring its own migration; until one exists no upgrade path is promised.
- Always take a [backup](#backups) before replacing the binary, and keep the previous binary.
- Source: `git pull`, `cargo build --release -p sg --locked`, replace the binary, restart (`systemctl --user restart
  secret-custodian`). Agents see the proxy disappear for a moment; open tunnels are dropped, and tokens, CA and rules
  persist.
- Docker: rebuild the image, `docker compose up -d --build`; the named volume keeps the data and the key stays a
  secret. `docker stop` sends `SIGTERM` and the server exits cleanly within seconds.

### Upgrading from a version without required rules

Older builds let you store a secret with no rule and widen the CA
by hand (`sg ca allow-domain`). The schema did not change, so no migration runs, but on **every** start `sg serve`
makes the CA's permitted domains equal to the set derived from the rules, once (it logs `CA domains re-derived from the
rules; agents must reload the CA certificate` at `warn` level, so it shows with the default log level, when that changed the CA). Rule hosts the CA cannot accept (rows stored by older builds, for example with `_` in a label or under `.invalid`) are skipped with a `warn` line naming them, so startup never fails because of them: those hosts are simply not interceptable until the rule is fixed. Consequences on the first start
after the upgrade:

- Domains that were allowed by hand and that no rule uses are **dropped** from the CA; hosts that rules need but the CA
  did not permit are added. The CA certificate is re-issued (same key) if the set changed, so agents must reload it
  (`sg ca export`). A second start changes nothing.
- Secrets created before the change that have no rules **keep existing** and stay valid, but they are never injected;
  the web UI marks them "none: never injected" and `sg secret ls` shows `RULES 0`. Give them a rule with `sg rule add`
  or delete them. (You cannot recreate that state with the current commands.)
- Nothing else changes: tokens, roles and existing rules are untouched. There is no `sg ca allow-domain` and no
  `POST /ca/domains` any more; scripts that called them must create the secret with its first rule
  (`sg secret add NAME --role R --host H --header N`).

## Running as a systemd user service

A user service keeps the vault running under your login (and, with lingering, without being logged in), uses
`$XDG_RUNTIME_DIR` for the socket and the default data directory, and gives you `journalctl --user`.

```ini
# ~/.config/systemd/user/secret-custodian.service
[Unit]
Description=Secret Custodian vault (credential-injecting proxy)
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/sg serve --key-file %h/.config/secret-custodian/sg.key
Restart=on-failure
RestartSec=2
# Files the service creates are private to the user.
UMask=0077
# stdout carries the one-time web login URL; keep it out of the journal and use `sg login-url` instead.
# Warnings and errors go to stderr and into the journal.
StandardOutput=null
StandardError=journal
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

[Install]
WantedBy=default.target
```

Set-up:

```sh
mkdir -p ~/.config/secret-custodian ~/.local/bin ~/.config/systemd/user
chmod 700 ~/.config/secret-custodian
install -m 0755 target/release/sg ~/.local/bin/sg
sg keygen --out ~/.config/secret-custodian/sg.key
# write the unit file above, then:
systemctl --user daemon-reload
systemctl --user enable --now secret-custodian
sg ca status                      # works without flags: XDG_RUNTIME_DIR is set for user services
sg login-url
loginctl enable-linger "$USER"    # optional: keep running when logged out
```

What was validated: `systemd-analyze --user verify` accepts this unit (with `ExecStart` pointing at an existing binary,
since `verify` checks that), and a transient service run with `systemd-run --user` using the same
`UMask`, `StandardOutput=null`, `NoNewPrivileges`, `RestrictAddressFamilies`, `LockPersonality`,
`MemoryDenyWriteExecute`, `RestrictRealtime` and `Restart` properties started the server, created the data
directory and the socket with the expected `0700`/`0600` modes, served `sg ca status` and `sg login-url`, and stopped
cleanly. The unit file itself was not enabled on a real login (that would touch the real user configuration), and
`PrivateTmp=` and the `Protect*=` filesystem sandboxing options were deliberately left out because they were not tested
with the data directory under `$HOME`. Treat the sandboxing lines as a starting point.

If the data directory or socket location differs, add `--data-dir` and `--socket` to `ExecStart`. Use a system-wide
service (`/etc/systemd/system`) only with a dedicated service user and its own `0700` directories; the user-service
route is simpler.

## Containers and networking

The shape of the provided `docker-compose.example.yml`:

```mermaid
flowchart LR
    subgraph hostns["Host"]
        BR["Browser (http://localhost:9090)"]
    end
    subgraph agents["Docker network: agents (internal, no internet)"]
        AG["Agent container"]
    end
    subgraph egress["Docker network: egress"]
        SG["secret-custodian container"]
    end
    NET["Upstream APIs"]

    AG -- "http://secret-custodian:8080 with token" --> SG
    SG --> NET
    BR -- "127.0.0.1:9090 only" --> SG
```

- The **proxy** (8080) is not published to the host; agent containers reach it as `http://secret-custodian:8080` over an
  `internal` Docker network that has no route to the internet, so the proxy is the only way out. Create tokens with
  `--proxy-url http://secret-custodian:8080` so the printed `HTTPS_PROXY` line is right.
- The **web UI** (9090) is published to `127.0.0.1:9090` of the host only. Both ports live in the same container, so an
  agent on the `agents` network *can* reach `secret-custodian:9090`; that is why the proxy refuses to relay to its own
  ports, the UI checks `Host`/`Origin` and everything needs a one-time login token. Do not publish 9090 on any other
  interface.
- If you publish the UI on another host port (`-p 127.0.0.1:19090:9090`) add `--admin-public-url http://localhost:19090`
  (or `SG_ADMIN_PUBLIC_URL`): the `admin:` line and `sg login-url` then print that URL and its host:port joins the
  `Host`/`Origin` allowlist, so `--admin-allowed-host` is only needed for additional names. The web listener is plain HTTP and
  `Origin` must be `http://<allowed host>`, so `--admin-public-url` rejects `https://` URLs at start-up (a TLS-terminating
  reverse proxy in front of the UI is not supported: browser writes would carry an `https://` `Origin` and be refused).
- Run the CLI inside the container: `docker compose exec secret-custodian sg secret ls`; secrets via
  `printf %s "$TOKEN" | docker compose exec -T secret-custodian sg secret add github`.
- Hardening used by the example and verified by the Docker end-to-end script: read-only root filesystem, `tmpfs`
  `/tmp`, `cap_drop: [ALL]`, `no-new-privileges`, resource limits, non-root uid 10001.
- **Key delivery pitfall.** The default command reads `/run/secrets/sg_key`. A Docker secret (or any bind mount) of a
  host file keeps the host file's owner and mode; the server demands mode `0600`/`0400` and the container user is uid
  10001, so a key file owned by your own uid is unreadable:

  ```
  error: cannot read key file /run/secrets/sg_key: Permission denied (os error 13)
  ```

  Fixes: (a) generate the key *inside* a volume and hand it to uid 10001:
  `docker run --rm --user 0 --entrypoint sh -v sg-key:/k secret-custodian:dev -c 'sg keygen --out /k/sg_key && chown 10001:10001 /k/sg_key && chmod 0400 /k/sg_key'`,
  then mount the volume read-only at `/run/secrets`; (b) `sudo chown 10001:10001 sg.key && sudo chmod 0400 sg.key` on the
  host (the compose example's route; not run here because it needs root); (c) pass `SG_MASTER_KEY` and drop `--key-file`
  from the command. Routes (a) and (c) were run and work. Also note that
  `docker run --rm -v "$PWD":/out --entrypoint sg ... keygen --out /out/sg.key`
  fails with `Permission denied` unless the host directory is writable by uid 10001; run `sg keygen` on the host or use
  (a).
- Agents that are not in Docker use the published/host-side proxy address instead; keep the proxy bound to loopback or
  a private interface.

## Trusting the CA on agents

Give each agent process three things: the proxy URL with its token, the vault CA certificate, and (if needed) the
proxy variables for plain HTTP. `sg token create` prints exactly this block with your token filled in (the user name
before the colon is a label; only the password, the token, matters):

```sh
sg ca export > sg-ca.pem                      # on the machine that runs the agent (or copy the file there)
export HTTPS_PROXY=http://laptop:TOKEN@127.0.0.1:8080
export HTTP_PROXY=$HTTPS_PROXY
export SSL_CERT_FILE=$PWD/sg-ca.pem
export CURL_CA_BUNDLE=$PWD/sg-ca.pem
export REQUESTS_CA_BUNDLE=$PWD/sg-ca.pem
export NODE_EXTRA_CA_CERTS=$PWD/sg-ca.pem
```

**Trust is per process, via environment variables, not the system store**, so the CA only works where you want it.
Only hosts for which the agent's role has a rule are re-signed by the vault CA; everything else (passthrough) shows
the real certificate. Four variables cover most tools:

| Variable | Read by | Behaviour |
|---|---|---|
| `SSL_CERT_FILE` | OpenSSL-based programs, Python's `ssl`, Ruby and many others | **Replaces** the default bundle |
| `CURL_CA_BUNDLE` | curl (also `--cacert`) | Replaces |
| `REQUESTS_CA_BUNDLE` | Python `requests` | Replaces |
| `NODE_EXTRA_CA_CERTS` | Node.js | **Adds** to the built-in roots |

Because most of them replace the bundle, a file containing only the vault CA breaks TLS to hosts that are not
intercepted (verified: a passthrough request fails with `unable to get local issuer certificate`). If the agent also
talks to hosts without rules, point the variables at a combined file:

```sh
cat /etc/pki/tls/certs/ca-bundle.crt sg-ca.pem > combined.pem    # Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=$PWD/combined.pem CURL_CA_BUNDLE=$PWD/combined.pem REQUESTS_CA_BUNDLE=$PWD/combined.pem
```

(Verified: with the combined bundle a passthrough request to `https://example.com` succeeded.) Whenever a rule or secret
adds a **new host** (the command prints `the CA certificate changed: agents must reload it`), export the certificate
again and replace the file: a client holding the old one refuses the new name (`permitted subtree violation`). Removing
a host does not require a reload.

**curl** (verified):

```sh
HTTPS_PROXY=http://laptop:TOKEN@127.0.0.1:8080 CURL_CA_BUNDLE=$PWD/sg-ca.pem curl https://api.example.com/...
```

**Python `requests` / `urllib`**: honours `HTTPS_PROXY`, `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE`. No extra code is needed:
Python 3.13 and later (whose default `ssl` context enables `VERIFY_X509_STRICT`) works because the vault's leaf
certificates carry an Authority Key Identifier (verified with Python 3.14.7, OpenSSL 3.5.7, with both `urllib` and
`requests`).

```sh
HTTPS_PROXY=http://laptop:TOKEN@127.0.0.1:8080 SSL_CERT_FILE=$PWD/sg-ca.pem REQUESTS_CA_BUNDLE=$PWD/sg-ca.pem \
  python3 -c 'import requests; print(requests.get("https://api.example.com/").text)'
```

**Node.js:** `NODE_EXTRA_CA_CERTS` works, but Node does not read `HTTPS_PROXY` by itself. On recent Node releases (tested with
22.22) set `NODE_USE_ENV_PROXY=1` (or run `node --use-env-proxy`): `fetch` then goes through the proxy (it prints an
experimental-feature warning). Without it, `fetch` connects directly (verified: it bypassed the proxy). Libraries such as
`undici`'s `ProxyAgent` or `https-proxy-agent` also work.

**AI agent CLIs:** most are Node or Python programs, so the same variables apply: `HTTPS_PROXY` plus
`NODE_EXTRA_CA_CERTS` (Node) or `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` (Python). Start the agent from a shell, or a
launcher script, that has them exported. This was not tested against any specific commercial agent CLI; check the
tool's own documentation for proxy and CA support.

**git:** honours `HTTPS_PROXY`, but takes its CA from `GIT_SSL_CAINFO` or `http.sslCAInfo`, not from `SSL_CERT_FILE`
(verified: git failed with `SSL certificate problem` until `GIT_SSL_CAINFO` was set).

**Tools known to ignore the proxy or the CA variables, or to refuse the vault's certificates:** programs with
certificate pinning, Java (own trust store: import the CA with `keytool`; it also takes its proxy from
`-Dhttps.proxyHost` properties, not `HTTPS_PROXY`; not tested here), some Go programs, anything that opens raw sockets
or uses WebSockets, and browsers (which use the system store). Nothing is injected for traffic that bypasses the
proxy, and the agent would then use whatever credentials it has itself.

## Routine tasks

### Rotating a secret

1. Create the new credential at the provider.
2. `printf %s "$NEW" | sg secret rotate gh` (or the UI). The change is effective for the very next request: values are
   decrypted per request. Rules and tokens are untouched; agents notice nothing.
3. Revoke the old credential at the provider.

Check with `sg secret ls` (the `ROTATED` column).

### Revoking tokens

- One token: `sg token ls` to find the id, then `sg token revoke <jti>`.
- Everything of a machine: `sg token revoke-machine laptop`.
- Effect: the next request inside any open MITM tunnel gets `407` and the tunnel closes; new CONNECTs get `407`. A
  passthrough tunnel already open stays until it ends (idle 10 min, at most 8 h).
- A suspected leak of a *secret* (not a token) means rotating the secret at the provider; revoking tokens does not
  help.

### When the CA gains a domain, and why agents must reload

There is no command to allow a domain: the CA's permitted domains are derived from the rules. Creating a rule (or a secret,
which always comes with its first rule) for a host the CA does not yet permit, for example
`sg rule add --role reviewer --host api.example.com ...`, re-issues the CA certificate **with the same key** and wider name
constraints, and prints `warning: the CA certificate changed: agents must reload it (sg ca export)`.
Agents that still trust the previous certificate refuse the new name:

```
curl: (60) SSL certificate problem: permitted subtree violation
```

So when you see that notice: `sg ca export > sg-ca.pem` again, replace the file on every agent (and rebuild the combined
bundle), then restart or re-run the agent processes. Certificates issued earlier stay valid. `sg ca status` lists what the
CA permits. Removing the last rule that uses a host (or its secret or role) shrinks the CA again; agents with the old
certificate keep working, so no reload is needed for removals. A rule for a host that is already permitted (including a
subdomain of a wildcard `*.x`, which is stored as `x`) changes nothing. While the CA certificate is being prepared the
proxy may wait a few milliseconds on that one write (see [architecture.md](architecture.md#admin-operations-and-the-ca)).

### Logging in to the web UI

`sg login-url`, open the link in a browser on the same machine within 10 minutes. Sessions last 8 hours and end when the
tab closes or the server restarts.

## Observability

**The audit log** is the main tool. Every authenticated proxy event is a row; `sg audit` shows the newest first:

```sh
sg audit --limit 50
sg audit --role reviewer --host api.github.com
sg audit --since "$(date -d '1 hour ago' +%s)" --limit 1000
# everything that was refused or failed in the last hour, as TSV
sg --json audit --since "$(date -d '1 hour ago' +%s)" --limit 1000 \
  | jq -r '.[] | select(.decision | IN("inject","mitm","passthrough") | not) | [.ts,.machine,.host,.decision,.status] | @tsv'
# counts per decision
sg --json audit --limit 1000 | jq -r 'group_by(.decision)[] | "\(.[0].decision)\t\(length)"'
```

The decisions and what they mean are in [proxy-internals.md](proxy-internals.md#audit-decisions). Failed authentication
(`407`) writes **no** row, except for a validly signed token that is revoked or expired (`token-invalid`, at most one
row per token per 60 s); for the rest use the agent-side error and `curl -v`. Rows never contain query
strings, headers, tokens or secrets. The log grows without bound; see [pruning](#backups). An agent left running with an expired or revoked (still validly
signed) token now writes about one row per minute per token (up to ~1440 rows/day/token) until the token is replaced
or the agent stopped; this is bounded by the number of tokens ever issued.

**Server logs** go to stderr (`journalctl --user -u secret-custodian` under systemd, `docker logs` in a container).
The default level is `warn`; `RUST_LOG` overrides it (`RUST_LOG=debug`). The program logs very little by design: an
upstream failure (`WARN sg_proxy::forward: upstream failure error=connect failed: Connection refused (os error 111)
host=localhost`), failed accepts, failed audit writes and internal errors; at `debug`, dropped connections. There are
no per-request log lines and no `info` messages. Log lines contain ANSI colour codes even when redirected.

**Health:** `sg ca status` succeeds when the admin socket answers (it is the Docker health check). A full check is a
request through the proxy.

**Lifecycle:** stdout shows `proxy:`, `admin:`, `socket:`, `ready`; `SIGTERM`/`SIGINT` stop it cleanly and remove the
socket.

## Troubleshooting

Messages are copied from real runs. "Agent side" means what the agent's HTTP client reports.

| Symptom | Cause | Fix |
|---|---|---|
| `error: cannot reach the vault at <path> (is `sg serve` running?): No such file or directory (os error 2)` | Server not running, or the CLI and the server use different socket paths (`XDG_RUNTIME_DIR` differs, or `--socket`/`SG_SOCKET` set on one side only) | Start `sg serve`; pass the same `--socket` or export `SG_SOCKET`. Inside Docker the variable is preset |
| `error: refusing to use <socket>: its directory <dir> is accessible to group/others (mode 755)...` | The socket directory is not `0700` | `chmod 700 <dir>` or use `$XDG_RUNTIME_DIR` |
| `sg serve`: `error: could not unlock the vault with the given key source` | Wrong key or passphrase, wrong kind of source for this vault, or a damaged database | Use the key the vault was created with; restore the key from backup |
| `sg serve`: `error: key file <f> is accessible to group/others (mode 644); run `chmod 600 <f>`` | Key file mode | `chmod 600` |
| `sg serve`: `error: cannot read key file /run/secrets/sg_key: Permission denied (os error 13)` (container) | Key file not readable by uid 10001 | See the [key delivery pitfall](#containers-and-networking) |
| `sg serve`: `error: the key is not valid: expected base64 of exactly 32 bytes ...` | Truncated or edited key file, wrong variable | Regenerate only for a new vault; otherwise restore the original |
| `sg serve`: `error: cannot bind the proxy address 127.0.0.1:8080: Address already in use (os error 98)` | Port taken (another instance, or another program) | Choose `--proxy-bind` / `--admin-bind`; `ss -ltnp` to find the owner |
| `sg serve`: `error: already running: <socket> accepts connections` | A live server owns the socket | Use another `--socket` and `--data-dir`, or stop the other one |
| `sg serve`: `error: database schema version 99 is not supported by this build (supports 1)` | The database was written by a different version | Run a matching build; restore a backup |
| `sg serve`: `WARNING: the admin interface is bound to 0.0.0.0:...` | Non-loopback `--admin-bind` | Fine inside a container whose port is published to host loopback only; otherwise bind loopback |
| Browser: `unexpected Host header` (HTTP 421) | The UI was opened with a `Host` the server does not allow (another port, a hostname, an IP in a container) | Open the URL printed by `sg login-url`; set `--admin-public-url http://host:port` (or add `--admin-allowed-host host:port`) for published/remapped ports |
| Browser: "Sign in required" / `invalid or already used login token` | Link used twice, older than 10 minutes, or the server restarted | `sg login-url` for a fresh link |
| Agent: `curl: (56) CONNECT tunnel failed, response 407` | No, wrong, malformed, expired or revoked token | Check `HTTPS_PROXY` (token in the password position); `sg token ls` shows `STATUS` |
| Agent: `curl: (56) CONNECT tunnel failed, response 403` | Host has no rule for the role and the role is `deny` (audit `unmatched-denied`), the role was deleted (`unknown-role`), or the network policy refused the target (`target-denied`, e.g. loopback or the vault's own port) | `sg audit --limit 5` shows which; add a rule or use a `passthrough` role; `--allow-loopback-targets` for local test targets |
| Agent: `curl: (56) CONNECT tunnel failed, response 502` and the body or audit says the CA does not permit the host (`ca-not-permitted`) | The role has a rule for a host the CA does not permit (should not happen: the CA follows the rules and `sg serve` refuses to start if it cannot sync it) | `sg ca status`; delete and re-create the rule (or restart `sg serve`), then re-export the certificate to agents |
| Agent: `502` with `could not reach the destination` (`tunnel-connect-failed`) | A passthrough target does not resolve or does not answer | DNS/network from the vault's side |
| Agent: `curl: (60) SSL certificate problem: unable to get local issuer certificate` | The agent does not trust the vault CA, or its bundle lacks the CA | Set the CA variables ([above](#trusting-the-ca-on-agents)) |
| Agent: `curl: (60) SSL certificate problem: permitted subtree violation` | The agent holds an older CA certificate that predates the rule that added this host (the CLI printed the reload notice) | Re-export and replace the CA file |
| Passthrough hosts fail TLS after pointing `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` at the vault CA | Those variables replace the trust store | Use a combined bundle ([above](#trusting-the-ca-on-agents)) |
| Agent talks to the API directly, nothing injected | `NO_PROXY=localhost,...` (printed by `token create`) matches the host, or the client ignores `HTTPS_PROXY` (some Go/Java/pinned tools) | Remove the host from `NO_PROXY`; use the client's own proxy setting |
| Inside the tunnel: `403` body `not allowed for this role` (`forbidden`) | No rule authorises this method or path (including paths the matcher refuses to judge, such as `..;`, malformed `%`, control characters) | `sg rule ls --role <r>`; widen the rule or fix the request. See [policy-and-rules.md](policy-and-rules.md#8-fail-closed-side-effects-operators-should-know) |
| `403` body `refusing to inject credentials over plain HTTP` (`plaintext-refused`) | The agent used `http://` for a host with a rule | Use `https://`; local services need a TLS front end |
| `421` body `Host does not match the CONNECT target` (`host-mismatch`) | The request's `Host` or URL differs from the tunnel's host (client reused a connection, or sets a custom `Host`) | Do not override `Host` |
| `405` body `method not allowed` (`method-refused`) | `TRACE`, `TRACK` or `CONNECT` inside a tunnel | Do not use them |
| `429` body `too many open tunnels for this token` / `too many concurrent requests for this token` | A token reached 64 tunnels or 64 in-flight requests (`Retry-After: 1`) | Reduce parallelism, or use another token; connection pooling helps |
| `502` body `upstream request failed` (`upstream-error`) | Upstream refused, timed out, or its TLS certificate is not trusted by the vault (a private CA) | Check the vault's `WARN` log line for the cause; for private CAs start with `--upstream-ca <pem>` |
| `503` body `service unavailable` (`internal-error`) | The vault could not read the role or the rules (database error); the proxy fails closed and forwards nothing | Check the vault `ERROR` log line; restore the database |
| `502` body `secret unavailable` | The stored secret no longer decrypts (database damaged or tampered) | Restore a backup; re-add the secret |
| `sg rule rm`: `error: this is the last rule of its secret: ...` | Every secret needs at least one rule | `sg secret rm <name>`, or `sg rule add` another rule first |
| `sg role rm`: `error: deleting this role would leave secrets without rules: ...` | Those secrets only have rules for this role | Delete the secrets, or add rules for another role, then retry |
| `sg secret add`: `error: several roles exist (a, b): choose one with --role` | More than one role and no `--role` | Add `--role <name>` |
| `sg secret add` / `sg rule add`: `warning: the CA certificate changed: agents must reload it` | The rule added a host to the CA | Re-export the certificate to agents ([above](#when-the-ca-gains-a-domain-and-why-agents-must-reload)) |
| `sg token create`: `error: unknown role` | The role does not exist | `sg role ls`; `sg role add` |
| `sg secret add` / `sg rule add`: `error: domain rejected: reserved` | The host is under the placeholder TLD `invalid` | Use a real host; nothing was created |
| Container shows `unhealthy` | The admin socket does not answer `sg ca status` | `docker logs`; the usual cause is a start-up error such as the key pitfall above |
| Requests are slow or hang under load | SQLite is accessed synchronously behind one mutex; a body is stalled (cut after 60 s idle) | Single-operator design; check agent concurrency; look for upstream timeouts |

If something is not in this table: reproduce with `sg audit` (what did the proxy decide?) and the server's stderr
(what did it log?), then see [proxy-internals.md](proxy-internals.md).
