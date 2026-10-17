# Secret Guardian

Secret Guardian (`sg`) is a self-hosted credential vault for AI agents and other untrusted automation. Your agents
make ordinary HTTP(S) requests through a local proxy; the proxy looks up the agent's role, and injects the real API
key into the request on the way out. The agent never holds the key, never sees it, and cannot ask for it. It is one
Rust binary (or one Docker image) with a CLI, an admin API and a small local web UI, and it keeps everything in a single
encrypted SQLite file.

Status: phase 1 is complete and tested ([Status](#status)). There is no license file yet ([License](#license)).

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

1. You store a secret (write-only), create a **role** (a policy) and **rules** (host, path, methods, and which header or
   query parameter carries which secret), then issue a **token** for a `(machine, role)`.
2. The agent runs with `HTTPS_PROXY=http://machine:TOKEN@vault:8080` and trusts the vault's CA certificate.
3. The agent sends `CONNECT api.example.com:443`. The proxy checks the token, then asks whether the role has rules for that host.
4. With rules, the proxy terminates TLS with a short-lived certificate from a **name-constrained CA** that can only sign
   for the domains you allowed; hosts without rules are tunnelled untouched or refused, per role.
5. For every request inside the tunnel the proxy re-checks the token, judges method and path against the rules,
   **removes** any credential the agent supplied, injects the real one and forwards the request over verified TLS.
6. Every decision is written to an audit log (no secrets, no query strings).

```mermaid
flowchart LR
    A["Agent (token + CA)"] -->|"HTTPS_PROXY, CONNECT"| P["sg proxy"]
    P -->|"token valid?"| T["Token check and revocation"]
    P -->|"host, path, method"| R["Vault rules for the role"]
    R -->|"decrypt secret for this request"| V[("Encrypted vault.db")]
    P -->|"real credential over TLS"| U["Upstream API"]
    U -->|"response (streamed)"| P
    P -->|"response"| A
    P -.->|"decision"| L["Audit log"]
```

## Quick start from source

This sequence was executed end to end on a Linux machine; the outputs shown have the shape you will get (ports,
timestamps and tokens differ). It uses a **local TLS test upstream** so nothing real is contacted, and ephemeral
ports and a temporary directory so it cannot collide with an instance of your own. You need Rust (via
[rustup](https://rustup.rs)), a C compiler, `curl`, `openssl`, `python3` and `jq`.

**1. Build** (about three minutes the first time):

```sh
cargo build --release -p sg
export PATH="$PWD/target/release:$PATH"
sg --version
```

```
sg 0.1.0
```

**2. A demo directory and a TLS upstream** that prints what it receives (this stands in for a real API; it answers
`ok` and logs the `Authorization` header it got):

```sh
export DEMO="$(mktemp -d)"; cd "$DEMO"          # mktemp creates it with mode 0700, which the admin socket needs

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -addext "basicConstraints=critical,CA:FALSE" -keyout up.key -out up.pem 2>/dev/null

cat > upstream.py <<'PY'
import http.server, ssl, sys
cert, key, portfile = sys.argv[1:4]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        print(self.command, self.path, "Authorization:", self.headers.get("Authorization"), flush=True)
        self.send_response(200); self.send_header("Content-Length", "3"); self.end_headers(); self.wfile.write(b"ok\n")
    do_GET = do_POST = _h
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
open(portfile, "w").write(str(s.server_address[1]))
s.serve_forever()
PY
python3 upstream.py up.pem up.key up.port > upstream.log 2>&1 &
UP_PID=$!
until [ -s up.port ]; do sleep 0.1; done
UPPORT="$(cat up.port)"
```

**3. Create the master key and start the vault.** The key is a file you must back up; the vault cannot be opened
without it. `--proxy-bind` and `--admin-bind` use port 0 here only to pick free ports (the defaults are
`127.0.0.1:8080` and `127.0.0.1:9090`); `--upstream-ca` makes the vault trust the demo upstream's self-signed
certificate.

```sh
sg keygen --out sg.key
export SG_SOCKET="$DEMO/sg.sock"
sg serve --data-dir "$DEMO/data" --key-file sg.key --upstream-ca up.pem \
   --proxy-bind 127.0.0.1:0 --admin-bind 127.0.0.1:0 > serve.out 2> serve.err &
SERVE_PID=$!
until grep -qx ready serve.out; do sleep 0.1; done
cat serve.out
PROXY="$(sed -n 's/^proxy: http:\/\///p' serve.out)"
```

```
wrote sg.key
Back this file up: without it the vault cannot be opened.
proxy: http://127.0.0.1:33691
admin: http://localhost:45081/#t=9e9f86cc1378bd4246951ee3212002143ca445fd2b5d48432c961c65008e061a
socket: /tmp/tmp.vINqLarwc9/sg.sock
ready
```

On a normal run you would write just `sg serve --key-file ~/.config/secret-guardian/sg.key`. The `admin:` line is a
one-time login link for the [web UI](#web-ui).

**4. Store a secret, create roles and rules.** The secret comes from stdin, never from an argument. `reviewer` may only
`GET`; `developer` may do anything; both can reach only hosts that have a rule (`--unmatched deny`). The CA must permit
the host before the proxy can impersonate it.

```sh
printf '%s' 'demo-secret-value' | sg secret add upstream-key
sg role add reviewer  --unmatched deny
sg role add developer --unmatched deny
sg ca allow-domain localhost
sg rule add --role reviewer  --host localhost --methods GET \
   --header Authorization --template 'Bearer {secret}' --secret upstream-key
sg rule add --role developer --host localhost \
   --header Authorization --template 'Bearer {secret}' --secret upstream-key
sg rule ls
```

```
secret 'upstream-key' stored
role 'reviewer' created
role 'developer' created
the CA certificate changed: agents must reload it (sg ca export)
rule 1 created
rule 2 created
ID  ROLE       HOST       PATH  METHODS  KIND    TARGET         TEMPLATE         SECRET
1   reviewer   localhost  *     GET      header  Authorization  Bearer {secret}  1
2   developer  localhost  *     *        header  Authorization  Bearer {secret}  1
```

**5. Export the CA and issue tokens.** `sg token create` normally prints a ready-made `HTTPS_PROXY` block (see the
[CLI reference](docs/cli-reference.md#the-environment-block)); `--json` is handier in a script.

```sh
sg ca export > ca.pem
REVIEWER="$(sg --json token create --machine laptop --role reviewer  | jq -r .token)"
DEVELOPER="$(sg --json token create --machine laptop --role developer | jq -r .token)"
```

**6. Call the upstream through the proxy.** The password part of the proxy URL is the token; `--cacert` makes curl trust
the vault CA.

```sh
curl -sS --proxy "http://laptop:$REVIEWER@$PROXY"  --cacert ca.pem "https://localhost:$UPPORT/repos/demo"
curl -sS -w '%{http_code}\n' --proxy "http://laptop:$REVIEWER@$PROXY"  --cacert ca.pem -X POST -d x=1 "https://localhost:$UPPORT/repos/demo"
curl -sS --proxy "http://laptop:$DEVELOPER@$PROXY" --cacert ca.pem -X POST -d x=1 "https://localhost:$UPPORT/repos/demo"
```

```
ok
not allowed for this role
403
ok
```

**7. See what the upstream received, and what the vault recorded.** The agent's `curl` never saw the secret; the upstream
did:

```sh
cat upstream.log
sg audit --limit 6
```

```
GET /repos/demo Authorization: Bearer demo-secret-value
POST /repos/demo Authorization: Bearer demo-secret-value
TIME                  MACHINE  ROLE       METHOD   HOST       PATH         DECISION   STATUS  RULE
2026-10-16T20:10:34Z  laptop   developer  POST     localhost  /repos/demo  inject     200     2
2026-10-16T20:10:34Z  laptop   developer  CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   POST     localhost  /repos/demo  forbidden  403     -
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   GET      localhost  /repos/demo  inject     200     1
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
```

The reviewer's `POST` was refused by the vault and never reached the upstream. Try `sg token revoke <id>` (ids from
`sg token ls`) and repeat a request: it now gets `407`.

**8. Stop and clean up:**

```sh
kill "$SERVE_PID"; wait "$SERVE_PID"; kill "$UP_PID"; cd /; rm -rf "$DEMO"
```

`sg serve` stops cleanly on `SIGINT` or `SIGTERM` (exit code 0) and removes its socket.

**With a real API** (example only, not part of the verified sequence above): `sg ca allow-domain api.github.com`, a role
with `--unmatched deny`, a rule with `--host api.github.com --methods GET --header Authorization --template 'Bearer {secret}'`,
the real token on stdin, and `curl https://api.github.com/user` under the printed `HTTPS_PROXY`. Without `--upstream-ca`
the vault trusts the system root store.

Note for local demos: the block printed by `sg token create` sets `NO_PROXY=localhost,127.0.0.1`. If your test upstream is
`localhost`, drop that line, or the client will bypass the proxy and nothing will be injected.

## Configure an agent

Give each agent process three things: the proxy URL with its token, the vault CA certificate, and (if needed) the
proxy variables for plain HTTP.

```sh
sg ca export > sg-ca.pem                      # on the machine that runs the agent (or copy the file there)
export HTTPS_PROXY=http://laptop:TOKEN@127.0.0.1:8080
export HTTP_PROXY=$HTTPS_PROXY
export SSL_CERT_FILE=$PWD/sg-ca.pem
export CURL_CA_BUNDLE=$PWD/sg-ca.pem
export REQUESTS_CA_BUNDLE=$PWD/sg-ca.pem
export NODE_EXTRA_CA_CERTS=$PWD/sg-ca.pem
```

`sg token create` prints exactly this block with your token filled in. The user name before the colon is a label; only
the password (the token) matters.

**Trust is per process, via environment variables, not the system store**, so the CA only works where you want it. Four
variables cover most tools:

| Variable | Read by | Behaviour |
|---|---|---|
| `SSL_CERT_FILE` | OpenSSL-based programs, Python's `ssl`, Ruby and many others | **Replaces** the default bundle |
| `CURL_CA_BUNDLE` | curl | Replaces |
| `REQUESTS_CA_BUNDLE` | Python `requests` | Replaces |
| `NODE_EXTRA_CA_CERTS` | Node.js | **Adds** to the built-in roots |

Because most of them replace the bundle, a file containing only the vault CA breaks TLS to hosts that are not
intercepted (verified: a passthrough request fails with `unable to get local issuer certificate`). If the agent also
talks to hosts without rules, point the variables at a combined file:

```sh
cat /etc/pki/tls/certs/ca-bundle.crt sg-ca.pem > combined.pem    # Debian/Ubuntu: /etc/ssl/certs/ca-certificates.crt
```

After every `sg ca allow-domain` that adds a domain, export the certificate again and replace the file: a client holding
the old one refuses the newly allowed name (`permitted subtree violation`).

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

**Claude Code and other agent CLIs:** most are Node or Python programs, so the same variables apply:
`HTTPS_PROXY` plus `NODE_EXTRA_CA_CERTS` (Node) or `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` (Python). Start the agent from a
shell, or a launcher script, that has them exported. This was not tested against any specific commercial agent CLI; check
the tool's own documentation for proxy and CA support.

**git:** honours `HTTPS_PROXY`, but takes its CA from `GIT_SSL_CAINFO` or `http.sslCAInfo`, not from
`SSL_CERT_FILE` (verified: git failed with `SSL certificate problem` until `GIT_SSL_CAINFO` was set).

**Tools known to ignore the proxy or the CA variables, or to refuse the vault's certificates:** programs with
certificate pinning, Java (own trust store: import the CA with `keytool`; it also takes its proxy from `-Dhttps.proxyHost`
properties, not `HTTPS_PROXY`; not tested here), some Go programs, anything that opens raw sockets or uses WebSockets, and browsers (which use the
system store). Nothing is injected for traffic that bypasses the proxy, and the agent would then use whatever credentials it
has itself.

## Docker

The image is a Debian-slim build of the release binary that runs as uid/gid `10001`, with `/data` (mode `0700`) as its
volume, ports `8080` (proxy) and `9090` (web UI), and `SG_SOCKET` preset so `docker exec` works without flags.

```sh
docker build -t secret-guardian:dev .
```

**The key.** The default command reads the key from `/run/secrets/sg_key`. The file must be mode `0600` or `0400` and
**readable by uid 10001**. This is the usual stumbling block: a Docker secret or bind mount of a host file keeps the host
file's owner, so a key you created with your own uid is refused (verified):

```
error: cannot read key file /run/secrets/sg_key: Permission denied (os error 13)
```

Three ways out (the first and third were run):

```sh
# 1. generate the key inside a volume, owned by uid 10001, and mount that volume at /run/secrets
docker volume create sg-key
docker run --rm --user 0 --entrypoint sh -v sg-key:/k secret-guardian:dev \
  -c 'sg keygen --out /k/sg_key && chown 10001:10001 /k/sg_key && chmod 0400 /k/sg_key'
docker run -d --name secret-guardian --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -p 127.0.0.1:9090:9090 -v sg-key:/run/secrets:ro -v sg-data:/data secret-guardian:dev

# 2. (compose example's route, needs root, not run here) chown the host file to the container user
sudo chown 10001:10001 sg.key && sudo chmod 0400 sg.key

# 3. no file at all: SG_MASTER_KEY (the same base64 value) and override the command without --key-file
docker run -d --name secret-guardian -e SG_MASTER_KEY="$(cat sg.key)" -p 127.0.0.1:9090:9090 -v sg-data:/data \
  secret-guardian:dev serve --data-dir /data --socket /data/sg.sock \
  --proxy-bind 0.0.0.0:8080 --admin-bind 0.0.0.0:9090
```

Environment variables are visible in `docker inspect`; prefer the file. **Back the key up outside Docker**; losing it
loses every secret. (Note: `docker run -v "$PWD":/out ... keygen --out /out/sg.key` fails with `Permission denied` unless that host directory is
writable by uid 10001. Run `sg keygen` on the host, or use route 1.)

**Compose.** Copy `docker-compose.example.yml` to `docker-compose.yml`, put the key where it says, and
`docker compose up -d --build`. It builds the image, publishes the web UI on `127.0.0.1:9090` of the host only, does **not**
publish the proxy (agents reach it as `http://secret-guardian:8080` over an internal Docker network with no internet
route), and runs read-only, without capabilities, with resource limits. The file validates with `docker compose config`.

**Using it.** The CLI runs inside the container over the in-container socket:

```sh
docker compose exec secret-guardian sg secret ls
printf %s "$GITHUB_TOKEN" | docker compose exec -T secret-guardian sg secret add github
docker compose exec secret-guardian sg token create --machine agent1 --role reviewer --proxy-url http://secret-guardian:8080
docker compose exec secret-guardian sg ca export > sg-ca.pem
docker compose exec secret-guardian sg login-url
```

`sg login-url` prints `http://localhost:9090/#t=...`; open it in a browser on the Docker host. The URL names the port the
process bound *inside* the container, so if you publish the UI on a different host port, add
`--admin-public-url http://localhost:<hostport>` to the command (or set `SG_ADMIN_PUBLIC_URL`): `sg login-url` and the
`admin:` line then print that URL and its host:port is accepted as `Host`/`Origin` (otherwise the UI answers
`421 unexpected Host header`).
The container logs `WARNING: the admin interface is bound to 0.0.0.0:9090` at start: expected, because there is no remote
login and the port must stay published to `127.0.0.1` only. More in [docs/operations.md](docs/operations.md#containers-and-networking).

## Web UI

A small local admin page for everything the CLI does. It is plain HTML and JavaScript embedded in the binary (no build step,
no third-party resources).

**Opening it:** `sg serve` prints a one-time link on its `admin:` line; run `sg login-url` any time for a new one. Open it in a
browser on the same machine (it points at `http://localhost:<port>/#t=<token>`, default port `9090`). The token is in the URL
fragment, so it is never sent to the server in a request line or in a `Referer`; the page removes it from the address bar,
trades it once (`POST /login`) for a session, and keeps the session in `sessionStorage` (it ends when the tab closes, after 8 hours,
or when the server restarts). Each link works once and expires after 10 minutes. **There are no cookies**, on purpose:
browsers send cookies to every port of `localhost`, so another local web server could have read one. A page opened without a
valid session shows a "Sign in required" screen that tells you to run `sg login-url`. The listener is loopback-only by default and
checks `Host` and `Origin`; see [docs/admin-api.md](docs/admin-api.md).

| Tab | What it does |
|---|---|
| Secrets | Lists secret names and dates (never values). Add a secret (name and a masked value), rotate one, delete one (blocked while a rule uses it) |
| Roles & rules | Create and delete roles (with the unmatched policy: `deny` or `passthrough`); add rules with host, path, method checkboxes, header or query target, template and secret; delete rules. Shows the CA warning when a rule's host is not yet permitted |
| Tokens | Create a token for a machine, role and optional lifetime (`30m`, `12h`, `7d`); the token and a ready `HTTPS_PROXY` block are shown **once** with a Copy button; revoke one token or every token of a machine; status shows active, expired or revoked |
| CA | Lists permitted domains, allows a new domain (with the "agents must reload" notice), downloads the CA certificate, and shows the environment variables to trust it |
| Audit | Newest-first table with filters for role, host, time range (any time, last hour, 24 hours, 7 days) and limit (50, 200, 1000); refusals are highlighted |

**Honest status of the UI: it has not been verified in a real browser by the authors.** It was tested through Rust tests of the
server side (headers, guards, login flow, embedded assets), static source checks (no `innerHTML`, `eval` or inline handlers),
and `node` tests of its logic (fragment parsing, TTL parsing, 401 handling, rendering of hostile strings as text). Layout, clipboard
copy, certificate download and the interactive flow are unexercised in an actual browser. The CLI covers every operation,
so you are never blocked by the UI.

## CLI overview

Full reference with every flag, default, output example and error: [docs/cli-reference.md](docs/cli-reference.md).

| Command | What it does |
|---|---|
| `sg serve` | Run the vault: proxy, admin socket and web UI |
| `sg keygen --out FILE` | Create a random master key file (mode 0600, never overwrites) |
| `sg secret add NAME` / `rotate NAME` / `rm NAME` / `ls` | Manage secrets; values come from stdin or a hidden prompt and are write-only |
| `sg role add NAME [--unmatched passthrough\|deny]` / `rm NAME` / `ls` | Manage roles and what happens to hosts without rules |
| `sg rule add --role R --host H [--path P] [--methods M,..] (--header N \| --query N) [--template T] --secret S` / `rm ID` / `ls [--role R]` | Manage injection rules |
| `sg token create --machine M --role R [--ttl 12h] [--proxy-url URL]` / `revoke JTI` / `revoke-machine M` / `ls` | Issue and revoke agent tokens |
| `sg ca export` / `allow-domain DOMAIN` / `status` | Export the CA certificate, permit a domain, list permitted domains |
| `sg audit [--role R] [--host H] [--since TS] [--limit N]` | Show the audit log, newest first |
| `sg login-url` | Print a fresh single-use link to the web UI |

Global options on every command: `--socket PATH` (env `SG_SOCKET`) and `--json`. Exit codes: `0` success, `1` failure, `2` usage
error.

## Configuration

`sg serve` is configured by flags and environment variables only; there is no configuration file.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--data-dir DIR` | - | `$XDG_DATA_HOME/secret-guardian`, else `~/.local/share/secret-guardian` | Directory with `vault.db` (created `0700`) |
| `--socket PATH` | `SG_SOCKET` | `$XDG_RUNTIME_DIR/secret-guardian.sock`, else `<data dir>/sg.sock` | Admin Unix socket (mode `0600`, in a `0700` directory); also what client commands connect to |
| `--proxy-bind ADDR` | `SG_PROXY_BIND` | `127.0.0.1:8080` | Proxy listener (`IP:port`) |
| `--admin-bind ADDR` | `SG_ADMIN_BIND` | `127.0.0.1:9090` | Web UI listener; non-loopback prints a warning |
| `--admin-public-url URL` | `SG_ADMIN_PUBLIC_URL` | `http://localhost:<bound admin port>` | URL you really use for the web UI (`http(s)://host[:port]`, no path); printed on the `admin:` line, returned by `sg login-url`, and its host:port is accepted as `Host`/`Origin` |
| `--admin-allowed-host HOST:PORT` | - | none | Extra `Host`/`Origin` accepted by the web UI (repeatable) |
| `--key-file FILE` | `SG_KEY_FILE` | none | Master key file (base64 of 32 bytes, mode `0600`) |
| (no flag) | `SG_MASTER_KEY` | none | The same base64 key in the environment |
| `--passphrase` | - | off | Derive the key from a prompt (needs a terminal) |
| `--upstream-ca PEM` | `SG_UPSTREAM_CA` | none | Extra CA bundle trusted for upstream TLS (repeatable flag) |
| `--allow-loopback-targets` | - | off | Let the proxy reach loopback addresses (its own and the UI's ports stay blocked) |
| (no flag) | `RUST_LOG` | `warn` | Log level (stderr) |

Choose exactly one key source. Timeouts, caps and limits are compiled-in defaults and are documented in
[docs/proxy-internals.md](docs/proxy-internals.md). Installing, directories and permissions, key management, backups,
upgrades, a systemd unit and troubleshooting: [docs/operations.md](docs/operations.md).

## Security model in brief

Guaranteed (by design and by tests):

- No command, API route or web page returns a stored secret value; values are write-only.
- Secrets, the token signing key and the CA key are AES-256-GCM ciphertext under a key that is not in the database; a copy of
  the database alone reveals metadata (names, hosts, audit) but no secret.
- The agent's own `Authorization`/API-key header or parameter for a rule's target is discarded and replaced; routing and
  forwarding headers are stripped; `TRACE` is refused; the path a rule is judged on is the path that is forwarded, checked
  at every percent-decoding depth.
- Credentials are only ever injected over TLS, never into plain `http://`.
- The proxy refuses loopback, link-local and cloud-metadata targets and its own ports; revoking a token stops an open
  tunnel at the next request.
- The CA can only sign for the domains you allow (X.509 name constraints) and never for IP addresses.
- The web UI uses no cookies, checks `Host` and `Origin`, requires a bearer session obtained with a one-time token, and ships a
  strict CSP.

Not guaranteed:

- An agent can do whatever its role allows. Scope roles narrowly.
- An origin that echoes your credential in a response (common with query-string keys) hands it to the agent.
- Anything against an attacker running as the same operating-system user as the vault, or holding both the database and the key.
- Protection from clients that ignore X.509 name constraints.

Full threat model, attacker analysis, code map and deployment checklist: [docs/security-model.md](docs/security-model.md).

## Limitations

Read these before relying on it:

- **No injection over plain HTTP, ever.** Rules do not include the port, so a credential sent in clear to another port of an
  allowed host would leak. Local services without TLS need a TLS terminator in front.
- **Headers and query parameters only.** No request-body injection, no request signing (AWS SigV4, HMAC).
- **No WebSockets / `Upgrade`** through the proxy (the headers are stripped).
- **Clients that cannot use the vault CA:** certificate-pinned programs, Java (own trust store), some Go binaries.
- **Responses are not inspected.** Reflected credentials are visible to the agent; query-parameter keys are especially prone to
  this (`Link`, `Location`).
- **Query injection** appends `name=value` (percent-encoded) at the end and removes the agent's own copies of that parameter;
  prefer header injection whenever the API allows it. Method overrides carried in the query or body (`_method=`) are not stripped.
- **The port is not part of a rule:** a rule for `api.example.com` applies to every port of that host. Not a security boundary.
- **No public-suffix check:** `sg ca allow-domain github.io` or `co.uk` would let the CA sign for every site under it. Allow exact hosts.
- **Rotation of the master key, token signing key and CA key is not implemented.** Rotating a secret value is.
- **Loopback targets are denied** unless you pass `--allow-loopback-targets`; the only built-in exception is TLS to the exact host
  `localhost` with an applicable rule. Private LAN addresses (RFC 1918, ULA, CGNAT) are reachable on purpose.
- **Revocation cannot cut an open passthrough tunnel;** it ends after 10 idle minutes or 8 hours at most.
- **The web UI has not been verified in a real browser** by the authors.
- **Single operator.** No multi-user model, no remote administration, no login beyond the one-time local links. Plain HTTP on loopback.
- **Linux only as written:** the program learns its user id from `/proc/self`; other systems are untested.
- **The audit log has no retention** and grows until you prune it.
- Upstream connections are HTTP/1.1 only; the proxy does not store request or response bodies (streams them), and applies fixed
  timeouts documented in [proxy internals](docs/proxy-internals.md).

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
| `scripts/` | - | `e2e.sh` (host) and `e2e-docker.sh` (Docker) end-to-end tests |
| `Dockerfile`, `docker-compose.example.yml` | - | Container packaging |
| `docs/` | - | This documentation, the spec (`docs/specs`) and the plan (`docs/plans`) |

Running the checks (details and inventory in [docs/testing.md](docs/testing.md)):

```sh
cargo test -p sg-policy                                  # scoped, while developing
cargo test --workspace                                   # everything (449 tests pass, 1 ignored; about 4 minutes cold)
cargo test -p sg-policy --release -- --include-ignored   # + the exhaustive path oracle (1.5 million paths, about 40 s)
node --test crates/admin/tests/js/app.test.js            # JavaScript logic tests (also run by cargo test)
scripts/e2e.sh                                           # real curl through the real proxy
scripts/e2e-docker.sh                                    # same in Docker (needs a Docker daemon)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

The work follows a pipeline: brainstorm, then a **spec** in `docs/specs/` (design, threat model), then a **plan** in
`docs/plans/` (step-by-step, test-driven tasks), then implementation on a branch, verification, review and integration. Both
documents are in Spanish; the other documentation is in English. Where the plan or spec and the code differ, the code wins, and
the reference pages under `docs/` describe the code.

## Documentation index

| Page | Contents |
|---|---|
| [docs/README.md](docs/README.md) | Index of the documentation with one-line descriptions |
| [docs/cli-reference.md](docs/cli-reference.md) | Every command, flag, default, output, exit code and error message |
| [docs/admin-api.md](docs/admin-api.md) | Admin API for the socket and the web listener, authentication, guards |
| [docs/proxy-internals.md](docs/proxy-internals.md) | Request lifecycle, network policy, limits, audit decisions, error responses |
| [docs/security-model.md](docs/security-model.md) | Assets, attackers, mitigations, residual risks, hardening history, checklist |
| [docs/operations.md](docs/operations.md) | Install, permissions, keys, backups, upgrades, systemd, containers, troubleshooting |
| [docs/testing.md](docs/testing.md) | Test strategy, inventory, end-to-end scripts, known gaps |
| [docs/architecture.md](docs/architecture.md) | Crates, request sequence, concurrency, design decisions |
| [docs/database-schema.md](docs/database-schema.md) | Tables, columns, permissions, WAL, backup |
| [docs/crypto-and-keys.md](docs/crypto-and-keys.md) | Key hierarchy, encryption format, AADs, zeroization, failure modes |
| [docs/policy-and-rules.md](docs/policy-and-rules.md) | Roles, rules, matching, path judging |
| [docs/tokens-and-ca.md](docs/tokens-and-ca.md) | Token format and revocation; the CA and certificates |
| [docs/specs/](docs/specs/2026-10-16-secret-guardian-vault.md), [docs/plans/](docs/plans/2026-10-16-secret-guardian-vault.md) | Design spec and implementation plan (Spanish) |

## Status

**Phase 1 is complete:** the encrypted vault, name-constrained CA, header and query injection over TLS, tokens per
(machine, role), rules, audit, the CLI, the admin API with a local web UI, Docker packaging and two end-to-end scripts.

Planned for later phases (from the spec; none of it exists yet): a launcher/sidecar (`sg run`) that keeps the token out of
the agent's reach; remote administration with a login (opt-in); OIDC federation as a second token verifier with per-agent tokens;
injection into request bodies and request signing (SigV4 and similar).

## License

There is no `LICENSE` file in this repository yet, so no license is granted: all rights are reserved by default until the author
adds one. If you want to use or contribute to the project, ask first.
