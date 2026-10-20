# Quickstart: a verified walkthrough

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
admin: http://localhost:45081/#t=9e9f86cc1378bd4246951ee3212002143ca445fd2b5d54232c961c65008e061a
socket: /tmp/tmp.vINqLarwc9/sg.sock
ready
```

On a normal run you would write just `sg serve --key-file ~/.config/secret-guardian/sg.key`. The `admin:` line is a
one-time login link for the web UI (see [admin-api.md](admin-api.md)).

**4. Create roles, store a secret with its first rule, add another rule.** The secret comes from stdin, never from an
argument. A secret is created **together with its first rule** (`--host` and `--header` or `--query` are required), because a
secret no rule uses can never be injected. `reviewer` may only `GET`; `developer` may do anything; both can reach only hosts
that have a rule (`--unmatched deny`). The CA's permitted domains come from the rules, so there is no separate "allow this
domain" step: the first rule for `localhost` is what lets the proxy impersonate it.

```sh
sg role add reviewer  --unmatched deny
sg role add developer --unmatched deny
printf '%s' 'demo-secret-value' | sg secret add upstream-key --role developer --host localhost \
   --header Authorization --template 'Bearer {secret}'
sg rule add --role reviewer --host localhost --methods GET \
   --header Authorization --template 'Bearer {secret}' --secret upstream-key
sg rule ls
```

```
role 'reviewer' created
role 'developer' created
secret 'upstream-key' stored with rule 1
warning: the CA certificate changed: agents must reload it (sg ca export)
rule 2 created
ID  ROLE       HOST       PATH  METHODS  KIND    TARGET         TEMPLATE         SECRET
1   developer  localhost  *     *        header  Authorization  Bearer {secret}  1
2   reviewer   localhost  *     GET      header  Authorization  Bearer {secret}  1
```

The warning (on stderr) is the reload note: the CA certificate was re-issued because `localhost` was added, so agents must
fetch it again (step 5 does, and `sg ca status` lists the domains). Without `--role`, `secret add` uses the only existing
role, creates a role `default` if there is none, and fails if there are several roles.

**5. Export the CA and issue tokens.** `sg token create` normally prints a ready-made `HTTPS_PROXY` block (see the
[CLI reference](cli-reference.md#the-environment-block)); `--json` is handier in a script.

```sh
sg ca export > ca.pem
REVIEWER="$(sg --json token create --machine laptop --role reviewer  | jq -r .token)"
DEVELOPER="$(sg --json token create --machine laptop --role developer | jq -r .token)"
```

**6. Call the upstream through the proxy.** The password part of the proxy URL is the token; `--cacert` makes curl
trust the vault CA.

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
2026-10-16T20:10:34Z  laptop   developer  POST     localhost  /repos/demo  inject     200     1
2026-10-16T20:10:34Z  laptop   developer  CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   POST     localhost  /repos/demo  forbidden  403     -
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   GET      localhost  /repos/demo  inject     200     2
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
```

The reviewer's `POST` was refused by the vault and never reached the upstream. Try `sg token revoke <id>` (ids from
`sg token ls`) and repeat a request: it now gets `407`.

**8. Stop and clean up:**

```sh
kill "$SERVE_PID"; wait "$SERVE_PID"; kill "$UP_PID"; cd /; rm -rf "$DEMO"
```

`sg serve` stops cleanly on `SIGINT` or `SIGTERM` (exit code 0) and removes its socket.

**With a real API** (example only, not part of the verified sequence above): a role with `--unmatched deny`, then
`sg secret add gh --role reviewer --host api.github.com --methods GET --header Authorization --template 'Bearer {secret}'`
with the real token on stdin, and `curl https://api.github.com/user` under the printed `HTTPS_PROXY`. Without `--upstream-ca`
the vault trusts the system root store.

Note for local demos: the block printed by `sg token create` sets `NO_PROXY=localhost,127.0.0.1`. If your test upstream is
`localhost`, drop that line, or the client will bypass the proxy and nothing will be injected.

Next: [trusting the CA on your agents](operations.md#trusting-the-ca-on-agents), the [CLI reference](cli-reference.md), or
the [Docker setup](operations.md#docker).
