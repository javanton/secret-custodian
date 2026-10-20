#!/usr/bin/env bash
# Host-side end-to-end test: real curl through the real `sc` proxy to a real local TLS upstream.
# Uses a private temp dir and dynamic ports; never touches your own data dir or sockets.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in cargo curl openssl python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy SC_SOCKET SC_MASTER_KEY SC_KEY_FILE

cargo build -q -p sg
SC="$PWD/target/debug/sc"
W="$(mktemp -d)"
SERVE_PID=""; UP_PID=""
FAILED=0
cleanup() {
  [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
  rm -rf "$W"
}
trap cleanup EXIT

SECRET="E2E-SECRET-$RANDOM$RANDOM$RANDOM"
SOCK="$W/sg.sock"
DATA="$W/data"
UPLOG="$W/upstream.log"; : >"$UPLOG"
sc() { "$SC" --socket "$SOCK" "$@"; }

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1 (=$3)"; else fail "$1 (expected $2, got $3)"; fi
}
die() {
  echo "FAIL: $1"
  for f in serve.out serve.err upstream.log upstream.err; do
    echo "----- tail $f -----"; tail -n 25 "$W/$f" 2>/dev/null || true
  done
  exit 1
}

# 1. TLS upstream on a free port; logs method, path and the two credential headers.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" -addext "basicConstraints=critical,CA:FALSE" -keyout "$W/up.key" -out "$W/up.pem" 2>/dev/null
cat >"$W/up.py" <<'PY'
import http.server, ssl, sys
cert, key, log, portfile = sys.argv[1:5]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        with open(log, "a") as f:
            f.write("%s %s auth=%s xkey=%s\n" % (self.command, self.path,
                    self.headers.get("Authorization"), self.headers.get("X-Api-Key")))
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET = do_POST = _h
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
open(portfile + ".tmp", "w").write(str(s.server_address[1])); import os; os.rename(portfile + ".tmp", portfile)
s.serve_forever()
PY
python3 "$W/up.py" "$W/up.pem" "$W/up.key" "$UPLOG" "$W/up.port" 2>"$W/upstream.err" &
UP_PID=$!
for _ in $(seq 100); do [ -s "$W/up.port" ] && break; kill -0 "$UP_PID" 2>/dev/null || die "upstream died"; sleep 0.1; done
[ -s "$W/up.port" ] || die "upstream did not start"
UPPORT="$(cat "$W/up.port")"

# 2. The vault.
"$SC" keygen --out "$W/k.key" >/dev/null
MASTER_KEY="$(cat "$W/k.key")"
"$SC" serve --data-dir "$DATA" --socket "$SOCK" --key-file "$W/k.key" \
  --proxy-bind 127.0.0.1:0 --admin-bind 127.0.0.1:0 --upstream-ca "$W/up.pem" \
  >"$W/serve.out" 2>"$W/serve.err" &
SERVE_PID=$!
for _ in $(seq 100); do grep -qx ready "$W/serve.out" 2>/dev/null && break; kill -0 "$SERVE_PID" 2>/dev/null || die "sc serve died"; sleep 0.1; done
grep -qx ready "$W/serve.out" || die "sc serve never printed ready"
PROXY="$(sed -n 's/^proxy: http:\/\///p' "$W/serve.out")"
ADMIN_PORT="$(sed -n 's/^admin: http:\/\/localhost:\([0-9]*\)\/.*/\1/p' "$W/serve.out")"
LOGIN_TOKEN="$(sed -n 's/^admin: .*#t=//p' "$W/serve.out")"
[ -n "$PROXY" ] && [ -n "$ADMIN_PORT" ] && [ -n "$LOGIN_TOKEN" ] || die "could not parse serve output"
[ "$(sed -n 's/^socket: //p' "$W/serve.out")" = "$SOCK" ] || die "unexpected socket line"
echo "vault: proxy=$PROXY admin_port=$ADMIN_PORT upstream_port=$UPPORT"

# 3. Configuration through the CLI.
sc role add developer --unmatched deny >/dev/null
sc role add reviewer --unmatched deny >/dev/null
sc role add restricted --unmatched deny >/dev/null
sc role add querier --unmatched deny >/dev/null
sc role add keyer --unmatched deny >/dev/null
# A secret is created together with its first rule; the CA permits the rule's host from then on.
if printf '%s' "$SECRET" | sc secret add norule-key >/dev/null 2>&1; then fail "secret add without rule flags succeeded"; else pass "secret add without rule flags is refused"; fi
sc secret ls | grep -q norule-key && fail "rejected secret was stored" || pass "rejected secret was not stored"
printf '%s' "$SECRET" | sc secret add api-key --role developer --host localhost --header Authorization --template 'Bearer {secret}' >/dev/null || die "secret add"
sc rule add --role reviewer   --host localhost --methods GET --header Authorization --template 'Bearer {secret}' --secret api-key >/dev/null
sc rule add --role restricted --host localhost --methods GET --path '/repos/*' --header Authorization --template 'Bearer {secret}' --secret api-key >/dev/null
sc rule add --role querier    --host localhost --query api_key --secret api-key >/dev/null
sc rule add --role keyer      --host localhost --header X-Api-Key --secret api-key >/dev/null
sc ca status | grep -q localhost && pass "ca status lists the rule host" || fail "ca status does not list localhost"
sc ca export >"$W/ca.pem"
tokjson() { sc --json token create --machine e2e --role "$1" --proxy-url "http://$PROXY"; }
jget() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
DEV_JSON="$(tokjson developer)"; DEV="$(jget token <<<"$DEV_JSON")"; DEV_JTI="$(jget jti <<<"$DEV_JSON")"
REV="$(tokjson reviewer | jget token)"
RES="$(tokjson restricted | jget token)"
QRY="$(tokjson querier | jget token)"
KEY="$(tokjson keyer | jget token)"
ALL_TOKENS="$DEV $REV $RES $QRY $KEY"
BASE="https://localhost:$UPPORT"

# curl through the proxy; prints the HTTP status. Extra curl args after the URL path.
req() { # req <token> <method> <path> [curl args...]
  local tok="$1" m="$2" p="$3"; shift 3
  curl -s -o /dev/null -w '%{http_code}' --max-time 20 --proxy "http://x:$tok@$PROXY" --cacert "$W/ca.pem" -X "$m" "$@" "$BASE$p" || true
}

# Status of the proxy's CONNECT answer (a 407 happens before any tunnel exists, so http_code is 000).
connect_code() { # connect_code <token> <path>
  curl -s -o /dev/null -w '%{http_connect}' --max-time 20 --proxy "http://x:$1@$PROXY" --cacert "$W/ca.pem" "$BASE$2" || true
}

# 4. Role behaviour.
check "developer GET"                 200 "$(req "$DEV" GET /thing)"
check "developer POST"                200 "$(req "$DEV" POST /thing -d x=1)"
check "reviewer GET"                  200 "$(req "$REV" GET /thing)"
check "reviewer POST is forbidden"    403 "$(req "$REV" POST /thing -d x=1)"
check "unknown token"                 407 "$(connect_code not-a-token /thing)"
check "restricted GET /repos/ok"      200 "$(req "$RES" GET /repos/ok)"
check "restricted traversal %2f"      403 "$(req "$RES" GET '/repos/..%2fadmin' --path-as-is)"
check "restricted traversal ../"      403 "$(req "$RES" GET '/repos/../admin' --path-as-is)"
check "restricted outside its path"   403 "$(req "$RES" GET /other)"
check "query rule request"            200 "$(req "$QRY" GET '/q?x=1')"
check "header X-Api-Key rule request" 200 "$(req "$KEY" GET /k)"

# 5. What the upstream saw.
grep -qxF "GET /thing auth=Bearer $SECRET xkey=None" "$UPLOG" && pass "upstream got Authorization: Bearer <secret>" || fail "secret not injected into Authorization"
grep -qxF "POST /thing auth=Bearer $SECRET xkey=None" "$UPLOG" && pass "upstream got developer POST with secret" || fail "developer POST missing upstream"
[ "$(grep -c '^POST ' "$UPLOG")" = 1 ] && pass "reviewer POST never reached upstream (1 POST total)" || fail "unexpected POST count at upstream"
grep -qxF "GET /repos/ok auth=Bearer $SECRET xkey=None" "$UPLOG" && pass "restricted path request injected" || fail "restricted path request missing"
if grep -q 'admin' "$UPLOG"; then fail "traversal attempt reached upstream"; else pass "traversal attempts never reached upstream"; fi
if grep -q '^GET /other' "$UPLOG"; then fail "out-of-path request reached upstream"; else pass "out-of-path request never reached upstream"; fi
# the proxy percent-encodes everything but alphanumerics in the injected query value
SECRET_ENC="${SECRET//-/%2D}"
grep -qxF "GET /q?x=1&api_key=$SECRET_ENC auth=None xkey=None" "$UPLOG" && pass "query parameter injected (percent-encoded)" || fail "query parameter not injected"
grep -qxF "GET /k auth=None xkey=$SECRET" "$UPLOG" && pass "X-Api-Key header injected" || fail "X-Api-Key not injected"

# 6. The agent never sees the secret (verbose curl output captured and grepped).
VOUT="$W/curl-verbose.txt"
curl -sv --max-time 20 --proxy "http://x:$DEV@$PROXY" --cacert "$W/ca.pem" "$BASE/thing" >"$VOUT" 2>&1 || true
grep -q '< HTTP/1.1 200' "$VOUT" || fail "verbose request did not succeed"
curl -sv --max-time 20 --proxy "http://x:$QRY@$PROXY" --cacert "$W/ca.pem" "$BASE/q?x=1" >>"$VOUT" 2>&1 || true
if grep -qF "$SECRET" "$VOUT"; then fail "secret visible in agent-side curl -v output"; else pass "agent-side curl -v output contains no secret"; fi

# 7. Plain HTTP and SSRF-style targets.
BEFORE="$(wc -l <"$UPLOG")"
check "plain http to a ruled host refused" 403 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --proxy "http://x:$DEV@$PROXY" "http://localhost:$UPPORT/plain" || true)"
check "upstream log unchanged after plain http" "$BEFORE" "$(wc -l <"$UPLOG")"
grep -q '/plain' "$UPLOG" && fail "plain http request reached upstream" || pass "plain http request never reached upstream"
CONNECT_CODE="$(curl -s -o /dev/null -w '%{http_connect}' --max-time 20 --proxy "http://x:$DEV@$PROXY" --proxytunnel -k "https://127.0.0.1:$ADMIN_PORT/" || true)"
check "CONNECT to the admin port refused" 403 "$CONNECT_CODE"
CONNECT_CODE="$(curl -s -o /dev/null -w '%{http_connect}' --max-time 20 --proxy "http://x:$DEV@$PROXY" --proxytunnel -k "https://$PROXY/" || true)"
check "CONNECT to the proxy's own port refused" 403 "$CONNECT_CODE"

# 8. Revocation.
sc token revoke "$DEV_JTI" >/dev/null
check "revoked developer token" 407 "$(connect_code "$DEV" /thing)"
check "other tokens unaffected by revocation" 200 "$(req "$REV" GET /thing)"

# 9. Nothing sensitive at rest or in logs.
if grep -rqaF "$SECRET" "$DATA"; then fail "plaintext secret in the data dir"; else pass "no plaintext secret in database files"; fi
if grep -rqaF "$MASTER_KEY" "$DATA"; then fail "master key in the data dir"; else pass "no master key in database files"; fi
LEAK=0
for t in $SECRET $MASTER_KEY $ALL_TOKENS $(sc audit 2>/dev/null | grep -o 'eyJ[A-Za-z0-9._-]*' || true); do
  grep -qF "$t" "$W/serve.out" "$W/serve.err" 2>/dev/null && LEAK=1
done
# the login token is allowed once, on the admin line of stdout only
grep -qF "$LOGIN_TOKEN" "$W/serve.err" && LEAK=1
[ "$LEAK" = 0 ] && pass "server stdout/stderr contain no secret, master key or agent token" || fail "sensitive value in server logs"
if sc audit 2>&1 | grep -qF "$SECRET"; then fail "secret in audit output"; else pass "audit output contains no secret"; fi

# 10. Graceful shutdown.
kill -TERM "$SERVE_PID"
RC=0; wait "$SERVE_PID" || RC=$?
SERVE_PID=""
check "sc serve exit code after SIGTERM" 0 "$RC"
[ ! -e "$SOCK" ] && pass "socket removed after SIGTERM" || fail "socket still present after SIGTERM"

if [ "$FAILED" = 0 ]; then echo "E2E OK"; else
  echo "E2E FAILED"
  for f in serve.out serve.err upstream.log upstream.err; do echo "----- tail $f -----"; tail -n 25 "$W/$f" 2>/dev/null || true; done
  exit 1
fi
