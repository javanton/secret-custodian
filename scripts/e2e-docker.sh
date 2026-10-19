#!/usr/bin/env bash
# Docker end-to-end: builds the image, runs it hardened (non-root, read-only rootfs, no caps),
# configures it through `docker exec`, sends a real request through the published proxy port to a
# host-side TLS upstream, then checks graceful stop and persistence across a restart.
set -euo pipefail
cd "$(dirname "$0")/.."

for tool in docker curl openssl python3; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable by this user" >&2; exit 2; }
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy

IMAGE="secret-guardian:e2e-$$"
NAME="sg-e2e-$$"
KEYVOL="sg-e2e-key-$$"
DATAVOL="sg-e2e-data-$$"
W="$(mktemp -d)"
UP_PID=""; FAILED=0
cleanup() {
  [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker volume rm -f "$KEYVOL" "$DATAVOL" >/dev/null 2>&1 || true
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; FAILED=1; }
check() { if [ "$2" = "$3" ]; then pass "$1 (=$3)"; else fail "$1 (expected $2, got $3)"; fi; }
die() { echo "FAIL: $1"; docker logs "$NAME" 2>&1 | tail -n 30 || true; tail -n 20 "$W/upstream.log" 2>/dev/null || true; exit 1; }
freeport() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
dsg() { docker exec "$NAME" sg "$@"; }

echo "== build =="
docker build -q -t "$IMAGE" . >/dev/null || die "docker build failed"
pass "image builds"
check "container user is uid 10001" 10001 "$(docker run --rm --entrypoint id "$IMAGE" -u)"

# Key: generated inside the image as root into a volume, then handed to uid 10001 with mode 0400.
# (A host-owned file bind-mounted as a Docker secret keeps the host owner and is unreadable by uid 10001.)
docker volume create "$KEYVOL" >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$KEYVOL:/k" "$IMAGE" -c \
  'sg keygen --out /k/sg_key >/dev/null && chown 10001:10001 /k/sg_key && chmod 0400 /k/sg_key' || die "key generation"
docker volume create "$DATAVOL" >/dev/null

# Upstream on the host, reachable from the container via host.docker.internal. Cert SAN covers that name.
UPHOST="host.docker.internal"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$UPHOST" \
  -addext "subjectAltName=DNS:$UPHOST" -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$W/up.key" -out "$W/up.pem" 2>/dev/null
chmod 0644 "$W/up.pem"
UPLOG="$W/upstream.log"; : >"$UPLOG"
cat >"$W/up.py" <<'PY'
import http.server, ssl, sys, os
cert, key, log, portfile = sys.argv[1:5]
class H(http.server.BaseHTTPRequestHandler):
    def _h(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n: self.rfile.read(n)
        with open(log, "a") as f:
            f.write("%s %s auth=%s\n" % (self.command, self.path, self.headers.get("Authorization")))
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    do_GET = do_POST = _h
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("0.0.0.0", 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
open(portfile + ".tmp", "w").write(str(s.server_address[1])); os.rename(portfile + ".tmp", portfile)
s.serve_forever()
PY
python3 "$W/up.py" "$W/up.pem" "$W/up.key" "$UPLOG" "$W/up.port" 2>"$W/upstream.err" &
UP_PID=$!
for _ in $(seq 100); do [ -s "$W/up.port" ] && break; sleep 0.1; done
UPPORT="$(cat "$W/up.port")"

ADMIN_HOST_PORT="$(freeport)"; PROXY_HOST_PORT="$(freeport)"
start_container() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
    --add-host=host.docker.internal:host-gateway \
    -p "127.0.0.1:$ADMIN_HOST_PORT:9090" -p "127.0.0.1:$PROXY_HOST_PORT:8080" \
    -v "$DATAVOL:/data" -v "$KEYVOL:/run/secrets:ro" -v "$W/up.pem:/upstream-ca.pem:ro" \
    "$IMAGE" serve --data-dir /data --socket /data/sg.sock --key-file /run/secrets/sg_key \
      --proxy-bind 0.0.0.0:8080 --admin-bind 0.0.0.0:9090 \
      --admin-allowed-host "localhost:$ADMIN_HOST_PORT" --upstream-ca /upstream-ca.pem >/dev/null
  for _ in $(seq 150); do
    docker logs "$NAME" 2>/dev/null | grep -qx ready && return 0
    [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true ] || die "container exited before ready"
    sleep 0.2
  done
  die "container never printed ready"
}

echo "== start =="
start_container
pass "container printed ready"

echo "== admin port =="
check "admin: wrong Host header -> 421" 421 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: evil.example:9090' "http://127.0.0.1:$ADMIN_HOST_PORT/")"
check "admin: Host localhost:<port> serves the page" 200 "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: localhost:$ADMIN_HOST_PORT" "http://127.0.0.1:$ADMIN_HOST_PORT/")"

echo "== configure through docker exec =="
SECRET="E2E-DOCKER-SECRET-$RANDOM$RANDOM"
dsg --socket /data/sg.sock role add developer --unmatched deny >/dev/null
dsg --socket /data/sg.sock role add reviewer --unmatched deny >/dev/null
# A secret is created together with its first rule; the CA permits the rule's host from then on.
if printf '%s' "$SECRET" | docker exec -i "$NAME" sg --socket /data/sg.sock secret add norule-key >/dev/null 2>&1; then fail "secret add without rule flags succeeded"; else pass "secret add without rule flags is refused"; fi
dsg --socket /data/sg.sock secret ls | grep -q norule-key && fail "rejected secret was stored" || pass "rejected secret was not stored"
printf '%s' "$SECRET" | docker exec -i "$NAME" sg --socket /data/sg.sock secret add api-key --role developer --host "$UPHOST" --header Authorization --template 'Bearer {secret}' >/dev/null || die "secret add"
dsg --socket /data/sg.sock rule add --role reviewer --host "$UPHOST" --methods GET --header Authorization --template 'Bearer {secret}' --secret api-key >/dev/null
dsg --socket /data/sg.sock ca status | grep -q "$UPHOST" && pass "ca status lists the rule host" || fail "ca status does not list $UPHOST"
dsg --socket /data/sg.sock ca export >"$W/ca.pem"
jget() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
DEV="$(dsg --socket /data/sg.sock --json token create --machine e2e --role developer | jget token)"
REV="$(dsg --socket /data/sg.sock --json token create --machine e2e --role reviewer | jget token)"
check "healthcheck command succeeds" 0 "$(docker exec "$NAME" sg --socket /data/sg.sock ca status >/dev/null 2>&1; echo $?)"

echo "== requests through the published proxy port =="
BASE="https://$UPHOST:$UPPORT"
# curl resolves host.docker.internal through --resolve (the proxy, in the container, resolves it itself).
req() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 --proxy "http://x:$1@127.0.0.1:$PROXY_HOST_PORT" \
          --resolve "$UPHOST:$UPPORT:127.0.0.1" --cacert "$W/ca.pem" -X "$2" "${@:4}" "$BASE$3" || true; }
check "developer GET via container proxy"  200 "$(req "$DEV" GET /thing)"
check "developer POST via container proxy" 200 "$(req "$DEV" POST /thing -d x=1)"
check "reviewer GET"                       200 "$(req "$REV" GET /thing)"
check "reviewer POST is forbidden"         403 "$(req "$REV" POST /thing -d x=1)"
grep -qxF "GET /thing auth=Bearer $SECRET" "$UPLOG" && pass "upstream received the injected secret" || fail "secret not injected"
[ "$(grep -c '^POST ' "$UPLOG")" = 1 ] && pass "reviewer POST never reached upstream" || fail "unexpected POST count"
if docker logs "$NAME" 2>&1 | grep -qF "$SECRET"; then fail "secret in container logs"; else pass "container logs contain no secret"; fi

echo "== graceful stop and persistence =="
START=$(date +%s)
docker stop -t 20 "$NAME" >/dev/null
check "exit code after docker stop" 0 "$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
[ $(( $(date +%s) - START )) -lt 15 ] && pass "stopped promptly on SIGTERM (not killed after timeout)" || fail "stop took too long"
start_container
pass "restarted with the same volume"
dsg --socket /data/sg.sock secret ls | grep -q api-key && pass "secret survived the restart" || fail "secret lost on restart"
dsg --socket /data/sg.sock role ls | grep -q reviewer && pass "roles survived the restart" || fail "roles lost on restart"
check "old developer token still valid after restart" 200 "$(req "$DEV" GET /after-restart)"
dsg --socket /data/sg.sock ca export >"$W/ca2.pem"
cmp -s "$W/ca.pem" "$W/ca2.pem" && pass "CA certificate unchanged across restart" || fail "CA changed across restart"

if [ "$FAILED" = 0 ]; then echo "E2E DOCKER OK"; else echo "E2E DOCKER FAILED"; docker logs "$NAME" 2>&1 | tail -n 30; exit 1; fi
