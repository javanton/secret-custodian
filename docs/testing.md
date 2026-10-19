# Testing

How the project is tested, what each suite covers, how to run it, how to add tests, and what is **not** covered.
Counts below come from a real `cargo test --workspace` run on the commit this page was written against (515 tests
passed, 1 ignored). They will drift as tests are added: run the
command to get the current numbers.

## Strategy

| Level | What | Where | Run |
|---|---|---|---|
| Unit | Pure logic next to the code: crypto, path normalization and the matcher, formatting, argument parsing, key handling | `#[cfg(test)]` modules in `crates/*/src` | `cargo test -p <crate>` |
| Integration (library) | A crate's public behaviour against a real SQLite file in a temp directory: vault, policy store, token service, CA | `crates/{core,policy,auth,ca}/tests` | `cargo test -p <crate>` |
| Integration (network) | The proxy against **real TLS and plain TCP test upstreams** on ephemeral loopback ports, with real rustls clients: injection, hardening, limits, SSRF policy, streaming | `crates/proxy/tests` | `cargo test -p sg-proxy` |
| Integration (HTTP) | The admin routers driven in-process (`tower::ServiceExt::oneshot`) and real listeners for the socket and web servers | `crates/admin/tests` | `cargo test -p sg-admin` |
| Client | CLI commands against a fake admin server on a Unix socket | `crates/cli/tests` | `cargo test -p sg-cli` |
| Binary end to end (Rust) | The real `sg` binary spawned on ephemeral ports: CLI flow, web login, signals, key-source errors | `crates/sg/tests/cli_e2e.rs` | `cargo test -p sg` |
| Page logic | The browser code's pure functions under `node --test` (no browser) | `crates/admin/tests/js` | run by `cargo test -p sg-admin`, or `node --test crates/admin/tests/js/app.test.js` |
| Script end to end (host) | Real `curl` through the real `sg` proxy to a real local TLS upstream | `scripts/e2e.sh` | `scripts/e2e.sh` |
| Script end to end (Docker) | The same through the built image, hardened flags, restart persistence | `scripts/e2e-docker.sh` | `scripts/e2e-docker.sh` (needs Docker) |
| Exhaustive | An independent oracle against the path matcher over about 1.5 million paths | `crates/policy/src/matcher.rs` | `cargo test -p sg-policy --release -- --include-ignored` |

Principles used throughout:

- **Test against real things.** Real SQLite files, real TLS handshakes, real sockets, the real binary. Mocks appear
  only where the thing mocked is not under test (the CLI tests use a fake server because the CLI is the subject).
- **Every security property has a test that fails if the property is removed**: the tests listed under
  [Security regression tests](#security-regression-tests).
- **Tests never touch your data.** They use `tempfile` directories (mode `0700` where sockets are involved), ephemeral
  ports and private sockets.
- **Altitude.** While developing run the tests of the crate you changed (`cargo test -p <crate>`); run the whole
  workspace once before integrating; do not repeat it in review.

## Running tests

```sh
cargo test -p sg-policy                        # one crate (package names are sg-<dir>; the binary package is `sg`)
cargo test -p sg-proxy --test inject           # one integration file
cargo test --workspace                         # everything (515 passed, 1 ignored, about 4 min cold)
cargo test -p sg-policy --release -- --include-ignored   # + the exhaustive path test (1 min 07 s wall incl. build)
node --test crates/admin/tests/js/app.test.js  # JS logic tests alone (9 tests, about 0.1 s)
scripts/e2e.sh                                 # real curl through the real proxy (needs curl, openssl, python3)
scripts/e2e-docker.sh                          # same inside Docker (needs a reachable Docker daemon)
cargo fmt --all --check                        # formatting
cargo clippy --workspace --all-targets -- -D warnings   # lints, warnings are errors
```

The workspace is warning-free under `clippy -D warnings` and `fmt --check` at this commit. The `node` test is
skipped (with a message) when `node` is not installed. `sg-policy`'s exhaustive test is the only `#[ignore]`d test;
its release run measured 37.0 s of test time (a quick variant over about 5 thousand paths runs in the normal suite).

## Inventory per crate

Counts are `passed` per binary from the workspace run (unit tests are the `src/` modules; doc tests: none).

| Crate | Unit | Integration files (tests) | Total |
|---|---|---|---|
| `sg-core` | 20 | `audit` (10), `vault` (24) | 54 |
| `sg-policy` | 58 (+1 ignored) | `conn_api` (2), `policy` (19) | 79 (+1 ignored) |
| `sg-auth` | 4 | `tokens` (30) | 34 |
| `sg-ca` | 0 | `ca` (37) | 37 |
| `sg-proxy` | 14 | `connect` (20), `hardening` (12), `inject` (26), `limits` (18), `netpolicy` (13), `no_leaks` (1), `plain_and_streaming` (29), `review_fixes` (10) | 143 |
| `sg-admin` | 2 | `api` (25), `hygiene` (2), `ops` (1), `serve` (14), `sessions` (11), `web_assets` (5, one of which runs the 12 `node` tests), `web_guard` (17) | 77 |
| `sg-cli` | 20 | `client` (8), `run` (36) | 64 |
| `sg` | 13 | `cli_e2e` (14) | 27 |
| **Workspace** | | | **515 passed, 1 ignored** |

### What each suite covers

- **`sg-core`**: AES-256-GCM format, wrong-AAD and tamper failures, Argon2id known-answer pin, vault init/open (file
  mode `0600` before SQLite opens it, failed init leaves nothing, missing vault is not created, unsupported schema),
  secret CRUD and validation, plaintext never in database files (`database_file_never_contains_plaintext_secret`),
  audit bounds and query stripping, default paths.
- **`sg-policy`**: host/path/method matching, specificity, fail-closed method behaviour, rule validation, role store,
  path normalization and judging (hundreds of cases), the oracle tests.
- **`sg-auth`**: token format, strict header, signature before claims, expiry before revocation, `Proxy-Authorization`
  parsing, TTL bounds, signing-key creation under races.
- **`sg-ca`**: name constraints verified by a real rustls client (forged leaf outside the domains refused, forged IP
  leaf refused), domain validation, probe, re-issue with the same key, leaf cache bound and validity.
- **`sg-proxy`**:
  - `connect`: 407/403/502/400 paths, passthrough, IPv6 literals, concurrent tunnels, audit before response, no echo of
    tokens or secret names, oversized or duplicate `Proxy-Authorization`, header timeout, connection cap.
  - `inject`: header and query injection, agent credentials discarded, restricted-path traversal cases, normalized
    path forwarded, host consistency, audit shape, streaming, revocation of an open tunnel, live rule changes, upstream
    TLS failures and timeouts.
  - `hardening`: routing-override headers (including underscore variants and HTTP/2), `TRACE`/`TRACK`/`CONNECT`, COPY/MOVE
    rules, query separators, absolute-form targets.
  - `limits`: connection slots held by tunnels, handshake/idle/lifetime bounds (HTTP/1.1, HTTP/2, passthrough), upstream
    cap, per-identity caps, stalled readers cut in both directions.
  - `netpolicy`: loopback, link-local, metadata, RFC 1918, NAT64/6to4, denied binds, the `localhost` exception, single
    resolution.
  - `plain_and_streaming`: plain HTTP never injected, unmatched policy, 400 forms, `Expect: 100-continue`, chunked and
    large bodies, upstream dying mid-response, 50 concurrent requests.
  - `no_leaks`: captures all `tracing` output of a failing request and asserts the secret and token are absent (own test
    binary, because tracing caches callsite interest process-wide).
- **`sg-admin`**: every route and status, validation errors, `deny_unknown_fields`, the guard order, cookies ignored,
  Origin/Host handling, security headers, static assets, socket binding rules (0600, symlink, live socket, stale socket,
  loose directory), connection limits and lifetimes, session and login-token behaviour (single use under concurrency,
  expiry, caps, no cleartext in memory), and source-level hygiene (no `reveal_for_injection`, no request-URI logging,
  no dangerous DOM sinks in `web/app.js`).
- **`sg-cli`**: output formats, secret input rules (stdin, prompt, limits, scrubbing), TTL parsing, proxy-URL checks,
  error mapping, socket ownership checks, size caps.
- **`sg`**: key file and key-source handling; the e2e tests start the real binary and check the full CLI flow without
  echoing the secret, that the database stays encrypted, web login against the live server, key-source error messages,
  socket and data-directory permissions, `SIGTERM`/`SIGINT` (socket removed, exit 0), a second instance failing without
  damaging the first, the non-loopback bind warning, `--admin-allowed-host`, and that the proxy and admin ports are denied
  as CONNECT targets.

## End-to-end scripts

### `scripts/e2e.sh` (host)

Builds `sg`, starts a TLS upstream (Python, self-signed for `localhost`, logging the method, path and the credential
headers it receives), a vault with dynamic ports and a private temp directory, then asserts (all with real `curl`):

| Area | Assertions |
|---|---|
| Role behaviour | developer `GET` and `POST` succeed (200); reviewer `GET` succeeds and `POST` is `403`; unknown token is `407`; a path-restricted role gets `200` for `/repos/ok` and `403` for `..%2f`, `../` traversal and an out-of-prefix path; query-injection and `X-Api-Key` rules answer `200` |
| What the upstream saw | `Authorization: Bearer <secret>` on allowed requests; the reviewer's `POST` and every traversal never reached it; the query parameter arrives percent-encoded; the custom header arrives |
| Agent blindness | the secret does not appear in `curl -v` output on the agent side |
| Plain HTTP and SSRF | plain `http://` to a ruled host is `403` and never reaches the upstream; CONNECT to the admin port and to the proxy's own port is `403` |
| Revocation | a revoked token gets `407`; others are unaffected |
| Nothing sensitive at rest or in logs | no plaintext secret and no master key in the data directory; server stdout/stderr contain no secret, master key or agent token; the audit output contains no secret |
| Shutdown | `SIGTERM` exits 0 and removes the socket |

It prints `PASS:`/`FAIL:` lines (33 checks in the latest run) and ends with `E2E OK`.

### `scripts/e2e-docker.sh` (Docker)

Builds the image and runs it with `--read-only`, `--cap-drop ALL`, `no-new-privileges`; checks the user is uid 10001;
generates the key inside a volume (the permission pitfall in [operations.md](operations.md#containers-and-networking));
checks the admin port (`421` for a wrong Host, `200` for the allowed one); configures through `docker exec`; sends real
requests through the published proxy port to a host-side TLS upstream; checks the container logs contain no secret;
`docker stop` exits 0 within seconds; restarts on the same volume and checks that the secret, roles, an old token and
the CA certificate survived. It ends with `E2E DOCKER OK`. This guide's authors did not rerun it while writing the
documentation (it had been verified before); the Docker commands in the README and operations guide were run separately.

## Security regression tests

Where each class of security property is pinned:

| Property | Tests |
|---|---|
| Path-restricted rules cannot be escaped | **The oracle**: `crates/policy/src/matcher.rs` contains an independent re-implementation of origin behaviour (`oracle_decode`, `oracle_strip`, `oracle_resolve`, `oracle_escape`; it shares no code with the matcher) that applies every sequence of up to five origin operations (decode, strip `;params`, cut at `?`/`#`, map `\` to `/`, resolve dots) to a path, and asserts that anything the matcher authorises never resolves outside `/repos/`. `exhaustive_prefix_rule_never_authorizes_an_escaping_path` runs a token length of 3 (about 5 thousand paths) in the normal suite; the `_full` variant runs token length 5 (about 1.5 million paths) and is `#[ignore]`d. `oracle_sanity` checks that the oracle itself detects known escapes. Hand-written witnesses live in `crates/policy/tests/policy.rs` and `matcher.rs` tests; end-to-end cases (`path_traversal_cannot_escape_a_restricted_rule`, `witness_that_normalizes_into_the_prefix_is_forwarded_normalized`, GitLab-style `%2F`) in `crates/proxy/tests/inject.rs`. Run the full variant after any change to `normalize.rs` or `matcher.rs` |
| No secret in any API response, log, error or file | `no_route_ever_returns_a_secret_value`, `error_bodies_never_leak_internals`, `admin_never_references_reveal_for_injection`, `admin_does_not_log_request_uris`, `logs_never_contain_the_secret_or_the_token`, `error_bodies_do_not_echo_tokens_or_secret_names`, `database_file_never_contains_plaintext_secret`, `full_cli_flow_never_echoes_the_secret_and_db_stays_encrypted`, the e2e scripts' log greps |
| Proxy hardening | `hardening.rs` (routing headers, TRACE/CONNECT, COPY/MOVE), `netpolicy.rs` (SSRF), `limits.rs` (resource bounds), `plain_and_streaming.rs` (no plain-HTTP injection), `inject.rs` (host mismatch, revocation of open tunnels) |
| Web UI hardening | `web_guard.rs` (cookies ignored, bearer exactly once, Origin on writes, Host everywhere, no CORS headers, guard order, CSP and headers), `sessions.rs`, `web_assets.rs` (no dangerous DOM sinks or ambient credentials, fragment plus `sessionStorage` plus bearer), the `node` tests (hostile strings rendered as text, `el()` never parses HTML) |
| CA constraints | `ca.rs`: real verifiers refuse a forged leaf for a name outside the constraints and for IP names |
| Permissions | `socket_is_0600_and_serves_the_api`, `refuses_a_parent_directory_open_to_group_or_others`, `socket_and_data_dir_are_private`, key file mode tests, `wal_and_shm_files_are_private_while_open` |

## Adding tests

1. **Pick the lowest level that can show the behaviour.** A pure function: a unit test beside it. A stored property: an
   integration test in the crate's `tests/` with a temp `Vault` (`Vault::init(&dir.join("v.db"), KeyInput::Raw(crypto::random_key()))`).
2. **Proxy behaviour:** use the helpers in `crates/proxy/tests/common/mod.rs`: `Env` wires a vault, token service, CA and
   proxy on an ephemeral port; `spawn_tls_upstream(host)` / `spawn_plain_upstream()` give a recording upstream;
   `env_with_upstream(host)` combines them with a CA that allows `host`; `raw_connect`, `raw_head` and `echo_server` support
   byte-level tests. Prefer a real TLS client for anything about certificates.
3. **Admin behaviour:** build the router with `api_router`/`socket_router`/`web_router` (see `crates/admin/tests/api.rs`
   for the `env()` helper) and call it with `tower::ServiceExt::oneshot`; use the `serve_*` functions with real listeners for
   limits and socket checks. Remember the web guard order when asserting status codes (Host, session, Origin, content type,
   body).
4. **A new security property gets a regression test that fails without the fix**: write the test first, watch it fail,
   then fix.
5. **Name tests as sentences** (`a_revoked_token_gets_407`): the name is the documentation in a failure.
6. **Never hard-code ports or paths**: bind port 0, use `tempfile`, and keep socket directories `0700`.
7. **Do not commit slow tests into the default suite**: put them behind `#[ignore = "reason"]` and document the command,
   as the exhaustive path test does.
8. Keep `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean.

## Known gaps

- **The web UI has not been verified in a real browser by the authors.** It is covered by Rust tests of the server side
  (headers, guards, login flow, assets), source scans for dangerous DOM sinks, and `node` tests of the page's pure logic
  (fragment parsing, TTL parsing, 401 handling, `el()` building text nodes, hostile strings). Layout, focus handling,
  clipboard use, the CA download button and the whole interactive flow have never been exercised in Chrome, Firefox or
  Safari. Treat the UI as untested in browsers and report problems.
- No fuzzing of the HTTP parsing, the `Proxy-Authorization` parser or the JSON bodies beyond the cases written by hand.
- No load or soak testing beyond 50 concurrent requests and the limit tests; no test of very long-lived tunnels beyond the
  shortened timeouts used by the limit tests.
- Compatibility is tested with `curl`, rustls clients and hand-written TLS clients, plus a manual check with Python and
  Node. There is no automated matrix of agent tools (Claude Code, `gh`, `git`, Go, Java, browsers...).
- Strict X.509 clients: `openssl_strict_verification_accepts_leaves` runs `openssl verify -x509_strict` against fresh and
  reloaded CAs (skipped with a message when `openssl` is missing); Python 3.14 was checked manually, not in the suite.
- Platform: only Linux is tested. The program reads `/proc/self`, so other systems are unsupported.
- When `node` is missing the JS logic test only prints a message and passes, so a machine without it runs `cargo test`
  green without having run them.
- `scripts/e2e-docker.sh` needs a Docker daemon and is not part of `cargo test`; nothing runs automatically (there is no
  CI configuration in the repository).
