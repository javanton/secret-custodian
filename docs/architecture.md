# Architecture

This page describes what Secret Guardian is, how the workspace is split into crates, how one injected
HTTPS request flows through the process, and why the main design decisions were taken. Everything here
is derived from the code in `crates/` at the commit this documentation was written against; where a
statement refers to a file, the file (and function) is cited so it can be checked.

Status: the crates `core`, `policy`, `auth`, `ca` and `proxy` are implemented. The crates `admin`, `cli`
and the binary `sg` exist in the workspace only as empty stubs (see [Planned](#planned-not-implemented)).

- Spec: [`docs/specs/2026-10-16-secret-guardian-vault.md`](specs/2026-10-16-secret-guardian-vault.md)
- Plan: [`docs/plans/2026-10-16-secret-guardian-vault.md`](plans/2026-10-16-secret-guardian-vault.md)

## 1. Purpose and threat model

Secret Guardian is a self-hosted vault, written in Rust, that lets an AI agent make authenticated HTTP(S)
requests to external APIs without ever holding or being able to read the credential. The agent
authenticates to a local proxy with a token that carries a **role**. The proxy intercepts the agent's
HTTPS traffic (a CONNECT tunnel that is terminated with a certificate from a locally generated CA),
looks up the rules of that role for the destination, **removes** any credential the agent supplied under
the same name, **injects** the decrypted secret and forwards the request to the real server.

It is a per-operator, single-instance tool: no central server, no multi-tenancy, no synchronisation
between instances (spec section 1).

The threat model summary (full table in spec section 2):

| Threat | Mitigation (where it lives) |
|---|---|
| The agent, or a prompt injection, tries to read the secret | The library API only exposes secret metadata (`SecretMeta`); the only decrypting call is `Vault::reveal_for_injection` (`crates/core/src/secrets.rs`), called from `crates/proxy/src/forward.rs`. |
| The database file is stolen | Secret values, the token signing key and the CA private key are AES-256-GCM ciphertext under a key that is not in the DB (see [crypto-and-keys.md](crypto-and-keys.md)). |
| The CA private key leaks | The CA carries X.509 name constraints, so it can only sign for the domains the operator allowed (see [tokens-and-ca.md](tokens-and-ca.md)). |
| An agent token leaks | Optional expiry, immediate revocation, and an audit trail keyed by `jti`. The proxy re-verifies the token before every request inside an open tunnel (`crates/proxy/src/mitm.rs`). |
| The agent uses the proxy to reach unplanned hosts | Per-role `Unmatched` policy: `passthrough` (opaque tunnel) or `deny` (see [policy-and-rules.md](policy-and-rules.md)). |
| The agent crafts paths that escape a restricted rule | Paths are judged "closed by construction" (see [policy-and-rules.md](policy-and-rules.md)). |

Explicit limit (spec section 2): an agent that can reach the proxy can make requests with the
permissions of its role. The guarantee is that it cannot extract the secret and that rules bound what it
can do with it. Secrets reflected by the destination in a response are out of scope.

The threat model items about the local web UI (rebinding, CSRF, sessions) belong to the planned `admin`
crate and are not implemented.

## 2. Crate map

The workspace (`Cargo.toml`) has eight members. Crate names on disk are `crates/<x>`; package names are
`sg-<x>` (the binary package is `sg`).

| Crate | Status | Responsibility | Public API (summary) | Depends on (workspace) |
|---|---|---|---|---|
| `core` (`sg-core`) | implemented | Encryption primitives, key derivation, the single SQLite file, schema, secrets, audit log, default paths. | `Vault` (`init`, `open`, `open_or_init`, `conn`, `seal_value`, `open_value`, secret CRUD, `reveal_for_injection`, `record_audit`, `list_audit`), `KeyInput`, `CoreError`, `SecretMeta`, `validate_secret_value`, `now`, modules `crypto` (`seal`, `open`, `random_key`, `kek_from_passphrase`, `kek_from_base64`), `audit` (`AuditEntry`, `AuditFilter`), `paths` (`default_data_dir`, `default_socket`). | none |
| `policy` (`sg-policy`) | implemented | Roles, rules and their validation; host/path/method matching; rendering the injected value. | `add_role`/`get_role`/`list_roles`/`remove_role`, `add_rule`/`list_rules`/`remove_rule`, `NewRule`, `Rule`, `Role`, `Unmatched`, `InjectionKind`, `PolicyError`, `evaluate`, `has_rules_for_host`, `Decision`, `normalize_host`, `normalize_path`, `is_ip_literal`, `render`. | `core` |
| `auth` (`sg-auth`) | implemented | Issues and verifies agent tokens (EdDSA JWT), revocation, parsing of `Proxy-Authorization`. | `TokenService` (`new`, `issue`, `revoke`, `revoke_machine`, `list`), trait `TokenVerifier`, `Identity`, `IssuedToken`, `TokenMeta`, `AuthError`, `extract_proxy_token`. | `core` |
| `ca` (`sg-ca`) | implemented | The name-constrained CA, leaf certificates, leaf cache. | `CaService` (`init_or_load`, `cert_pem`, `domains`, `allow_domain`, `is_host_permitted`, `server_config_for`), `CaError`, `crypto_provider`. | `core` |
| `proxy` (`sg-proxy`) | implemented (CONNECT/MITM only) | Proxy listener, CONNECT handling, TLS termination, per-request policy evaluation, injection, upstream relay, audit of proxy events. | `serve`, `serve_with`, `ServeOptions`, `ProxyState`, `UpstreamConfig`. | `core`, `policy`, `auth`, `ca` |
| `admin` (`sg-admin`) | planned (stub) | REST admin API, web sessions, embedded assets. | none yet (`crates/admin/src/lib.rs` is one line) | declared: `core`, `policy`, `auth`, `ca` |
| `cli` (`sg-cli`) | planned (stub) | `clap` client that talks to `admin` over a Unix socket. | none yet | declared: `core` |
| `sg` | planned (stub) | The single binary that assembles everything. | `crates/sg/src/main.rs` is one line | declared: all of the above |

Dependencies are exactly those of each `Cargo.toml` (`crates/*/Cargo.toml`). Note that `policy`, `auth`
and `ca` do not depend on each other: they only share `core`, and are composed by `proxy` (and later
by `admin`). `TokenVerifier` is a trait so another validator (for example OIDC, a future phase) could
be plugged into `ProxyState::verifier` without touching `policy` or `proxy`.

```mermaid
graph TD
    core["core (sg-core)<br/>crypto, SQLite, secrets, audit"]
    policy["policy (sg-policy)<br/>roles, rules, matching"]
    auth["auth (sg-auth)<br/>tokens, Proxy-Authorization"]
    ca["ca (sg-ca)<br/>name-constrained CA, leaves"]
    proxy["proxy (sg-proxy)<br/>CONNECT, MITM, injection"]
    admin["admin (planned)"]
    cli["cli (planned)"]
    sg["sg binary (planned)"]

    policy --> core
    auth --> core
    ca --> core
    proxy --> core
    proxy --> policy
    proxy --> auth
    proxy --> ca
    admin -.-> core
    admin -.-> policy
    admin -.-> auth
    admin -.-> ca
    cli -.-> core
    sg -.-> proxy
    sg -.-> admin
    sg -.-> cli
    sg -.-> core
    sg -.-> policy
    sg -.-> auth
    sg -.-> ca
```

Solid arrows are real dependencies in the implemented crates; dashed arrows are declared in the
`Cargo.toml` of the planned crates (they have no code yet).

### What each crate owns in the database

Every crate that persists data does so through the one `Vault` connection (see section 4):

| Crate | Tables / `meta` keys it writes |
|---|---|
| `core` | `meta` (`schema_version`, `kdf`, `salt`, `dek_wrapped`), `secrets`, `audit` |
| `policy` | `roles`, `rules` |
| `auth` | `tokens`, `meta.token_signing_key` |
| `ca` | `ca` |

Details per table are in [database-schema.md](database-schema.md).

## 3. Life of one injected HTTPS request

The diagram follows an agent running `curl https://api.example.com/repos/x` with
`HTTPS_PROXY=http://x:TOKEN@127.0.0.1:<port>` and a role that has a rule for `api.example.com`.
It is derived from `crates/proxy/src/server.rs` (`handle_request`, `connect`), `crates/proxy/src/mitm.rs`
(`serve`) and `crates/proxy/src/forward.rs` (`forward`). Audit writes are marked with `AUDIT`.

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent
    participant P as Proxy (server.rs)
    participant Au as auth (TokenService)
    participant Po as policy (roles, rules)
    participant C as ca (CaService)
    participant V as core (Vault + SQLite)
    participant U as Upstream server

    A->>P: CONNECT api.example.com:443 + Proxy-Authorization
    P->>Au: extract_proxy_token, verify(token)
    Au->>V: SELECT revoked_at FROM tokens WHERE jti
    Au-->>P: Identity (jti, machine, role)
    Note over P: no or bad token: 407, no audit row
    P->>Po: get_role(role), list_rules(role), has_rules_for_host(host)
    P->>C: is_host_permitted(host)
    P->>V: AUDIT decision=mitm status=200
    P-->>A: 200 (tunnel upgraded)
    A->>P: TLS ClientHello (SNI api.example.com)
    P->>C: server_config_for(host) (leaf, cached, ALPN h2 / http/1.1)
    C-->>P: rustls ServerConfig with leaf signed by the CA
    P-->>A: TLS handshake completes

    loop every inner request (HTTP/1.1 or HTTP/2)
        A->>P: GET /repos/x (inside the tunnel)
        P->>Au: verify(token) again (revocation / expiry)
        Note over P,V: failure: AUDIT token-invalid 407 and close the tunnel
        P->>P: host_is_consistent (Host / :authority == CONNECT host) else AUDIT host-mismatch 421
        P->>Po: normalize_path(uri.path())
        P->>Po: list_rules(role) (reloaded every request)
        P->>Po: evaluate(rules, host, method, path)
        Note over P,V: Forbidden or NoRuleForHost: AUDIT forbidden 403
        P->>V: reveal_for_injection(secret_id) (decrypt, AAD secret:{id})
        P->>Po: render(template, secret, kind)
        P->>P: inject::apply (strip agent credential, set header or query, forward normalized path)
        P->>U: new TCP + TLS connection (rustls, system roots + extra roots), HTTP/1.1 request
        U-->>P: response head, then streamed body
        P->>V: AUDIT decision=inject status=upstream status, rule_id
        P-->>A: response (hop-by-hop headers stripped)
    end
```

Step notes (all from the cited files):

1. **Authentication** (`server.rs`, `authenticate`): exactly one `Proxy-Authorization` header, at most
   8 KiB, parsed by `sg_auth::extract_proxy_token`, then `TokenVerifier::verify`. Any failure returns
   `407` with `Proxy-Authenticate: Basic realm="secret-guardian"`. **No audit row is written for a
   failed authentication** (there is no identity to attribute it to). A request that is not CONNECT
   gets `501` "plain HTTP proxying is not enabled yet".
2. **CONNECT target** (`server.rs`, `connect`): the authority must exist, contain no `@`, and its host
   must pass `normalize_host`; port defaults to 443; port 0 is rejected (`400`, no audit row).
3. **Role and rules**: an unknown role (e.g. the role was deleted after the token was issued) gives
   `403` with audit decision `unknown-role`. If the role has any rule whose host pattern matches the
   host (`has_rules_for_host`), the proxy MITMs; otherwise the role's `Unmatched` policy applies:
   `deny` gives `403` (`unmatched-denied`), `passthrough` opens a plain TCP tunnel to the destination and
   only then answers `200` (`passthrough`, or `tunnel-connect-failed` with `502`).
4. **CA check**: if the host has rules but the CA's name constraints do not permit it
   (`CaService::is_host_permitted`), the answer is `502` with a hint to run `sg ca allow-domain`
   (audit `ca-not-permitted`). The hint names a command that does not exist yet (planned CLI).
5. **TLS termination** (`mitm.rs`): after the `200`, the connection is upgraded, the leaf config for the
   host is obtained from `CaService::server_config_for`, and `hyper_util`'s auto builder serves HTTP/1.1
   or HTTP/2 according to ALPN.
6. **Per-request token check** (`mitm.rs`): the token is verified again before each inner request. If it
   fails (revoked, expired), the answer is `407`, the audit decision is `token-invalid`, and the
   connection is gracefully shut down. This applies to MITM tunnels only: a `passthrough` tunnel is an
   opaque byte copy (`copy_bidirectional`) and is not re-checked after it is established.
7. **Host consistency** (`forward.rs`, `host_is_consistent`): every `Host` header and the URI authority
   must normalise to the CONNECT host, and at least one must be present; otherwise `421`
   (`host-mismatch`). This stops an agent from reusing a tunnel (and its certificate) to address a
   different virtual host.
8. **Judging** (`forward.rs`): the path judged by `evaluate` is `normalize_path(uri.path())` and
   exactly that normalized path is what is forwarded (`inject::apply` rebuilds the URI from it).
   Rules are reloaded from the DB on each request, so rule changes apply to open tunnels immediately
   (test `rule_changes_apply_to_requests_inside_an_open_tunnel` in `crates/proxy/tests/inject.rs`).
9. **Reveal and render**: for every winning rule the secret is decrypted
   (`Vault::reveal_for_injection`) into a `Zeroizing<String>`, rendered into the template
   (`sg_policy::render`) and wrapped again in `Zeroizing`; the values are dropped as soon as the
   upstream request is on its way.
10. **Upstream** (`upstream.rs`): a fresh TCP connection per request (10 s connect timeout), TLS via
    `rustls` with system roots plus any extra roots given to `UpstreamConfig::new`, then an HTTP/1.1
    exchange; 60 s bound on handshake plus request until the response head arrives; the response body
    is streamed and not bounded. Failures give `502` with audit `upstream-error`.
11. **Audit and response**: the row (`inject`, status of the upstream response, id of the first
    matching rule) is written once the upstream response head has been received and before the response
    is returned to the agent (truncated bodies keep the status of the head that was sent). The audited path is the raw
    request path with the query string removed, not the normalized one. If writing the audit row fails,
    the error is logged and the request proceeds (`server.rs`, `audit`).

Audit decision values written by the proxy (all found in `server.rs`, `mitm.rs`, `forward.rs`):
`mitm`, `passthrough` (CONNECT and, in `forward`, no-rule requests, which cannot occur today because
`allow_unruled` is always `false`), `unmatched-denied`, `unknown-role`, `ca-not-permitted`,
`tunnel-connect-failed`, `token-invalid`, `host-mismatch`, `forbidden`, `plaintext-refused`
(unreachable today, since the only constructed `Ctx` has `tls: true`), `inject`, `upstream-error`.

Connection-level limits (`crates/proxy/src/lib.rs`, `ServeOptions`): at most 1024 simultaneous client
connections (excess clients wait in the kernel backlog because the permit is taken before `accept`), and
30 s to send a complete request head.

## 4. Concurrency model

- **One process, one tokio runtime.** `proxy::serve_with` spawns a task per accepted connection;
  MITM tunnels spawn another task for the TLS session (`tokio::spawn(crate::mitm::serve(...))`).
- **One SQLite connection.** `Vault` owns `Mutex<Connection>` (`crates/core/src/vault.rs`). All crates
  access the database through `Vault::conn()`, which returns a `MutexGuard`. A panic while holding the
  guard does not poison the vault: `conn()` recovers via `PoisonError::into_inner`, and rusqlite rolls
  back an open transaction when the connection's transaction is dropped during unwinding.
- **The mutex is not reentrant** (`std::sync::Mutex`). The rule used across the code base: never call
  `Vault::conn()` while already holding a guard, and never hold a guard while calling something that
  itself locks. Examples of how the code complies:
  - `TokenService::new` (`crates/auth/src/token.rs`) takes each guard as a temporary dropped at the end
    of its statement, so it is never held across `seal_value`/`open_value`.
  - `Vault::add_secret` takes the guard once, opens a transaction, and uses `self.seal_value` (which does
    not touch the connection) inside it. `rotate_secret` does lookup and update under one guard.
  - `Vault::reveal_for_injection` takes the guard only for the `SELECT` (a temporary), and decrypts after
    releasing it.
  - `CaService` has its own mutexes (`state`, `cache`, `cache_ttl`); the lock order is state then cache
    (`server_config_for` reads the state first, then takes the cache lock; `allow_domain` locks state,
    then clears the cache). The vault guard is a temporary in each statement.
- **Crypto calls are synchronous and run on the async worker threads** (AES-GCM and ed25519 are cheap;
  Argon2id only runs at `Vault::init`/`open` with a passphrase). SQLite calls also block the worker
  thread while holding the mutex; the design accepts this because it is a local single-operator tool.
- **CA leaf issuance** holds the cache lock while issuing so concurrent callers for one host share one
  leaf (`server_config_for`).
- **WAL mode** is enabled at init (`PRAGMA journal_mode=WAL`), but with a single connection per process the
  mutex, not SQLite, serialises access.

## 5. Design decisions and rationale

### Why a MITM proxy with a name-constrained CA

The requirement is that the agent never holds the secret, yet the request must reach the real API with
the secret in it. The credential therefore has to be added by something between the agent and the
server. For HTTPS that means terminating TLS, which requires a certificate the agent trusts. Compared to
alternatives (an HTTP gateway the agent calls with a different URL, or an SDK in the agent) a proxy needs
no change to agent code: standard tools honour `HTTPS_PROXY` and a CA bundle variable.

A MITM CA is dangerous if its key leaks. Two measures bound that: (1) the CA private key is stored
encrypted under the DEK (AAD `sg:ca-key`), and (2) the CA certificate has X.509 **name constraints**
(`permitted` DNS subtrees = the allowed domains, `excluded` = all IPv4 and IPv6 ranges), `pathlen:0`,
and key usage limited to `keyCertSign`/`crlSign` (`crates/ca/src/service.rs`, `ca_params`). A conforming
client refuses a leaf for any name outside the permitted set even if it was signed by this CA. With no
allowed domain the CA is limited to the reserved TLD `invalid`, so it is never unconstrained. Details
and caveats (public suffixes, clients that ignore name constraints) are in
[tokens-and-ca.md](tokens-and-ca.md).

### Why a single database file

Secrets, roles, rules, tokens, audit and the CA live in one SQLite file (`crates/core/src/schema.rs`).
Reasons visible in the code: foreign keys give integrity between rules, roles and secrets
(`ON DELETE RESTRICT` on `rules.secret_id`, `ON DELETE CASCADE` on `rules.role`); schema and `meta` rows
are created in one transaction so a half-initialised vault is never visible (`init_with`); and backup is
one file plus the key (see [database-schema.md](database-schema.md)). One DEK protects every encrypted
value, so the design allows changing the passphrase or key source by re-wrapping one 32-byte DEK
(rotation is not implemented in phase 1; see [crypto-and-keys.md](crypto-and-keys.md)).

### Why per-secret AAD

Every encrypted value is sealed with AES-256-GCM using an additional authenticated data (AAD) string
that names its purpose: `sg:dek`, `secret:{id}`, `sg:token-signing-key`, `sg:ca-key`. GCM authenticates
the AAD, so a ciphertext copied from one row or purpose to another fails to decrypt. Without it, anyone
who can write the database file could swap two secrets' `value_enc` blobs (for example making the
GitHub rule inject the value of another API's key) or replace the signing key blob. The test
`too_long_value_is_rejected_and_secret_cannot_move_between_rows` in `crates/core/tests/vault.rs` covers
the row-swap case. Note that the AAD includes the autoincrement `id`, which is never reused
(`AUTOINCREMENT`).

### Why closure-based path judging

A rule such as `GET /repos/*` must not authorise a request that some origin server would resolve to
`/admin`. Origins differ in how they decode `%XX`, strip `;params`, cut at `?`/`#`, treat `\`, and
resolve `..`. Rather than imitate one origin, the matcher makes the question moot: it reads the path at
every percent-decoding depth and refuses to judge (so the restricted rule does not match and the answer
is `403`) any path in which a dot-like segment exists under *any* separator model, plus control
characters, look-alike Unicode and a few other inputs. If nothing is left to resolve, no ordering of
origin operations can leave the prefix. The proxy also forwards the normalized path, so what is
authorised is what is sent. The argument, its assumptions A1-A6 and the side effects are described in
[policy-and-rules.md](policy-and-rules.md); an exhaustive test enumerates about 1.5 million paths against
an independent oracle.

### Other decisions visible in the code

- **Fail closed in policy.** An unparsable `unmatched_policy` is read as `deny` (`get_role`);
  an unjudgeable path never matches a restricted rule; a method excluded from the most specific rule
  does not fall back to a broader rule.
- **No plaintext in logs or errors.** Error bodies do not echo tokens or secret names (test
  `error_bodies_do_not_echo_tokens_or_secret_names` in `crates/proxy/tests/connect.rs`); the test
  `logs_never_contain_the_secret_or_the_token` (`crates/proxy/tests/no_leaks.rs`) captures all tracing
  output of a failing request.
- **Tokens are stateless but registered.** Verification checks the signature offline, then requires the
  `jti` to exist in `tokens` and not be revoked (details in [tokens-and-ca.md](tokens-and-ca.md)).

## Planned (not implemented)

The following is described in the spec and the plan but has no code today and must not be relied on:
the `admin` REST API and web UI, the `cli` crate and the `sg` binary (including `sg serve`, `sg keygen`,
`sg ca allow-domain`, key-file loading, `--upstream-ca`), Docker packaging, and the plain-HTTP proxy path
(today a non-CONNECT request gets `501`). See the plan:
[`docs/plans/2026-10-16-secret-guardian-vault.md`](plans/2026-10-16-secret-guardian-vault.md).
