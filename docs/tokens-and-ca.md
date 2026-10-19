# Tokens and the CA

This page covers how agents authenticate (the token and the `Proxy-Authorization` header) and how the
proxy's certificate authority works (name constraints, domains, leaf certificates, and what agents must do
to trust it). Sources: `crates/auth/src/{token,header}.rs`, `crates/ca/src/service.rs`,
`crates/proxy/src/{server,mitm}.rs` and the tests in `crates/auth/tests/tokens.rs` and
`crates/ca/tests/ca.rs`. See also [crypto-and-keys.md](crypto-and-keys.md) and
[database-schema.md](database-schema.md).

## Part 1: Tokens

### 1.1 Format

A token is a compact JWT-style string `header.payload.signature`, three base64url segments without
padding (`URL_SAFE_NO_PAD`):

| Part | Content |
|---|---|
| header | The exact bytes `{"alg":"EdDSA","typ":"JWT"}` (constant `HEADER`). |
| payload (claims) | JSON with `iss` = `"secret-guardian"`, `jti` (UUID v4), `sub` (the machine label), `role`, `iat` (issue time, Unix seconds) and optional `exp` (omitted when the token has no expiry). |
| signature | Ed25519 signature (64 bytes) over the ASCII string `base64url(header) + "." + base64url(payload)`. |

One token is valid for one role. A machine can have several tokens (for example `developer` and
`reviewer`); the machine label `sub` is used for audit and for bulk revocation.

The signing key is a random 32-byte Ed25519 seed created the first time `TokenService::new` runs and
stored encrypted in `meta.token_signing_key` (AAD `sg:token-signing-key`); concurrent first creators use
`INSERT OR IGNORE` and re-read, so they converge on one key (test `racing_first_creators_converge_on_one_key`).
A token from one vault does not verify on another (test `token_from_one_vault_does_not_verify_on_another`).

### 1.2 Issuing

`TokenService::issue(machine, role, ttl: Option<Duration>) -> IssuedToken { token, jti }`:

1. `iat = now()`. With a TTL, `exp = iat + ttl`; if the TTL in seconds does not fit `i64`, or the addition
   overflows, the call returns `AuthError::InvalidTtl` ("ttl out of range") and nothing is stored
   (test `out_of_range_ttl_is_rejected_without_inserting_a_row`).
2. A zero TTL is accepted and yields a token that is already expired (`exp == iat`, and expiry is `now >= exp`).
3. The token is signed and a row is inserted into `tokens` (`jti`, `machine`, `role`, `created_at`,
   `expires_at`, and `token_hash` = hex SHA-256 of the token).
4. The token string is returned to the caller once. It is not stored in clear and cannot be listed again
   (`TokenService::list` returns `TokenMeta` without it).

`issue` does not check that the role exists: tokens for a non-existent role can be issued and then fail with
`403` (`unknown-role`) at CONNECT. The library does not limit the maximum TTL; the admin API and the CLI cap it at 10 years (315360000 s). The admin API
also checks that the role exists (`unknown role`).

### 1.3 Verification order

`TokenVerifier::verify(token) -> Result<Identity, AuthError>` (`Identity` = `jti`, `machine`, `role`):

1. Split on `.`: exactly three parts, else `Invalid`.
2. Decode the header and compare to the exact `HEADER` bytes, so `alg: none`, other algorithms and other
   header spellings are rejected (`Invalid`).
3. Decode the signature to exactly 64 bytes (non-canonical or padded encodings fail to decode) and check it
   with `verify_strict` over `header.payload` using the vault's verifying key. **The signature is verified before
   the claims are parsed.**
4. Parse the claims as JSON (missing fields or wrong types: `Invalid`).
5. `iss` must equal `secret-guardian` (`Invalid`).
6. If `exp` is present and `now >= exp`: `Expired`. This is evaluated **before** the revocation lookup
   (test `expiry_is_evaluated_before_the_revocation_lookup`).
7. Look up `revoked_at` by `jti` in `tokens`: no row gives `Invalid` (a correctly signed token whose row is missing is
   not accepted), a non-null `revoked_at` gives `Revoked`, otherwise the `Identity` is returned.

So verification is offline except for that one `SELECT` by `jti`. The `role` and `sub` that become the identity
come from the signed claims, not from the row. `tokens.token_hash` is not consulted.

### 1.4 Revocation

- `revoke(jti)`: sets `revoked_at = now()` where it is still `NULL`; returns `NotFound` if the `jti` is unknown
  **or already revoked**.
- `revoke_machine(machine)`: revokes every not-yet-revoked token of the machine and returns how many.
- The proxy checks the token at CONNECT and again before **every** request inside a MITM tunnel
  (`mitm.rs`): a revoked or expired token gets `407`, audit `token-invalid`, and the tunnel is shut down
  (test `revoking_the_token_stops_an_open_tunnel`). Passthrough tunnels are not re-checked once established.
- Expired rows are never deleted by the code.

### 1.5 `Proxy-Authorization` parsing

`sg_auth::extract_proxy_token(header_value) -> Option<String>` (`crates/auth/src/header.rs`):

- Trim the value, split at the **first space** into scheme and rest; trim the rest; an empty rest gives `None`.
- Scheme is matched case-insensitively.
- `Bearer <token>`: the rest, as is, is the token.
- `Basic <base64>`: standard base64 (with padding) of `user:password`, must be valid UTF-8; the token is the
  **password**, i.e. everything after the **first** colon (a password containing `:` is kept whole);
  the user name is ignored; no colon, empty password, invalid base64 or invalid UTF-8 give `None`.
  This is what `HTTPS_PROXY=http://x:TOKEN@host:port` makes clients send.
- Any other scheme (`Digest`, ...) gives `None`.

The proxy adds its own bounds before calling it (`server.rs`, `authenticate`): there must be exactly one
`Proxy-Authorization` header (duplicates give `407`), at most 8 KiB (`MAX_PROXY_AUTH_LEN`), and the value
must be a valid header string. Any failure is `407 Proxy Authentication Required` with
`Proxy-Authenticate: Basic realm="secret-guardian"`, and no audit row is written. A `403` is returned only
once the token is valid but the role does not exist or the host is denied.

### 1.6 What is stored

Only metadata, in the `tokens` table (columns in [database-schema.md](database-schema.md)): `jti`, `machine`,
`role`, `created_at`, `expires_at`, `revoked_at` and the SHA-256 hex digest. The signing key is in `meta`.
Audit rows carry `jti`, `machine` and `role` for every proxied request.

## Part 2: The CA

### 2.1 What the CA is

`CaService` (`crates/ca/src/service.rs`) owns one self-signed CA, created on first use
(`CaService::init_or_load`) and stored in the `ca` table: public certificate PEM, private key sealed under the
DEK (AAD `sg:ca-key`), and the JSON list of permitted domains, which the admin crate keeps equal to the set derived from the rules (section 2.3). The key is an ECDSA key generated by `rcgen`.

CA certificate properties (`ca_params`):

| Property | Value |
|---|---|
| Subject | CN = `Secret Guardian CA` |
| Basic constraints | CA, path length 0 (`Constrained(0)`), critical: it can only sign leaves |
| Key usage | `keyCertSign`, `cRLSign` only |
| Subject Key Identifier | SHA-256 based, derived from the CA public key, so it is the same in every re-issued certificate |
| Validity | `not_before` = now minus 1 day, `not_after` = now plus 3650 days |
| Serial | 16 random bytes with the top bit cleared (positive), generated at every build |
| Name constraints | permitted DNS subtrees = the permitted domains (derived from the rules); excluded IP subtrees = `0.0.0.0/0` and `::/0` |

Leaf certificate properties (`issue_leaf`), all required by strict verifiers (OpenSSL `X509_STRICT`, Python 3.13+):

| Extension | Value |
|---|---|
| Subject Alternative Name | the requested host (DNS name) |
| Basic constraints | `CA:FALSE`, critical |
| Key usage | `digitalSignature` |
| Extended key usage | `serverAuth` only |
| Authority Key Identifier | `keyid` equal to the CA's Subject Key Identifier |
| Subject Key Identifier | derived from the leaf key |
| Validity | about 24 hours |

The AKI and SKI are derived from the CA key, so they do not change when the CA certificate is re-issued or when
the service reloads from the vault (tests `leaf_aki_equals_ca_ski_fresh_after_allow_domain_and_after_reload` and
`openssl_strict_verification_accepts_leaves`, which runs `openssl verify -x509_strict` when the binary exists).

### 2.2 Name constraints

- With **no** permitted domain (no rules), the single permitted subtree is the reserved TLD `invalid` (test
  `fresh_ca_certificate_contains_name_constraints_for_invalid_only`), so the CA is never unconstrained.
- Once domains exist, the permitted subtrees are exactly those domains (the `invalid`
  placeholder is dropped; it comes back when the last rule disappears). Per RFC 5280 a DNS constraint `github.com` covers `github.com` and its subdomains
  such as `api.github.com`.
- All IP addresses are excluded explicitly because DNS constraints do not restrict IP-address SANs (tests
  `forged_ip_leaves_are_refused_by_the_real_ca_constraints`).
- The security value is that a conforming client rejects a leaf for any other name even if it is signed by the
  CA key (test `verifier_enforces_name_constraints_against_a_forged_leaf`). The spec notes (section 11) that not every TLS
  library enforces name constraints; the constraint protects only clients that do.

### 2.3 The CA follows the rules

The permitted domains are not configured by hand: the admin crate derives them from the stored rules and keeps the CA
equal to that set. There is no `sg ca allow-domain` and no `POST /ca/domains`. (`CaService::allow_domain` survives only as a
library call that the CA and proxy tests use to set up a domain; the admin crate never calls it, and its name appears in
some test names below for that reason.)

**Derivation** (`sg_policy::derive_ca_domains`): the host of every rule, with a leading `*.` removed (`*.example.com`
becomes `example.com`, which already covers every subdomain under RFC 5280), sorted and deduplicated, so `x` and `*.x`
together give one entry.

**When it runs.** Inside the same SQLite transaction as every change that touches rules (`crates/admin/src/ops.rs`):

| Operation | CA effect |
|---|---|
| `POST /secrets` (secret plus its first rule(s)) | domains added if new |
| `POST /rules` | domain added if new |
| `DELETE /rules/{id}` | domain dropped if no other rule uses it |
| `DELETE /secrets/{name}` (its rules go too) | domains dropped if nobody else uses them |
| `DELETE /roles/{name}` (its rules go too; refused if it would orphan a secret) | domains dropped if nobody else uses them |
| `sg serve` start-up (`sync_ca`) | one sync of the CA with the existing rules |

**Prepare, commit, install.** `CaService::prepare_domains` validates the set (`validate_domain`), builds the new
certificate with the same key and a new random serial, and **probes** it; `persist` writes it inside the operation's
transaction; `install` swaps it into memory (and clears the leaf cache) only after the transaction commits. If
anything fails (a rejected host, a failed probe) the transaction rolls back: no rule, no secret and no CA change.
Both adding and removing a domain re-issue the certificate; an unchanged set is a no-op (`ca_changed: false`).

**Validation** (`validate_domain`, reason in `domain rejected: <reason>`):

- only `[a-z0-9.-]`; not empty; no leading or trailing dot; no `..`;
- at most 253 bytes; each label 1 to 63 bytes, not starting or ending with `-`;
- the last label must not be all digits (rejects `example.123`, `1.2.3.4`);
- not an IP address; not `invalid` or `*.invalid` (`reserved`: that TLD is the placeholder);
- single-label names are rejected (TLDs such as `com`), except `localhost`.

Rule validation applies the same DNS rules to `host_pattern` (with a leading `*.` removed; `localhost` is allowed), so a
new rule can never name a host the CA would refuse and such a request gets a `400`. The CA validation remains as a
safety net. Rules stored by older builds may still hold such hosts: when the CA domains are derived (every rule
operation and `sg serve` startup) those hosts are skipped with a `warn` log line naming them, which only narrows the CA
(they cannot be intercepted) instead of failing the operation.

**The probe** (`probe`): with the new certificate as the only trust anchor and rustls-webpki's verifier, a
throw-away leaf is issued and verified for `probe.<domain>` for **every** domain of the new set (or the bare domain if
the name would exceed 253 bytes). If any verification fails the call returns
`DomainRejected("would invalidate the CA name constraints")`. The point is that a name webpki would refuse can never
make the whole CA unusable.

**Start-up sync.** Each `sg serve` start makes the stored CA equal to the derived set once. Domains that no rule uses
(for example added by hand with the removed `ca allow-domain`) are dropped; domains rules need are added. A second start
changes nothing. See [operations.md](operations.md#upgrading-from-a-version-without-required-rules).

**Public suffix caveat.** The CA does not consult the Public Suffix List (a deliberate decision). A rule for
`*.github.io`, `*.co.uk`, `*.amazonaws.com` or `*.com.au` permits that suffix, and then the CA could sign for every site
under it (and the proxy would MITM any ruled host there). Write rules for the exact API host (`api.github.com`) rather
than a broad parent. See [security-model.md](security-model.md).

**Concurrency.** Every admin write that touches rules or the CA first takes `CaService::domain_guard()`, so two requests
cannot interleave between "derive" and "install" and install a stale set. Lock order: guard, vault connection, CA state,
leaf cache ([architecture.md](architecture.md#admin-operations-and-the-ca)).

There is no way to rotate the CA key in the code.

### 2.4 Re-issue with the same key

Changing the set of domains **re-issues the CA certificate with the same private key**, a new random serial and different
constraints (tests `allow_domain_keeps_the_same_key_and_persists`, `reissued_ca_certificates_have_distinct_serials_and_the_same_key`).
Consequences:

- Leaves issued earlier still verify against the new certificate (same key and subject; test
  `leaf_issued_before_allow_domain_still_verifies_against_the_reissued_ca`). The leaf cache is cleared on every re-issue.
- A client that still trusts the **old** certificate refuses a newly permitted domain (its constraints are narrower;
  test `old_ca_certificate_refuses_a_newly_allowed_domain`). **Agents must reload the exported public certificate
  (`sg ca export`) after a domain is ADDED.** The CLI (`secret add`, `rule add`) prints `the CA certificate changed: agents
  must reload it (sg ca export)`, the API returns `ca_changed` and `notice`, and the web UI shows the notice.
- After a domain is **removed** the old certificate is wider, not narrower, so agents holding it keep working: reloading is
  not needed (but harmless).
- The random serial matters because the issuer name and key stay the same across re-issues.
- `init_or_load` on an existing vault also rebuilds the signing certificate object (new serial) from the stored key and
  domains; the stored `cert_pem` (what operators export) is not replaced, and leaves signed by the rebuilt object verify
  against it because key, subject and constraints are the same (test `reload_after_allow_domain_still_signs_valid_leaves`).
  Because the stored set equals the derived one after the start-up sync, this rebuild normally changes nothing the
  operator can see.

`cert_pem()` returns the public certificate PEM to distribute; the private key never leaves the vault.

### 2.5 Leaf certificates

`CaService::server_config_for(host)` (called by `mitm.rs` after the CONNECT `200`):

- The host is lower-cased and must be permitted: `is_host_permitted` is true when `host == d` or
  `host` ends with `.d` for an allowed `d`; otherwise `CaError::NotPermitted`. (`localhost` allowed also permits
  `app.localhost`; `notlocalhost` is not permitted.)
- A fresh ECDSA key and a leaf certificate with one SAN (the exact hostname, no wildcard), extended key usage
  `serverAuth`, `not_before` = now minus 1 hour, **`not_after` = now plus 24 hours**, signed by the CA key.
- The returned `rustls::ServerConfig` has no client auth, rustls' safe default protocol versions (TLS 1.2 and 1.3,
  `ring` provider), and ALPN `["h2", "http/1.1"]`. Only the leaf is sent in the chain (the CA must already be trusted
  by the agent).
- **Cache:** the configs are cached per lower-cased host. Default cache lifetime is 12 hours (the setter is a
  test hook and is clamped to 20 hours), which is below the 24 h validity (so a cached config is replaced well before its certificate expires).
  At most **1024** entries: when full and a new host arrives, expired entries are dropped, and if still full the oldest is
  evicted (test `leaf_cache_is_bounded_and_the_ca_certificate_is_built_once_per_change`). The cache is cleared by every re-issue (`install`).
  The cache lock is held while issuing so concurrent first requests for one host share one leaf.
- Leaf keys exist only in memory.

When a host has rules but is not permitted (which should not happen while the CA is kept in sync with the rules), the
proxy never reaches this point: CONNECT is answered `502` with the message `the CA does not permit <host>; its domains
follow the rules: re-create the rule or restart `sg serve`, then reload the CA certificate` and audit `ca-not-permitted`.

Upstream connections are independent of this CA: the proxy validates the real server's certificate with the system
roots plus any extra roots in `UpstreamConfig::new` (`upstream.rs`).

### 2.6 What agents must do to trust the CA

Only MITM'd hosts (hosts with at least one rule for the agent's role) present certificates from this CA. Passthrough
tunnels show the real certificate, so the agent keeps using its normal trust store for those.

The agent must trust the exported CA certificate (`CaService::cert_pem`). The spec (section 6.3) distributes it by
environment variable rather than by the system store:

| Variable | Used by (tool behaviour, outside this repository) |
|---|---|
| `SSL_CERT_FILE` | OpenSSL-based clients and many runtimes |
| `NODE_EXTRA_CA_CERTS` | Node.js (adds to its built-in roots) |
| `REQUESTS_CA_BUNDLE` | Python `requests` |
| `CURL_CA_BUNDLE` | curl |

Most of these variables **replace** the tool's trust store rather than extend it, so a bundle that contains only this CA
breaks verification of hosts that are not intercepted; when such an agent also talks to passthrough hosts, point the
variable at a file with the system roots plus this CA. Re-export the file after each change that adds a domain (the CLI and
API tell you with the "agents must reload" notice).

Leaf certificates carry an Authority Key Identifier, so strict verifiers (OpenSSL `X509_STRICT`, the default context of Python 3.13+) accept them.

Known limitations (spec section 6.5 and 11; these are properties of the clients, not verifiable in this code base):

- Tools with certificate pinning will refuse the proxy's certificate.
- Java uses its own trust store and ignores these variables (it needs the CA imported into its keystore).
- Binaries that ignore the environment variables, as the spec says of some Go programs, will not trust the CA.
- Libraries that do not enforce name constraints get no protection from the CA's constraints.
- Plain HTTP is proxied but never receives injected credentials ([proxy-internals.md](proxy-internals.md#plain-http-absolute-form)); websockets and other upgrades are not supported
  (the proxy strips `Upgrade`).

## Commands

`sg ca export|status` and `sg token create|revoke|revoke-machine|ls` are documented in
[cli-reference.md](cli-reference.md); the web UI offers the same operations (its CA tab is read-only).
