# Proxy internals

What the proxy does with every byte an agent sends, in the order it does it. Sources:
`crates/proxy/src/{server,mitm,forward,inject,upstream,body,ident,lib}.rs`; every status and body below was
observed on a running `sg serve` (see [testing.md](testing.md) for the tests that pin each behaviour). For the
big picture see [architecture.md](architecture.md); for matching rules see [policy-and-rules.md](policy-and-rules.md).

The proxy is an HTTP/1.1 proxy listener (`--proxy-bind`, default `127.0.0.1:8080`). Agents speak to it in one
of two ways, and nothing else is accepted:

| Agent sends | Name here | Result |
|---|---|---|
| `CONNECT host:port` (HTTPS) | CONNECT | A tunnel: terminated by the proxy (MITM) when the role has rules for the host, otherwise an opaque passthrough tunnel or a refusal |
| `GET http://host/path` (absolute form) | plain HTTP | Never receives an injected credential. Forwarded untouched, or refused |

## Overview

```mermaid
flowchart TD
    A["Agent request"] --> B{"Valid Proxy-Authorization?"}
    B -- "no" --> R407["407, no audit row"]
    B -- "yes" --> C{"CONNECT or absolute http?"}
    C -- "CONNECT" --> D{"Role exists and target well formed?"}
    D -- "no" --> R4["400 or 403, audited"]
    D -- "yes" --> E{"Role has a rule for the host?"}
    E -- "yes" --> F{"CA permits the host?"}
    F -- "no" --> R502["502 ca-not-permitted"]
    F -- "yes" --> G["200, then TLS handshake (MITM)"]
    G --> H["Per request: verify token, judge, inject, forward"]
    E -- "no" --> I{"Role unmatched policy"}
    I -- "deny" --> R403["403 unmatched-denied"]
    I -- "passthrough" --> J{"Network policy allows the target?"}
    J -- "no" --> R403b["403 target-denied"]
    J -- "yes" --> K["200, opaque byte tunnel"]
    C -- "absolute http" --> L{"Role has rules for the host?"}
    L -- "yes" --> M["403 plaintext-refused, or 403 forbidden"]
    L -- "no" --> N{"Role unmatched policy"}
    N -- "deny" --> R403
    N -- "passthrough" --> O["Forward without injection"]
```

## Connection level

For every accepted TCP connection (`serve_with` in `lib.rs`):

1. A slot is taken **before** `accept`. At most **1024** client connections are open at once; excess clients wait in
   the kernel listen backlog (they are not refused). A CONNECT tunnel keeps its slot until the tunnel itself ends,
   not just until the CONNECT is answered.
2. The client has **30 s** (`header_read_timeout`) to send a complete request head. A client that connects and
   stays silent is dropped.
3. A client connection (keep-alive plain requests included) lives at most **8 h** (`tunnel_max_lifetime`).
4. Failed `accept` calls (for example out of file descriptors) are logged at `warn` and retried after 100 ms.

None of these limits is configurable from the command line; they are the defaults of `ServeOptions` and
`UpstreamConfig`, which `sg serve` uses unchanged.

## Authentication and revocation

Authentication happens first, on every request the proxy listener receives (CONNECT and plain alike).

1. There must be **exactly one** `Proxy-Authorization` header, at most **8 KiB**, with a valid header string.
2. `Basic <base64(user:password)>`: the token is the **password** (everything after the first `:`), the user name is
   ignored. `Bearer <token>` also works. This is what `HTTPS_PROXY=http://machine:TOKEN@host:port` makes clients
   send.
3. The token is verified (`TokenService::verify`): signature first, then issuer, then expiry, then the database
   lookup of the token id for revocation. Details: [tokens-and-ca.md](tokens-and-ca.md#13-verification-order).
4. Any failure is `407 Proxy Authentication Required`, header `Proxy-Authenticate: Basic realm="secret-guardian"`,
   body `proxy authentication required`. **No audit row is written** (there is no identity to attribute it to).

**Per-request revocation.** The raw token is kept for the life of a MITM tunnel and **verified again before every
inner request**. A revoked or expired token gets `407` (audit `token-invalid`, with the identity) and the tunnel is
shut down gracefully. So `sg token revoke` stops an open MITM tunnel at the next request. **Passthrough tunnels
are opaque byte copies and are not re-checked**: revocation takes effect when they end, which is bounded by the idle
timeout (10 min without any byte in either direction) and the absolute lifetime (8 h).

A token whose role was deleted still verifies but gets `403 role not found` (audit `unknown-role`).

## CONNECT

### Target checks

The CONNECT authority (`host[:port]`) is parsed by hyper, then:

| Check | Failure |
|---|---|
| authority present | `400 bad CONNECT target`, audit `bad-request` |
| no `@` in the authority | `400 bad CONNECT target` |
| host passes `normalize_host` (lower-cased, trailing dots removed, `[a-z0-9._:-]` only, 1 to 253 bytes, IPv6 literals in brackets) | `400 bad CONNECT host` |
| port: defaults to **443** when absent; `0` is refused | `400 bad CONNECT port` |

A target that hyper itself cannot parse (for example a space in the host) is answered `400` with an empty body and
no audit row, before the proxy code runs.

### Deciding what to do with the host

After the role is loaded (`403 role not found` + `unknown-role` if it was deleted), the proxy asks one question:
**does the role have any rule whose host pattern matches this host** (ignoring path, method and port)?

| Rules for host? | Role `unmatched` | CA permits host? | Outcome |
|---|---|---|---|
| yes | any | no | `502`, body names `sg ca allow-domain`, audit `ca-not-permitted` |
| yes | any | yes | per-identity tunnel budget, then `200` and MITM (audit `mitm`) |
| no | `deny` | - | `403 host not allowed for this role`, audit `unmatched-denied` |
| no | `passthrough` | - | per-identity tunnel budget, then connect to the target first: network policy refusal `403 destination not allowed` (`target-denied`), connect failure `502 could not reach the destination` (`tunnel-connect-failed`), otherwise `200` (`passthrough`) and an opaque tunnel |

Passthrough connects to the destination **before** answering `200`, so the agent gets an honest error instead of a
tunnel that dies. An IP address can never have rules, so a CONNECT to an IP always follows the role's `unmatched`
policy. The port is not part of rule matching: a rule for `api.example.com` applies to whatever port the agent
names (never a security boundary on its own; see [security-model.md](security-model.md)).

### Per-identity tunnel budget

At most **64 simultaneous tunnels per token** (passthrough and MITM together). More gets
`429 too many open tunnels for this token`, header `Retry-After: 1`, audit `identity-limit`. The slot is released when
the tunnel ends. Verified: with 66 attempts, 64 got `200` and 2 got `429`.

### Passthrough tunnels

After `200` the proxy copies bytes both ways (`copy_bidirectional`). Both sides are wrapped so that the tunnel ends if
nothing moves in either direction for **10 min**, and a write that stays blocked for 10 min ends it even if the other
direction keeps flowing (a peer that stopped reading cannot pin a tunnel). The whole tunnel is cut after **8 h**. The
TLS inside is the real end-to-end session between the agent and the destination: the agent keeps using its normal
trust store, and there is no injection.

### MITM tunnels

After `200` the connection is upgraded and TLS is terminated with a leaf certificate for the exact host, signed by
the vault CA (`CaService::server_config_for`, ALPN `h2` and `http/1.1`, leaf valid 24 h, cached in memory).

| Aspect | Value |
|---|---|
| TLS handshake deadline | 30 s (`header_read_timeout`); a tunnel that never sends a ClientHello is closed |
| Wait for the first request | same 30 s |
| Idle connection | closed after 10 min with no request in flight and none started; a response body still being sent counts as in flight |
| HTTP/2 | PING every 30 s, peer dropped if no answer in 20 s; at most 32 concurrent streams per connection |
| Absolute lifetime | 8 h |
| Upstream protocol | always HTTP/1.1 (a fresh connection per request); the agent side may be HTTP/1.1 or HTTP/2 |

Activity is measured at the HTTP level, not by transport bytes, so HTTP/2 keep-alive pings cannot keep an abandoned
connection alive forever.

Each inner request goes through the same pipeline as plain requests (next section), after the token re-check.

## The request pipeline (`forward`)

Both MITM requests and plain-HTTP requests run through this function. In order:

1. **Method refusals.** `TRACE`, `TRACK` and `CONNECT` (any letter case) inside a tunnel get
   `405 method not allowed`, audit `method-refused`. (TRACE/TRACK would reflect the injected credentials;
   CONNECT inside a tunnel is never legitimate.)
2. **Host consistency.** Every `Host` header value and the URI authority (if any) must normalize to the host the
   tunnel was opened for, and at least one must be present. Otherwise `421 Misdirected Request`
   (`Host does not match the CONNECT target`), audit `host-mismatch`. This stops an agent from reusing a tunnel and
   its certificate to address another virtual host.
3. **Path normalization.** `normalize_path(uri.path())` resolves `.`/`..`, collapses `//` and decodes escapes of
   unreserved characters; **that normalized path is what is judged and what is forwarded**. The query string is not
   part of the path.
4. **Rules are reloaded from the database for every request**, so rule edits apply to open tunnels immediately.
   A database error here is `502 internal error`, audit `upstream-error`.
5. **Evaluation** (`evaluate`, summarized): candidates are the role's rules whose host and path match; they are
   grouped by injection destination (header name or query parameter); in each group the most specific rule wins
   (exact host over wildcard, longer wildcard over shorter, exact path over prefix, longer pattern); among equally
   specific rules the method list is applied and the lowest id wins; **a method excluded from the most specific
   rule does not fall back to a broader rule**. The path of a path-restricted rule is judged at every
   percent-decoding depth and unjudgeable paths do not match. Full semantics:
   [policy-and-rules.md](policy-and-rules.md#4-evaluation-specificity-and-method-semantics).
   - `Forbidden` or no rule for the host: `403 not allowed for this role`, audit `forbidden`.
   - Inject, but the request is **plain HTTP**: `403 refusing to inject credentials over plain HTTP`, audit
     `plaintext-refused`. There is no exception (not even `localhost`, not even with an explicit port).
   - Inject, method `COPY` or `MOVE` (WebDAV, which carry a `Destination` header the proxy cannot judge) and not every
     matched rule lists that method explicitly: `403 not allowed for this role`, audit `forbidden`.
6. **Secret and rendering.** Each matched rule's secret is decrypted for this request only and rendered into the
   template, both in zeroizing buffers dropped as soon as the upstream request is on its way. Failures: `502 secret
   unavailable` or `502 invalid injection value`, audit `upstream-error` (a stored value that no longer decrypts, or a
   rendered value that is not a valid header value).
7. **Header and URI rewriting** (`inject::apply`): see the next section. Failure: `502 could not build the upstream
   request`, audit `upstream-error`.
8. **`Host` header** is replaced by the CONNECT host, with `:port` appended unless it is the default of the scheme
   (443 for TLS, 80 for plain); the version is forced to HTTP/1.1.
9. **Per-identity upstream budget.** At most **64 simultaneous upstream requests per token**, counted until the
   response body is finished. More gets `429 too many concurrent requests for this token`, `Retry-After: 1`, audit
   `identity-limit`.
10. **Send** (see [Upstream connection handling](#upstream-connection-handling)). The request body is streamed, never
    buffered.
11. **Audit and respond.** The audit row (`inject`, or `passthrough` for unruled plain HTTP) is written when the
    upstream response head has arrived, **before** the head is returned to the agent; it records the upstream status
    and the id of the first matching rule. The response has its hop-by-hop headers removed and its body is streamed
    back. A body truncated later keeps the status of the head that was already sent. If writing the audit row fails,
    the error is logged and the request proceeds (fail-open for what was already forwarded).

### What is rewritten in the request

Applied to **every** forwarded request, injected or not (`inject::apply`):

| Removed | Notes |
|---|---|
| Hop-by-hop: `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, every header starting with `Proxy-`, and any header named in `Connection` | framing is recomputed by hyper; `Upgrade` removal is why WebSockets do not work |
| Routing and attribution overrides: `X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `X-Original-URL`, `X-Original-URI`, `X-Rewrite-URL`, `X-Real-IP`, `Forwarded`, `X-Original-Host`, `X-Host`, `Via`, `Front-End-Https`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `X-Cluster-Client-IP`, and every `X-Forwarded-*` | compared after lower-casing and mapping `_` to `-`, so `X_HTTP_METHOD_OVERRIDE` is removed too. `Referer` and `Origin` are kept |
| Any value the agent sent under the injection **destination**: for a header rule, every value of that header (any case); for a query rule, every parameter whose percent-decoded name equals the target name (case-insensitive, also inside `;`-separated sub-parameters, also a bare `name` with no `=`) | so an agent cannot supply a competing credential |

| Written | Notes |
|---|---|
| Header rule: the rendered template as the header value (marked sensitive) | `Bearer {secret}` and similar |
| Query rule: `name=<value>` appended at the **end** of the query, with every byte except ASCII letters and digits percent-encoded | query injection is weaker than header injection: origins often echo URLs back (see Limitations in the README) |
| The normalized path | what was judged is what is sent |

The method override in the **query or body** (for example `_method=DELETE` accepted by some frameworks) is not
defended against.

Response: hop-by-hop headers (the same list, plus those named in `Connection`) are removed. Everything else, including
`Set-Cookie`, `Location` and `Link`, passes unchanged.

## Plain HTTP (absolute form)

An agent that sends `GET http://host/path` to the proxy port (curl does this when `HTTP_PROXY` is set) is handled like
this:

| Condition | Result |
|---|---|
| scheme is not `http` (an origin-form `GET /foo` sent to the proxy port, `ftp://`) | `400 send absolute-form http:// requests, or CONNECT for https`, audit `bad-request` |
| no authority | `400 missing host` |
| `@` in the authority | `400 bad request target` |
| host fails `normalize_host` | `400 bad host` |
| port `0` | `400 bad port` |
| role deleted | `403 role not found`, audit `unknown-role` |
| host has no rules and role is `deny` | `403 host not allowed for this role`, audit `unmatched-denied` |
| host has rules for the role | the request goes through `forward` and ends in `403 plaintext-refused` (a rule would inject) or `403 forbidden` (no rule authorises the request); the origin is never contacted and no secret is decrypted |
| host has no rules and role is `passthrough` | forwarded **untouched** (no injection; `Proxy-Authorization`, hop-by-hop and routing headers still removed; Host consistency still enforced), audit `passthrough` with the upstream status |

Because credentials are never injected over plain HTTP, local services without TLS cannot receive injected
credentials; put a TLS terminator in front of them. The network policy applies to plain forwarding too
(`127.0.0.1` is refused unless `--allow-loopback-targets`).

## Network policy

Applied to the address actually connected to, **after resolution**, for passthrough tunnels and forwarded requests
alike. The destination is resolved once, the resulting addresses are filtered, and the connection goes to one of the
vetted addresses (no second lookup between check and connect). A refusal is `403 destination not allowed`, audit
`target-denied`.

| Destination | Default | Notes |
|---|---|---|
| Loopback `127.0.0.0/8`, `::1` | **denied** | allowed by `--allow-loopback-targets`; also allowed, over TLS only, for the exact host `localhost` when a rule of the role applies (the `localhost` exception) |
| Unspecified `0.0.0.0`, `::` | denied | not configurable from the CLI |
| `0.0.0.0/8` (other than `0.0.0.0`), `240.0.0.0/4`, broadcast, multicast | always denied | |
| Link-local `169.254.0.0/16`, `fe80::/10` | denied | includes the usual cloud metadata address `169.254.169.254`; not configurable from the CLI |
| Cloud metadata outside link-local: `100.100.100.200` (Alibaba), `fd00:ec2::254` (AWS IPv6) | always denied | |
| RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), unique-local `fc00::/7`, CGNAT `100.64.0.0/10` (Tailscale) | **allowed** | homelab and VPN targets |
| IPv6 that embeds IPv4: mapped `::ffff:a.b.c.d`, compatible `::a.b.c.d`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16` | judged as the IPv4 address they carry | Teredo is out of scope |
| The proxy's own bind address and the web UI's bind address | **always denied**, on their ports | an entry also blocks its port on every loopback and unspecified address; for a wildcard bind (`0.0.0.0:8080`) every interface address at that port is added (read once at start-up) |

The last row is why an agent cannot use the proxy to reach the admin web UI or to loop back into the proxy
(verified: CONNECT to the UI port or to the proxy port gives `403`). The `localhost` exception never overrides it:
`https://localhost:<proxy port>/` gives `403 destination not allowed` (`target-denied`, inside the tunnel).

`localhost` (the exact name) resolves to `127.0.0.1` and `::1` without consulting the system resolver (RFC 6761);
`foo.localhost` is not covered by the exception. A rule on `localhost` requires `sg ca allow-domain localhost`.

## Upstream connection handling

| Aspect | Value |
|---|---|
| Connection | a **new** TCP connection per forwarded request; TLS to the origin with `rustls` (TLS 1.2 and 1.3) against the system root store plus every `--upstream-ca` file; the server name is the CONNECT host; HTTP/1.1 only |
| Connect timeout | 10 s for name resolution plus TCP connect, and also the time a request may wait for a free upstream slot |
| Response-head timeout | 120 s for TLS handshake plus sending the request until the response head arrives. The response body is **not** bounded by it. When an origin waits for the whole request body before answering, this also bounds slow uploads |
| Global cap | 256 simultaneous upstream connections; excess requests wait up to the connect timeout and then fail with `502` |
| Per-identity cap | 64 upstream requests per token (`429` beyond), 64 tunnels per token |
| Body idle timeout | a streamed body in **either** direction (response to the agent, request to the origin) that moves no frame for 60 s is aborted, and everything it holds (upstream slot, per-identity slot, in-flight accounting) is released. A slow but progressing body is not cut |
| Body size | unbounded (streamed, never held in memory) |
| Failure | connection, TLS (including an untrusted origin certificate) and I/O errors give `502 upstream request failed`, audit `upstream-error`; the log line (`warn`) carries the error text and host but never request data |

## Concurrency and shared state

- One tokio runtime, one task per connection; MITM tunnels add a task for the TLS session.
- One SQLite connection behind a mutex serves rule reads, secret reveals, token checks and audit writes. These
  calls are synchronous on the async worker threads; the design accepts that for a single-operator tool.
- Per-identity counters are in-memory maps keyed by token id; guards release on drop, including on abort.

## Audit decisions

Every `decision` string the proxy can write (found by grepping `crates/proxy/src`), with the HTTP status recorded and
what it means. The host column of an audit row is the CONNECT target or the request host; `path` has no query string
(for CONNECT rows it is `/`). Authentication failures (`407` at CONNECT) are never audited.

| Decision | Status | Where | Meaning |
|---|---|---|---|
| `mitm` | 200 | CONNECT | Tunnel accepted and TLS will be terminated (the host has rules and the CA permits it) |
| `passthrough` | 200 | CONNECT | Opaque tunnel opened to a host without rules (role `passthrough`) |
| `passthrough` | upstream status | plain HTTP | Unruled plain request forwarded untouched |
| `inject` | upstream status | inside a tunnel | Request judged, credential injected, forwarded; `rule` column = first matching rule |
| `unmatched-denied` | 403 | CONNECT, plain HTTP | Host has no rule for the role and the role is `deny` |
| `unknown-role` | 403 | CONNECT, plain HTTP | The token's role no longer exists |
| `ca-not-permitted` | 502 | CONNECT | The host has rules but the CA does not permit it; run `sg ca allow-domain` |
| `tunnel-connect-failed` | 502 | CONNECT | Passthrough target not resolvable or not reachable (or timed out) |
| `target-denied` | 403 | CONNECT, inside a tunnel, plain HTTP | Network policy refused the destination address |
| `identity-limit` | 429 | CONNECT, inside a tunnel | The token holds the maximum number of tunnels (64) or concurrent upstream requests (64) |
| `bad-request` | 400 | CONNECT, plain HTTP | Malformed target from an authenticated agent (`host` may be the unparsed hint, truncated to 255 characters) |
| `token-invalid` | 407 | inside a tunnel | The token was revoked or expired while the tunnel was open; the tunnel is closed |
| `method-refused` | 405 | inside a tunnel / plain | `TRACE`, `TRACK` or `CONNECT` |
| `host-mismatch` | 421 | inside a tunnel / plain | `Host` or authority differs from the CONNECT target |
| `forbidden` | 403 | inside a tunnel / plain | No rule authorises this method and path, or `COPY`/`MOVE` without an explicit method |
| `plaintext-refused` | 403 | plain HTTP | A rule would have injected a credential into a plain HTTP request |
| `upstream-error` | 502 | inside a tunnel / plain | Upstream failure (connect, TLS, I/O, timeout), or an internal failure (rules unreadable, secret undecryptable, bad injected value) |

Audit rows contain the machine, role, token id, host, method, path (no query), rule id, decision and status. They never
contain a secret, a token, a query string or a header.

## Error responses

All proxy-generated bodies are plain text ending in a newline, with `Content-Length`; none echoes a token, a secret
name or a rule.

| Status | Body | When | Audited as |
|---|---|---|---|
| 400 | `bad CONNECT target` / `bad CONNECT host` / `bad CONNECT port` | CONNECT target checks | `bad-request` |
| 400 | `send absolute-form http:// requests, or CONNECT for https` / `missing host` / `bad request target` / `bad host` / `bad port` | plain request target checks | `bad-request` |
| 400 | (empty) | request the HTTP parser rejects before our code | not audited |
| 403 | `role not found` | token role deleted | `unknown-role` |
| 403 | `host not allowed for this role` | no rules for host, role `deny` | `unmatched-denied` |
| 403 | `not allowed for this role` | no rule authorises the request; COPY/MOVE without explicit method | `forbidden` |
| 403 | `refusing to inject credentials over plain HTTP` | plain request to a host with an applicable rule | `plaintext-refused` |
| 403 | `destination not allowed` | network policy | `target-denied` |
| 405 | `method not allowed` | TRACE, TRACK, CONNECT inside a tunnel | `method-refused` |
| 407 | `proxy authentication required` | missing, duplicate, oversized, malformed or invalid credentials (with `Proxy-Authenticate`); and token revoked mid-tunnel (no header) | none / `token-invalid` |
| 421 | `Host does not match the CONNECT target` | host consistency | `host-mismatch` |
| 429 | `too many open tunnels for this token` / `too many concurrent requests for this token` (with `Retry-After: 1`) | per-identity budgets | `identity-limit` |
| 502 | `the CA does not permit <host>; run `sg ca allow-domain <domain>` and reload the CA certificate` | CONNECT to a ruled host the CA does not permit | `ca-not-permitted` |
| 502 | `could not reach the destination` | passthrough connect failed | `tunnel-connect-failed` |
| 502 | `upstream request failed` | upstream connect/TLS/I/O/timeout | `upstream-error` |
| 502 | `secret unavailable` / `invalid injection value` / `could not build the upstream request` / `internal error` | internal failures while preparing the request | `upstream-error` |

Inside a MITM tunnel these statuses are returned to the agent over the tunnel (HTTP/1.1 or HTTP/2); for example a
refused `POST` shows as `403` with body `not allowed for this role` after a successful `200` to the CONNECT.

## Things this design deliberately does not do

- No injection into request bodies or signed requests (no HMAC/SigV4).
- No WebSocket or other `Upgrade` support through the MITM (the headers are removed).
- No injection into plain HTTP.
- No inspection or redaction of responses: if an origin echoes the credential back, the agent sees it.
- No HTTP/2 or HTTP/3 towards origins.
- No per-port rules.

See [security-model.md](security-model.md) for why, and what to do instead.
