# CLI reference

Every command and flag of the `sg` binary. Everything on this page was produced by running the real
binary (`sg 0.1.0`); sample outputs are copied from those runs (timestamps and ports differ on your machine).
For a guided first run see the [README](../README.md#quick-start-from-source); for what the commands
call on the server see [admin-api.md](admin-api.md).

Contents: [Global options](#global-options) · [Exit codes](#exit-codes) · [`sg serve`](#sg-serve) ·
[`sg keygen`](#sg-keygen) · [`sg secret`](#sg-secret) · [`sg role`](#sg-role) · [`sg rule`](#sg-rule) ·
[`sg token`](#sg-token) · [`sg ca`](#sg-ca) · [`sg audit`](#sg-audit) · [`sg login-url`](#sg-login-url) ·
[Errors you will meet](#errors-you-will-meet)

## How the CLI is split

Two kinds of commands:

| Kind | Commands | Talks to |
|---|---|---|
| Local | `sg serve`, `sg keygen` | The filesystem. `serve` is the server itself. |
| Client | `sg secret`, `role`, `rule`, `token`, `ca`, `audit`, `login-url` | A running `sg serve`, over its admin Unix socket. They cannot work offline and never open the database file. |

The socket is the only credential of a client command: whoever can open it (mode `0600`, in a `0700`
directory) is the operator. The client refuses to use a socket whose directory is not yours and `0700`, or a
socket that is not yours or is group/other writable (see [Errors](#errors-you-will-meet)).

## Global options

Accepted by every subcommand, before or after it (`sg --json audit` and `sg audit --json` are the same).

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--socket <PATH>` | `SG_SOCKET` | `$XDG_RUNTIME_DIR/secret-guardian.sock`; if `XDG_RUNTIME_DIR` is unset, empty or relative: `<data dir>/sg.sock` | Admin socket. For `sg serve` it is where the socket is created; for client commands it is where to connect. |
| `--json` | - | off | Print the raw JSON returned by the server instead of a table or a sentence. No effect on `serve` and `keygen`. |
| `-h`, `--help` | - | - | Help. `sg <command> --help` for any subcommand. |
| `-V`, `--version` | - | - | Prints `sg 0.1.0`. |

Data directory default (used by `sg serve --data-dir`): `$XDG_DATA_HOME/secret-guardian`, else
`$HOME/.local/share/secret-guardian`, else `/tmp/secret-guardian`. Empty or relative `XDG_DATA_HOME`/`HOME`
are ignored. (Verified: with `XDG_RUNTIME_DIR` unset and `HOME=/x`, a client looks for
`/x/.local/share/secret-guardian/sg.sock`.)

Logging: `tracing` to stderr, default level `warn`, overridable with `RUST_LOG` (for example
`RUST_LOG=sg_proxy=debug`). The code logs very little: upstream failures and internal errors (`warn`/`error`)
and, at `debug`, dropped connections. There are no `info` messages, and requests are not logged at all (use
[`sg audit`](#sg-audit)). A real line looks like
`WARN sg_proxy::forward: upstream failure error=connect failed: Connection refused (os error 111) host=localhost`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `sg serve`: clean stop on `SIGINT`/`SIGTERM`. |
| `1` | The command ran and failed (message on stderr as `error: <message>`): server unreachable, server returned an error, invalid input detected by the CLI, `sg serve` could not start. |
| `2` | Usage error detected by the argument parser (unknown subcommand, missing or invalid flag value). Message on stderr, followed by a usage hint. |
| `130` | `sg serve` only: a second `SIGINT`/`SIGTERM` while shutting down forces the exit. |

Messages go to stderr; results go to stdout. `sg rule add` prints its CA warning on stderr.

## `sg serve`

Runs the vault: the credential-injecting proxy, the admin Unix socket and the local web UI, in one process.

```
sg serve [OPTIONS]
```

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--data-dir <DATA_DIR>` | - | see above | Directory holding `vault.db` (plus `-wal`/`-shm`). Created, with missing parents, with mode `0700`. An existing directory you own with looser permissions is tightened to `0700` (`note: tightened <dir> to mode 0700` on stderr); one owned by another user, or a file, is refused. |
| `--socket <PATH>` | `SG_SOCKET` | see above | Admin socket to create. Its directory must be yours and `0700`. A stale socket file is replaced; a socket with a live server is refused. |
| `--proxy-bind <ADDR>` | `SG_PROXY_BIND` | `127.0.0.1:8080` | Address of the proxy. Must be `IP:port` (a hostname such as `localhost:80` is a usage error). Port `0` picks a free port; the real one is printed. |
| `--admin-bind <ADDR>` | `SG_ADMIN_BIND` | `127.0.0.1:9090` | Address of the web UI. A non-loopback address prints a warning (there is no remote login). |
| `--admin-public-url <URL>` | `SG_ADMIN_PUBLIC_URL` | `http://localhost:<bound admin port>` | The URL you really use to reach the web UI, `http://host[:port]` without userinfo, path, query or fragment (invalid values, including `https://`, end the start with an error: the UI only accepts `http://` origins). It is printed on the `admin:` line, returned by `sg login-url`, and its host:port (the bare host too when the port is the scheme default) is added to the `Host`/`Origin` allowlist. |
| `--admin-allowed-host <HOST:PORT>` | - | none | Extra `Host`/`Origin` value accepted by the web UI. Repeatable. Needed when a container publishes the UI on a different port. |
| `--key-file <FILE>` | `SG_KEY_FILE` | none | Master key file: base64 of 32 bytes, as written by `sg keygen`. Must be mode `0600` (no group/other bits). |
| `--passphrase` | - | off | Derive the master key from a passphrase typed at a prompt. Needs a terminal. |
| `--upstream-ca <PEM>` | `SG_UPSTREAM_CA` | none | Extra PEM CA bundle trusted for **upstream** TLS (internal services with a private CA). Repeatable as a flag; the environment variable takes one path. A file without a PEM certificate is an error. |
| `--allow-loopback-targets` | - | off | Allow the proxy to tunnel and forward to loopback addresses. The proxy's and the web UI's own ports stay denied. See [proxy-internals.md](proxy-internals.md#network-policy). |

Also: `SG_MASTER_KEY` (environment variable only, not a flag): the same base64 value as a key file.

**Key source: exactly one of** `--key-file`/`SG_KEY_FILE`, `SG_MASTER_KEY`, `--passphrase`. None gives
`no key source`, two or more give `ambiguous key source` (see [Errors](#errors-you-will-meet)). An empty
`SG_MASTER_KEY` counts as unset. With `--passphrase` the prompt is `Vault passphrase: ` on every start, and
a second `Repeat passphrase: ` the first time (when `vault.db` does not exist yet). A vault created with a
raw key cannot be opened with a passphrase and the reverse; both fail with the same non-specific message.

**Output** (stdout, one item per line, in this order), real run:

```
proxy: http://127.0.0.1:33691
admin: http://localhost:45081/#t=9e9f86cc1378bd4246951ee3212002143ca445fd2b5d48432c961c65008e061a
socket: /tmp/tmp.vINqLarwc9/sg.sock
ready
```

`ready` is printed once all three listeners are bound and the socket is `0600`. The `admin:` line is a
**one-time login URL** for the web UI (valid 10 minutes, single use). The proxy line shows the bound address
(`http://0.0.0.0:8080` inside a container). The login URL names `http://localhost:<bound port>` unless `--admin-public-url` is given; if a
container publishes the UI on another host port, pass `--admin-public-url http://localhost:<hostport>`.
Warnings and errors go to stderr.

**Start-up order and failures.** The data directory is prepared, then the socket path is probed (a live
instance there ends the start with `already running`), then the key source is resolved (a passphrase prompt
appears here), the vault is opened or created, the CA and token service are loaded, and the two TCP listeners
are bound. A bind failure ends the start with `cannot bind the proxy address ...`. Nothing is left running when
the start fails (an empty data directory may remain).

**Stopping.** `SIGINT` or `SIGTERM`: listeners are dropped, the socket file is removed, exit code `0`.
A second signal exits immediately with `130`.

**First start.** A missing, empty or table-less `vault.db` (`Vault::needs_init`; a crashed first start leaves one) counts as a
first run: leftovers are removed and the vault is initialised (a database with tables but no `meta` row is corrupt and is
an error). `vault.db` is created (`0600`), a random data key and the token signing key are generated and
sealed under the master key, and a CA with no permitted domains is created. Nothing else is created
automatically: you add roles, secrets, rules and CA domains.

Warnings printed by a non-loopback `--admin-bind` (real output):

```
WARNING: the admin interface is bound to 0.0.0.0:45631, which is not loopback. There is no remote login in this version: publish it only to 127.0.0.1 of the host.
hint: the web UI only accepts Host values for port 45631; if it is published on another port, add --admin-allowed-host <host:port>.
```

The `hint:` line appears only when the port is not `9090` and no `--admin-allowed-host` was given.

Host values the web UI accepts by default: `localhost:<port>`, `127.0.0.1:<port>`, `[::1]:<port>`, plus every
`--admin-allowed-host` and `--admin-public-url` value. `Origin` must be exactly `http://<one of those>`.

## `sg keygen`

```
sg keygen --out <FILE>
```

Writes a new random master key (base64 of 32 bytes, 44 characters, no newline) to `FILE` with mode `0600`.
It refuses to overwrite: `FILE` must not exist. The parent directory must exist and be writable.

```
$ sg keygen --out sg.key
wrote sg.key
Back this file up: without it the vault cannot be opened.
$ sg keygen --out sg.key
error: cannot create sg.key (it must not exist yet): File exists (os error 17)
```

Losing the key means losing every stored secret; there is no recovery path
([operations.md](operations.md#key-management)).

## `sg secret`

Secrets are **write-only**: no command returns a stored value.

| Command | Meaning |
|---|---|
| `sg secret add <NAME>` | Create a secret. Fails with `already exists` if the name is taken. |
| `sg secret rotate <NAME>` | Replace the value of an existing secret (`not found` otherwise). Rules keep pointing at it. |
| `sg secret rm <NAME>` | Delete. Fails with `still referenced by a rule` while any rule uses it. |
| `sg secret ls` | List metadata: `ID`, `NAME`, `CREATED`, `ROTATED` (`-` if never rotated), sorted by name. |

**Name:** 1 to 64 characters of `[a-z0-9._-]`.

### How the value is read

Never from arguments (so it cannot appear in shell history or `ps`).

| Input | Behaviour |
|---|---|
| stdin is a pipe or file | Read up to 8195 bytes. Exactly one trailing `\n` or `\r\n` is removed. `printf %s` and `echo` both work; `echo -n` is not needed. |
| stdin is a terminal | Hidden prompt `Secret value: `. `add` asks a second time (`Repeat secret value: `) and the two entries must match; `rotate` asks once. |

Rules, checked by the CLI before anything is sent and again by the server:

| Rule | Error |
|---|---|
| not empty | `the secret value is empty` |
| at most 8192 bytes (after removing the trailing newline) | `the secret value is longer than 8192 bytes` |
| no CR, LF or NUL inside | `the secret value must not contain CR, LF or NUL characters` |
| valid UTF-8 | `the secret value is not valid UTF-8` |
| terminal entries match (`add`) | `the two values do not match` |

Error messages never contain the value. The CLI also scrubs the value out of any server message
before printing it (replacing it with `[redacted]`); for very short values this scrub can also hit
innocent text (see [Known quirk](#known-quirk-redaction-of-short-values)).

```
$ printf '%s' "$GITHUB_TOKEN" | sg secret add gh
secret 'gh' stored
$ printf '%s' "$NEW_TOKEN" | sg secret rotate gh
secret 'gh' rotated
$ sg secret ls
ID  NAME  CREATED               ROTATED
1   gh    2026-10-16T19:55:47Z  2026-10-16T19:58:10Z
$ sg --json secret ls
[
  {
    "created_at": 1792180547,
    "id": 1,
    "name": "gh",
    "rotated_at": 1792180690
  }
]
$ sg secret rm gh
error: still referenced by a rule
```

`--json` of `add`/`rotate` prints the metadata object; of `rm` prints nothing (the server answers `204`).
Timestamps are Unix seconds in JSON and UTC RFC 3339 in tables.

### Known quirk: redaction of short values

The scrub described above replaces every occurrence of the value in server error messages. With a one-letter
secret it mangles the message (real output, value `x`):

```
$ echo 'x' | sg secret add upstream-key     # name already exists
error: already e[redacted]ists
```

It is cosmetic and errs on the safe side. Real secrets are not affected.

## `sg role`

A role is a name plus an **unmatched policy**: what the proxy does with a request from this role to a host that
has no rule for the role. See [policy-and-rules.md](policy-and-rules.md#1-roles-and-the-unmatched-policy).

| Command | Meaning |
|---|---|
| `sg role add <NAME> [--unmatched passthrough\|deny]` | Create a role. `--unmatched` defaults to `passthrough`. |
| `sg role rm <NAME>` | Delete a role **and all its rules**. Existing tokens of that role keep verifying but every request gets `403` (`unknown-role`). |
| `sg role ls` | List roles: `NAME`, `UNMATCHED`, sorted by name. |

**Name:** 1 to 64 characters of `[a-z0-9_-]` (no dot, unlike secret names).

```
$ sg role add reviewer --unmatched deny
role 'reviewer' created
$ sg role add developer
role 'developer' created
$ sg role ls
NAME       UNMATCHED
developer  passthrough
reviewer   deny
```

For least privilege prefer `--unmatched deny`: the agent can then only reach hosts you have written rules for.

## `sg rule`

A rule says: for this role, for requests matching host, path and methods, inject this secret this way.

| Command | Meaning |
|---|---|
| `sg rule add ...` | Create a rule. Prints `rule <id> created`. |
| `sg rule rm <ID>` | Delete a rule by numeric id. `not found` if absent. |
| `sg rule ls [--role <ROLE>]` | List rules (all, or one role's), ordered by id. |

`sg rule add` options:

| Option | Default | Meaning |
|---|---|---|
| `--role <ROLE>` | required | Must exist (`unknown role`). |
| `--host <HOST>` | required | Exact lowercase hostname (`api.github.com`) or one-label wildcard (`*.example.com`). No IP addresses, no ports, no bare TLDs (`*.com` is refused). `localhost` is allowed. |
| `--path <PATH>` | `*` | `*` (any path), an exact path, or a prefix ending in `*` (`/repos/*`). Patterns must already be normalized with upper-case hex in escapes. |
| `--methods <LIST>` | all | Comma-separated, case-insensitive, stored upper-case (`get,post`). |
| `--header <NAME>` or `--query <NAME>` | exactly one required | Inject into this header, or into this query parameter. |
| `--template <TEMPLATE>` | `{secret}` | Value template; `{secret}` is replaced by the secret. For `--query` it must be exactly `{secret}`. |
| `--secret <NAME>` | required | Name of an existing secret (the CLI resolves it to an id; `secret '<name>' not found` otherwise). |

All validation details (header names that cannot be targets, path-pattern rules, specificity and fail-closed
semantics) are in [policy-and-rules.md](policy-and-rules.md).

If the CA does not yet permit the rule's host, the rule is still created and a warning is printed on stderr:

```
$ sg rule add --role reviewer --host example.org --header X-Key --secret upstream-key
rule 3 created
warning: the CA does not permit example.org: run `sg ca allow-domain example.org` and reload the CA certificate in your agents
```

Until you do, a CONNECT to that host fails with `502` (decision `ca-not-permitted`).

```
$ sg rule add --role reviewer  --host localhost --methods GET --header Authorization --template 'Bearer {secret}' --secret upstream-key
rule 1 created
$ sg rule add --role developer --host localhost --header Authorization --template 'Bearer {secret}' --secret upstream-key
rule 2 created
$ sg rule ls
ID  ROLE       HOST       PATH  METHODS  KIND    TARGET         TEMPLATE         SECRET
1   reviewer   localhost  *     GET      header  Authorization  Bearer {secret}  1
2   developer  localhost  *     *        header  Authorization  Bearer {secret}  1
$ sg --json rule add --role developer --host example.net --header X-Key --secret upstream-key
{
  "ca_warning": null,
  "rule": {
    "host_pattern": "example.net",
    "id": 5,
    "kind": "header",
    "methods": [],
    "path_pattern": "*",
    "role": "developer",
    "secret_id": 1,
    "target_name": "X-Key",
    "template": "{secret}"
  }
}
```

In the table, the `METHODS` column shows `*` for "any method" and the `SECRET` column shows the secret **id**.
In JSON an empty `methods` array means any method. There is no `rule update`: remove and add again.

Common examples:

```sh
# read-only access to one API prefix
sg rule add --role reviewer --host api.github.com --path '/repos/*' --methods GET \
   --header Authorization --template 'Bearer {secret}' --secret gh
# a header that takes the bare secret (GitLab)
sg rule add --role developer --host gitlab.com --path '/api/v4/*' \
   --header PRIVATE-TOKEN --secret gitlab
# an API that wants the key in the query string (prefer headers: see Limitations in the README)
sg rule add --role developer --host api.example.com --query api_key --secret example
```

## `sg token`

A token proves the identity `(machine, role)` to the proxy. It is shown **once**, at creation; only metadata
can be listed afterwards.

| Command | Meaning |
|---|---|
| `sg token create --machine <M> --role <R> [--ttl <T>] [--proxy-url <URL>]` | Issue a token. |
| `sg token revoke <JTI>` | Revoke one token by id (`not found` if unknown **or already revoked**). |
| `sg token revoke-machine <MACHINE>` | Revoke every active token of a machine; prints the count (`0 token(s) revoked for 'ghost'` is not an error). |
| `sg token ls` | List metadata, newest first: `JTI`, `MACHINE`, `ROLE`, `CREATED`, `EXPIRES` (`-` = never), `STATUS` (`active`, `expired` or `revoked`). |

`token create` options:

| Option | Default | Meaning |
|---|---|---|
| `--machine <M>` | required | A label for the host or agent that will hold the token: 1 to 128 characters, no control characters. It is the "user name" in the proxy URL, appears in audit rows and is what `revoke-machine` matches. |
| `--role <R>` | required | An existing role (`unknown role` otherwise). One token, one role. |
| `--ttl <T>` | none (no expiry) | Lifetime: plain seconds or a number with a unit `s`, `m`, `h`, `d` (`90s`, `30m`, `12h`, `7d`, `3600`). At least 1 second, at most 10 years (`315360000` s = `3650d`). No fractions, no `y`/`w` units. |
| `--proxy-url <URL>` | `http://127.0.0.1:8080` | The address **agents** use to reach the proxy; only used to print the environment block. Must start with `http://` or `https://`, then `host:port` with no credentials, path, query or whitespace (a trailing `/` is dropped). |

TTL checks (real results): `90s`, `30m`, `12h`, `7d`, `3650d` and `315360000` are accepted; `3651d` and
`315360001` give `duration must be at most 10 years`; `0` gives `duration must be at least 1 second`;
`1.5h`, `abc`, `11y` and the empty string give `expected seconds or a duration like 30m, 12h, 7d`.

### The environment block

Without `--json`, `token create` prints the token and a ready-to-paste block (real run; the JWT is shortened):

```
$ sg token create --machine laptop --role reviewer --proxy-url http://127.0.0.1:44065 --ttl 12h
token (shown once): eyJhbGciOiJFZERTQSIs...<JWT>

export HTTPS_PROXY=http://laptop:eyJhbGciOiJFZERTQSIs...<JWT>@127.0.0.1:44065
export HTTP_PROXY=$HTTPS_PROXY
export NO_PROXY=localhost,127.0.0.1

# trust the vault CA:
sg ca export > sg-ca.pem
export SSL_CERT_FILE=$PWD/sg-ca.pem
export NODE_EXTRA_CA_CERTS=$PWD/sg-ca.pem
export REQUESTS_CA_BUNDLE=$PWD/sg-ca.pem
export CURL_CA_BUNDLE=$PWD/sg-ca.pem
```

Points to know:

- The machine label is percent-encoded in the URL (`my laptop/é` becomes `my%20laptop%2F%C3%A9`), and the
  proxy ignores the user name anyway: the token is in the password position.
- `NO_PROXY=localhost,127.0.0.1` is part of the block. If your upstream is `localhost`, delete that line,
  otherwise the client bypasses the proxy and nothing is injected.
- The `sg ca export > sg-ca.pem` line is an instruction to run on the machine where the agent runs, not part
  of the exports. Each CA variable points at the file; most of them *replace* the tool's own trust store (see
  [README: Configure an agent](../README.md#configure-an-agent)).
- Inside Docker the default `--proxy-url` is wrong for agents in other containers: pass
  `--proxy-url http://secret-guardian:8080` (the service name).

With `--json` only the JSON is printed, without the block:

```
$ sg --json token create --machine laptop --role reviewer --ttl 12h
{
  "jti": "e7783b5f-4282-4532-93f8-d2fa9897f486",
  "machine": "laptop",
  "role": "reviewer",
  "token": "eyJhbGciOiJFZERTQSIs...<JWT>"
}
```

```
$ sg token ls
JTI                                   MACHINE  ROLE       CREATED               EXPIRES               STATUS
e7783b5f-4282-4532-93f8-d2fa9897f486  laptop   reviewer   2026-10-16T19:55:56Z  2026-10-17T07:55:56Z  active
3f5d576b-e73a-4ce0-a5b2-61410cd488ed  laptop   developer  2026-10-16T19:55:56Z  -                     active
$ sg token revoke 3f5d576b-e73a-4ce0-a5b2-61410cd488ed
token 3f5d576b-e73a-4ce0-a5b2-61410cd488ed revoked
$ sg token revoke-machine laptop
1 token(s) revoked for 'laptop'
$ sg token revoke not-a-uuid
error: invalid token id
```

Revocation is immediate for open MITM tunnels (checked before every request); it only takes effect on
passthrough tunnels when they end (bounded by the idle timeout and lifetime). See
[proxy-internals.md](proxy-internals.md#authentication-and-revocation).

## `sg ca`

The proxy re-signs HTTPS for the hosts that have rules with a local CA whose X.509 name constraints are limited
to the domains you allow. Details: [tokens-and-ca.md](tokens-and-ca.md).

| Command | Meaning |
|---|---|
| `sg ca export` | Print the CA certificate (PEM, public part only) on stdout. |
| `sg ca allow-domain <DOMAIN>` | Permit a domain and its subdomains. **Re-issues the CA certificate** (same key, new serial and constraints). Allowing a domain that is already allowed succeeds and changes nothing (the notice is printed again). |
| `sg ca status` | List permitted domains. |

`allow-domain` accepts a plain lowercase domain such as `github.com` (surrounding spaces are trimmed and case
is folded): letters, digits, `-` and dots, labels of 1 to 63 characters, at most 253 bytes, a last label that is
not all digits. It rejects wildcards, underscores, IDNs (use punycode), IP addresses, single-label names
(except `localhost`) and `invalid`. It does **not** consult the Public Suffix List: allowing `github.io` or
`co.uk` would let the CA sign for every site under them, so allow the exact API host, for example `api.github.com`.

```
$ sg ca status
permitted domains:
$ sg ca allow-domain localhost
the CA certificate changed: agents must reload it (sg ca export)
$ sg ca status
permitted domains:
  localhost
$ sg ca export > sg-ca.pem
$ head -2 sg-ca.pem
-----BEGIN CERTIFICATE-----
MIIBzzCCAXWgAwIBAgIQGLka/vxjiCk9HHYWLBt+VzAKBggqhkjOPQQDAjAdMRsw
$ sg --json ca status
{
  "domains": [
    "localhost"
  ]
}
```

After every `allow-domain` that adds a domain, **re-export the certificate and restart or reconfigure the
agents**: a client still holding the previous certificate refuses the newly allowed name, because the old
certificate has narrower constraints. Leaf certificates issued earlier stay valid.

Real rejections:

```
$ sg ca allow-domain com
error: domain rejected: too broad: single-label domains are not allowed
$ sg ca allow-domain '*.example.com'
error: domain rejected: use a plain lowercase domain such as github.com
$ sg ca allow-domain 1.2.3.4
error: domain rejected: last label must not be all digits
```

There is no command to remove a domain or rotate the CA key.

## `sg audit`

```
sg audit [--role <ROLE>] [--host <HOST>] [--since <UNIX_TS>] [--limit <N>]
```

Shows the audit log, **newest first**. Filters combine with AND.

| Option | Default | Meaning |
|---|---|---|
| `--role <ROLE>` | all | Exact role name (`[a-z0-9._-]`). |
| `--host <HOST>` | all | Exact host as recorded (for CONNECT rows, the target host). |
| `--since <UNIX_TS>` | all | Only entries at or after this Unix timestamp (`--since $(date -d '1 hour ago' +%s)`). |
| `--limit <N>` | `50` | 1 to 1000. Outside the range the parser answers `0 is not in 1..=1000`. |

Columns: `TIME`, `MACHINE`, `ROLE`, `METHOD`, `HOST`, `PATH`, `DECISION`, `STATUS`, `RULE`. `-` means no value.
`PATH` never contains the query string. `RULE` is the id of the first matching rule. Every `decision` value is
explained in [proxy-internals.md](proxy-internals.md#audit-decisions).

```
$ sg audit --limit 6
TIME                  MACHINE  ROLE       METHOD   HOST       PATH         DECISION   STATUS  RULE
2026-10-16T20:10:34Z  laptop   developer  POST     localhost  /repos/demo  inject     200     2
2026-10-16T20:10:34Z  laptop   developer  CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   POST     localhost  /repos/demo  forbidden  403     -
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
2026-10-16T20:10:34Z  laptop   reviewer   GET      localhost  /repos/demo  inject     200     1
2026-10-16T20:10:34Z  laptop   reviewer   CONNECT  localhost  /            mitm       200     -
```

JSON rows have the fields `ts`, `jti`, `machine`, `role`, `host`, `method`, `path`, `rule_id`, `decision`,
`status` (`null` where unknown):

```
$ sg --json audit --limit 1
[
  {
    "decision": "inject",
    "host": "localhost",
    "jti": "3f5d576b-e73a-4ce0-a5b2-61410cd488ed",
    "machine": "laptop",
    "method": "POST",
    "path": "/repos/demo",
    "role": "developer",
    "rule_id": 2,
    "status": 200,
    "ts": 1792180566
  }
]
```

The audit log is never pruned by the program; see [operations.md](operations.md#observability).

## `sg login-url`

```
sg login-url
```

Mints a fresh single-use login link for the web UI and prints it. It works through the admin socket only (the
web listener cannot mint its own credentials), needs no restart, and can be run as often as you like. Each link
works once and expires after 10 minutes; at most 8 pending links are kept (older ones are dropped).

```
$ sg login-url
http://localhost:45081/#t=7bb9d66e57d13ce721571a5cfdf300cceb87ebf3f815177884d0ba79821baa83
$ sg --json login-url
{
  "token": "20bae5416d8853f38147a2ec12a2dbe626abb6e64f40617241ce3c819742883e",
  "url": "http://localhost:36655/#t=20bae5416d8853f38147a2ec12a2dbe626abb6e64f40617241ce3c819742883e"
}
```

The URL names the port the server bound. Behind a published container port it may need adjusting
([README: Docker](../README.md#docker)). Treat the link like a password for 10 minutes; do not paste it into chat or
tickets. See [Web UI](../README.md#web-ui).

## Errors you will meet

Copied from real runs. Prefix is always `error: ` on stderr, exit code `1` (or `2` for usage errors).

### Reaching the server

| Message | Cause and fix |
|---|---|
| `cannot reach the vault at <socket> (is `sg serve` running?): No such file or directory (os error 2)` | No server, or the wrong socket path. Start `sg serve`, or pass `--socket`/`SG_SOCKET` (remember the default depends on `XDG_RUNTIME_DIR`). |
| `... Connection refused (os error 111)` | The path exists but nothing listens (stale socket, or not a socket). |
| `refusing to use <socket>: its directory <dir> is accessible to group/others (mode 755); the socket must live in a 0700 directory such as $XDG_RUNTIME_DIR` | The client will not talk to a socket other users could have replaced. `chmod 700 <dir>` or use another directory. |
| `refusing to use <socket>: its directory <dir> is owned by uid N, not by you (uid M)` / `... it is owned by uid N, not by you` / `... it is writable by group/others (mode 666)` | Same family: wrong owner or loose mode. |
| `the vault at <socket> did not answer within 30s` | The server is stuck or overloaded. Each call has a 30 s deadline. |
| `request body too large (max 1 MiB)` / `response too large (max 1 MiB)` | Client-side size caps. |

### From the server (copied verbatim)

| Message | When |
|---|---|
| `not found` | Unknown secret, role, rule id, token id on `rm`/`rotate`/`revoke`. |
| `already exists` | Duplicate secret or role name. |
| `still referenced by a rule` | `secret rm` of a secret a rule uses. Remove the rules first. |
| `invalid name: use [a-z0-9._-], max 64 chars` | Secret name. |
| `role name must be [a-z0-9_-]` | Role name. |
| `unknown role` | `rule add` or `token create` with a role that does not exist. |
| `secret '<name>' not found` | `rule add --secret` (raised by the CLI). |
| `host_pattern must be a lowercase hostname or *.hostname (no IPs)` | Bad `--host`. |
| `--query injects the bare secret: the template must be `{secret}` (got `...`)` | `--query` with another template (CLI). |
| `invalid token id` | `token revoke` argument is not a UUID. |
| `machine must be 1-128 characters without control characters` | `--machine`. |
| `domain rejected: <reason>` | `ca allow-domain`; reasons include `too broad: single-label domains are not allowed`, `use a plain lowercase domain such as github.com`, `last label must not be all digits`, `would invalidate the CA name constraints`. |
| `internal error` | The server hit an unexpected condition (details only in its stderr log). |

### From the argument parser (exit code 2)

```
$ sg rule add --role reviewer --host localhost --secret upstream-key
error: the following required arguments were not provided:
  <--header <HEADER>|--query <QUERY>>
$ sg role add x --unmatched foo
error: invalid value 'foo' for '--unmatched <UNMATCHED>'
  [possible values: passthrough, deny]
$ sg audit --limit 5000
error: invalid value '5000' for '--limit <LIMIT>': 5000 is not in 1..=1000
$ sg token create --machine m --role reviewer --ttl 11y
error: invalid value '11y' for '--ttl <TTL>': expected seconds or a duration like 30m, 12h, 7d
```

### `sg serve` start-up errors

| Message | Cause and fix |
|---|---|
| `no key source: use --key-file, SG_MASTER_KEY or --passphrase` | None given. |
| `ambiguous key source: use exactly one of --key-file, SG_MASTER_KEY, --passphrase` | More than one given. |
| `key file <f> is accessible to group/others (mode 644); run `chmod 600 <f>`` | The key file must be `0600`. |
| `cannot read key file <f>: No such file or directory (os error 2)` | Wrong path or unreadable. In a container: see the Docker key pitfall in the README. |
| `the key is not valid: expected base64 of exactly 32 bytes (generate one with `sg keygen`)` | Corrupt or wrong file/variable. The value is never echoed. |
| `could not unlock the vault with the given key source` | Wrong key, wrong passphrase, key kind different from the one the vault was created with, or a damaged vault. Deliberately non-specific. |
| `database schema version 99 is not supported by this build (supports 1)` | The database was written by a different version of the program. Use a matching `sg`. |
| `--passphrase needs a terminal to prompt on; use --key-file or SG_MASTER_KEY when running unattended` | No TTY on stdin. |
| `passphrases do not match` / `the passphrase must not be empty` | Prompt problems on first creation. |
| `already running: <socket> accepts connections` | A live server owns that socket. Use another `--socket` (and `--data-dir`) or stop it. |
| `refusing to create the admin socket: directory <dir> is accessible to group/others (mode 755); use a 0700 directory such as $XDG_RUNTIME_DIR` | Put the socket in a private directory. |
| `<path> exists and is not a socket; refusing to replace it` | Something else sits at the socket path. |
| `refusing to use <dir> as the data directory: it is owned by uid N, not by the current user (uid M)` | Wrong owner. |
| `cannot bind the proxy address 127.0.0.1:8080: Address already in use (os error 98)` | Port taken; choose another `--proxy-bind` (same for `cannot bind the admin address`). |
| `error: invalid value 'localhost:80' for '--proxy-bind <PROXY_BIND>': invalid socket address syntax` | Binds take `IP:port`, not hostnames. |
| `<file> contains no PEM certificate` / `cannot read <file>` | `--upstream-ca` problems. |
| `the admin socket <path> did not come up` | The socket was not ready within 10 s of start. |

More symptoms (proxy-side) are in the troubleshooting table of [operations.md](operations.md#troubleshooting).
