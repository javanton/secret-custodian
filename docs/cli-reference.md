# CLI reference

Every command and flag of the `sc` binary. Everything on this page was produced by running the real
binary (`sc 0.1.0`); sample outputs are copied from those runs (timestamps and ports differ on your machine).
For a guided first run see the [README](../README.md#quick-start-from-source); for what the commands
call on the server see [admin-api.md](admin-api.md).

Contents: [Global options](#global-options) · [Exit codes](#exit-codes) · [`sc serve`](#sc-serve) ·
[`sc keygen`](#sc-keygen) · [`sc secret`](#sc-secret) · [`sc role`](#sc-role) · [`sc rule`](#sc-rule) ·
[`sc token`](#sc-token) · [`sc ca`](#sc-ca) · [`sc audit`](#sc-audit) · [`sc login-url`](#sc-login-url) ·
[Errors you will meet](#errors-you-will-meet)

## How the CLI is split

Two kinds of commands:

| Kind | Commands | Talks to |
|---|---|---|
| Local | `sc serve`, `sc keygen` | The filesystem. `serve` is the server itself. |
| Client | `sc secret`, `role`, `rule`, `token`, `ca`, `audit`, `login-url` | A running `sc serve`, over its admin Unix socket. They cannot work offline and never open the database file. |

The socket is the only credential of a client command: whoever can open it (mode `0600`, in a `0700`
directory) is the operator. The client refuses to use a socket whose directory is not yours and `0700`, or a
socket that is not yours or is group/other writable (see [Errors](#errors-you-will-meet)).

## Global options

Accepted by every subcommand, before or after it (`sc --json audit` and `sc audit --json` are the same).

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--socket <PATH>` | `SC_SOCKET` | `$XDG_RUNTIME_DIR/secret-custodian.sock`; if `XDG_RUNTIME_DIR` is unset, empty or relative: `<data dir>/sg.sock` | Admin socket. For `sc serve` it is where the socket is created; for client commands it is where to connect. |
| `--json` | - | off | Print the raw JSON returned by the server instead of a table or a sentence. No effect on `serve` and `keygen`. |
| `-h`, `--help` | - | - | Help. `sc <command> --help` for any subcommand. |
| `-V`, `--version` | - | - | Prints `sc 0.1.0`. |

Data directory default (used by `sc serve --data-dir`): `$XDG_DATA_HOME/secret-custodian`, else
`$HOME/.local/share/secret-custodian`, else `/tmp/secret-custodian`. Empty or relative `XDG_DATA_HOME`/`HOME`
are ignored. (Verified: with `XDG_RUNTIME_DIR` unset and `HOME=/x`, a client looks for
`/x/.local/share/secret-custodian/sg.sock`.)

Logging: `tracing` to stderr, default level `warn`, overridable with `RUST_LOG` (for example
`RUST_LOG=sg_proxy=debug`). The code logs very little: upstream failures and internal errors (`warn`/`error`)
and, at `debug`, dropped connections. There are no `info` messages, and requests are not logged at all (use
[`sc audit`](#sc-audit)). A real line looks like
`WARN sg_proxy::forward: upstream failure error=connect failed: Connection refused (os error 111) host=localhost`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. For `sc serve`: clean stop on `SIGINT`/`SIGTERM`. |
| `1` | The command ran and failed (message on stderr as `error: <message>`): server unreachable, server returned an error, invalid input detected by the CLI, `sc serve` could not start. |
| `2` | Usage error detected by the argument parser (unknown subcommand, missing or invalid flag value). Message on stderr, followed by a usage hint. |
| `130` | `sc serve` only: a second `SIGINT`/`SIGTERM` while shutting down forces the exit. |

Messages go to stderr; results go to stdout. `sc secret add` and `sc rule add` print their CA reload warning on stderr.

## `sc serve`

Runs the vault: the credential-injecting proxy, the admin Unix socket and the local web UI, in one process.

```
sc serve [OPTIONS]
```

| Option | Env | Default | Meaning |
|---|---|---|---|
| `--data-dir <DATA_DIR>` | - | see above | Directory holding `vault.db` (plus `-wal`/`-shm`). Created, with missing parents, with mode `0700`. An existing directory you own with looser permissions is tightened to `0700` (`note: tightened <dir> to mode 0700` on stderr); one owned by another user, or a file, is refused. |
| `--socket <PATH>` | `SC_SOCKET` | see above | Admin socket to create. Its directory must be yours and `0700`. A stale socket file is replaced; a socket with a live server is refused. |
| `--proxy-bind <ADDR>` | `SC_PROXY_BIND` | `127.0.0.1:8080` | Address of the proxy. Must be `IP:port` (a hostname such as `localhost:80` is a usage error). Port `0` picks a free port; the real one is printed. |
| `--admin-bind <ADDR>` | `SC_ADMIN_BIND` | `127.0.0.1:9090` | Address of the web UI. A non-loopback address prints a warning (there is no remote login). |
| `--admin-public-url <URL>` | `SC_ADMIN_PUBLIC_URL` | `http://localhost:<bound admin port>` | The URL you really use to reach the web UI, `http://host[:port]` without userinfo, path, query or fragment (invalid values, including `https://`, end the start with an error: the UI only accepts `http://` origins). It is printed on the `admin:` line, returned by `sc login-url`, and its host:port (the bare host too when the port is the scheme default) is added to the `Host`/`Origin` allowlist. |
| `--admin-allowed-host <HOST:PORT>` | - | none | Extra `Host`/`Origin` value accepted by the web UI. Repeatable. Needed when a container publishes the UI on a different port. |
| `--key-file <FILE>` | `SC_KEY_FILE` | none | Master key file: base64 of 32 bytes, as written by `sc keygen`. Must be mode `0600` (no group/other bits). |
| `--passphrase` | - | off | Derive the master key from a passphrase typed at a prompt. Needs a terminal. |
| `--upstream-ca <PEM>` | `SC_UPSTREAM_CA` | none | Extra PEM CA bundle trusted for **upstream** TLS (internal services with a private CA). Repeatable as a flag; the environment variable takes one path. A file without a PEM certificate is an error. |
| `--allow-loopback-targets` | - | off | Allow the proxy to tunnel and forward to loopback addresses. The proxy's and the web UI's own ports stay denied. See [proxy-internals.md](proxy-internals.md#network-policy). |

Also: `SC_MASTER_KEY` (environment variable only, not a flag): the same base64 value as a key file.

**Key source: exactly one of** `--key-file`/`SC_KEY_FILE`, `SC_MASTER_KEY`, `--passphrase`. None gives
`no key source`, two or more give `ambiguous key source` (see [Errors](#errors-you-will-meet)). An empty
`SC_MASTER_KEY` counts as unset. With `--passphrase` the prompt is `Vault passphrase: ` on every start, and
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
automatically: you add roles, secrets and rules. The CA's permitted domains are not configured by hand: they are derived
from the rules (see [tokens-and-ca.md](tokens-and-ca.md#2-the-certificate-authority)). On every start the vault also
syncs the CA with the stored rules once (see [operations.md](operations.md#upgrading-from-a-version-without-required-rules)).

Warnings printed by a non-loopback `--admin-bind` (real output):

```
WARNING: the admin interface is bound to 0.0.0.0:45631, which is not loopback. There is no remote login in this version: publish it only to 127.0.0.1 of the host.
hint: the web UI only accepts Host values for port 45631; if it is published on another port, add --admin-allowed-host <host:port>.
```

The `hint:` line appears only when the port is not `9090` and no `--admin-allowed-host` was given.

Host values the web UI accepts by default: `localhost:<port>`, `127.0.0.1:<port>`, `[::1]:<port>`, plus every
`--admin-allowed-host` and `--admin-public-url` value. `Origin` must be exactly `http://<one of those>`.

## `sc keygen`

```
sc keygen --out <FILE>
```

Writes a new random master key (base64 of 32 bytes, 44 characters, no newline) to `FILE` with mode `0600`.
It refuses to overwrite: `FILE` must not exist. The parent directory must exist and be writable.

```
$ sc keygen --out sg.key
wrote sg.key
Back this file up: without it the vault cannot be opened.
$ sc keygen --out sg.key
error: cannot create sg.key (it must not exist yet): File exists (os error 17)
```

Losing the key means losing every stored secret; there is no recovery path
([operations.md](operations.md#key-management)).

## `sc secret`

Secrets are **write-only**: no command returns a stored value.

| Command | Meaning |
|---|---|
| `sc secret add <NAME> [--role <ROLE>] --host <HOST> [--path <PATH>] [--methods <LIST>] (--header <NAME> \| --query <NAME>) [--template <TEMPLATE>]` | Create a secret **together with its first rule**, in one atomic request. Fails with `already exists` if the name is taken. |
| `sc secret rotate <NAME>` | Replace the value of an existing secret (`not found` otherwise). Rules keep pointing at it. |
| `sc secret rm <NAME>` | Delete the secret **and its rules**. If that removes the last rule that needed a host, the CA is re-issued without it. |
| `sc secret ls` | List metadata: `ID`, `NAME`, `RULES` (number of rules), `CREATED`, `ROTATED` (`-` if never rotated), sorted by name. |

**Name:** 1 to 64 characters of `[a-z0-9._-]`.

### `secret add` creates the first rule

A secret that no rule uses can never be injected, so `secret add` always creates one rule with it. The rule
options are the same as `sc rule add` (see [`sc rule`](#sc-rule)) except that the secret is the one being created:

| Option | Default | Meaning |
|---|---|---|
| `--role <ROLE>` | see below | Role of the first rule. |
| `--host <HOST>` | required | Exact lowercase hostname or one-label wildcard (`*.example.com`). |
| `--path <PATH>` | `*` | `*`, an exact path or a prefix ending in `*`. |
| `--methods <LIST>` | all | Comma-separated, case-insensitive. |
| `--header <NAME>` or `--query <NAME>` | exactly one required | Where the secret is injected. |
| `--template <TEMPLATE>` | `{secret}` | For `--query` it must be exactly `{secret}`. |

**Which role.** `--role` if given (it must exist: `unknown role`). Otherwise the only existing role; if there are none,
a role `default` (unmatched policy `passthrough`) is created first and the CLI prints a `note:` on stderr; if there are
several roles it fails with `several roles exist (<names>): choose one with --role`. The CLI validates the rule options
before reading the value or creating anything, so a bad `--query`/`--template` combination leaves no `default` role
behind. Add more rules (for the same or other roles) with `sc rule add`.

Without `--host` and `--header`/`--query` the argument parser refuses the command (exit code 2) and nothing is
stored. If the server rejects the rule (for example `unknown role`, a bad host or `domain rejected: reserved`, which
is what a host under the placeholder TLD `invalid` gets), nothing is stored either: no secret, no rule, no CA change.

When the new rule's host was not yet in the CA, the CA certificate is re-issued and the command prints
`warning: the CA certificate changed: agents must reload it (sc ca export)` on stderr; with `--json` the same text is in
the `notice` field.

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

Error messages never contain the value. The CLI also scrubs the value out of any server message before printing it
(replacing it with `[redacted]`; see [redaction](#redaction-of-the-value-in-error-messages)).

```
$ sc role add reviewer --unmatched deny
role 'reviewer' created
$ printf '%s' "$GITHUB_TOKEN" | sc secret add gh --role reviewer --host api.github.com --methods GET \
     --path '/repos/*' --header Authorization --template 'Bearer {secret}'
secret 'gh' stored with rule 1
warning: the CA certificate changed: agents must reload it (sc ca export)
$ printf '%s' "$NEW_TOKEN" | sc secret rotate gh
secret 'gh' rotated
$ sc secret ls
ID  NAME  RULES  CREATED               ROTATED
1   gh    1      2026-10-16T19:55:47Z  2026-10-16T19:58:10Z
$ sc --json secret ls
[
  {
    "created_at": 1792180547,
    "id": 1,
    "name": "gh",
    "rotated_at": 1792180690,
    "rules": 1
  }
]
$ sc secret rm gh
secret 'gh' removed
```

`--json` of `add` prints the server's answer `{"secret": {...}, "rules": [...], "ca_changed": true, "notice": "..."}`
(see [admin-api.md](admin-api.md#secrets)); of `rotate` the metadata object; of `rm` nothing (the server answers `204`).
Timestamps are Unix seconds in JSON and UTC RFC 3339 in tables.

### Redaction of the value in error messages

The CLI replaces the value with `[redacted]` in any server error message, raw or JSON-escaped, but only when the value
is at least 8 bytes long: replacing a one-letter value would mangle ordinary words (`already exists` for the value `x`).
Real secrets are far longer than that. A message that is exactly the value is always replaced.

## `sc role`

A role is a name plus an **unmatched policy**: what the proxy does with a request from this role to a host that
has no rule for the role. See [policy-and-rules.md](policy-and-rules.md#1-roles-and-the-unmatched-policy).

| Command | Meaning |
|---|---|
| `sc role add <NAME> [--unmatched passthrough\|deny]` | Create a role. `--unmatched` defaults to `passthrough`. |
| `sc role rm <NAME>` | Delete a role **and all its rules**, unless that would leave a secret without any rule: then it is refused (`409`) with the names of the affected secrets and nothing is deleted. If the role's rules were the only ones needing some hosts, the CA is re-issued without them. Existing tokens of that role keep verifying but every request gets `403` (`unknown-role`). |
| `sc role ls` | List roles: `NAME`, `UNMATCHED`, sorted by name. |

**Name:** 1 to 64 characters of `[a-z0-9_-]` (no dot, unlike secret names).

```
$ sc role add reviewer --unmatched deny
role 'reviewer' created
$ sc role add developer
role 'developer' created
$ sc role ls
NAME       UNMATCHED
developer  passthrough
reviewer   deny
```

For least privilege prefer `--unmatched deny`: the agent can then only reach hosts you have written rules for.

## `sc rule`

A rule says: for this role, for requests matching host, path and methods, inject this secret this way.

| Command | Meaning |
|---|---|
| `sc rule add ...` | Add a rule for an **existing** secret. Prints `rule <id> created`. (The first rule of a secret is created by [`sc secret add`](#sc-secret).) |
| `sc rule rm <ID>` | Delete a rule by numeric id. `not found` if absent. Refused (`409`) when it is the last rule of its secret: delete the secret instead, or add another rule first. |
| `sc rule ls [--role <ROLE>]` | List rules (all, or one role's), ordered by id. |

`sc rule add` options:

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

If the rule's host was not yet in the CA's permitted domains, the CA is re-issued as part of the same operation (rule and
CA change together or not at all) and a warning is printed on stderr; the agents must then reload the certificate
(`sc ca export`). If the host was already permitted, nothing is printed:

```
$ sc rule add --role reviewer --host example.org --header X-Key --secret upstream-key
rule 3 created
warning: the CA certificate changed: agents must reload it (sc ca export)
$ sc rule add --role developer --host example.org --header X-Other --secret upstream-key
rule 4 created
```

A host the CA cannot permit (for example under the placeholder TLD `invalid`) makes the command fail with
`domain rejected: reserved` and nothing is created.

```
$ sc rule add --role reviewer  --host localhost --methods GET --header Authorization --template 'Bearer {secret}' --secret upstream-key
rule 1 created
warning: the CA certificate changed: agents must reload it (sc ca export)
$ sc rule add --role developer --host localhost --header Authorization --template 'Bearer {secret}' --secret upstream-key
rule 2 created
$ sc rule ls
ID  ROLE       HOST       PATH  METHODS  KIND    TARGET         TEMPLATE         SECRET
1   reviewer   localhost  *     GET      header  Authorization  Bearer {secret}  1
2   developer  localhost  *     *        header  Authorization  Bearer {secret}  1
$ sc --json rule add --role developer --host example.net --header X-Key --secret upstream-key
{
  "ca_changed": true,
  "notice": "the CA certificate changed: agents must reload it (sc ca export)",
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
sc rule add --role reviewer --host api.github.com --path '/repos/*' --methods GET \
   --header Authorization --template 'Bearer {secret}' --secret gh
# a header that takes the bare secret (GitLab)
sc rule add --role developer --host gitlab.com --path '/api/v4/*' \
   --header PRIVATE-TOKEN --secret gitlab
# an API that wants the key in the query string (prefer headers: see Limitations in the README)
sc rule add --role developer --host api.example.com --query api_key --secret example
```

## `sc token`

A token proves the identity `(machine, role)` to the proxy. It is shown **once**, at creation; only metadata
can be listed afterwards.

| Command | Meaning |
|---|---|
| `sc token create --machine <M> --role <R> [--ttl <T>] [--proxy-url <URL>]` | Issue a token. |
| `sc token revoke <JTI>` | Revoke one token by id (`not found` if unknown **or already revoked**). |
| `sc token revoke-machine <MACHINE>` | Revoke every active token of a machine; prints the count (`0 token(s) revoked for 'ghost'` is not an error). |
| `sc token ls` | List metadata, newest first: `JTI`, `MACHINE`, `ROLE`, `CREATED`, `EXPIRES` (`-` = never), `STATUS` (`active`, `expired` or `revoked`). |

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
$ sc token create --machine laptop --role reviewer --proxy-url http://127.0.0.1:44065 --ttl 12h
token (shown once): eyJhbGciOiJFZERTQSIs...<JWT>

export HTTPS_PROXY=http://laptop:eyJhbGciOiJFZERTQSIs...<JWT>@127.0.0.1:44065
export HTTP_PROXY=$HTTPS_PROXY
export NO_PROXY=localhost,127.0.0.1

# trust the vault CA:
sc ca export > sg-ca.pem
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
- The `sc ca export > sg-ca.pem` line is an instruction to run on the machine where the agent runs, not part
  of the exports. Each CA variable points at the file; most of them *replace* the tool's own trust store (see
  [README: Configure an agent](../README.md#configure-an-agent)).
- Inside Docker the default `--proxy-url` is wrong for agents in other containers: pass
  `--proxy-url http://secret-custodian:8080` (the service name).

With `--json` only the JSON is printed, without the block:

```
$ sc --json token create --machine laptop --role reviewer --ttl 12h
{
  "jti": "e7783b5f-4282-4532-93f8-d2fa9897f486",
  "machine": "laptop",
  "role": "reviewer",
  "token": "eyJhbGciOiJFZERTQSIs...<JWT>"
}
```

```
$ sc token ls
JTI                                   MACHINE  ROLE       CREATED               EXPIRES               STATUS
e7783b5f-4282-4532-93f8-d2fa9897f486  laptop   reviewer   2026-10-16T19:55:56Z  2026-10-17T07:55:56Z  active
3f5d576b-e73a-4ce0-a5b2-61410cd488ed  laptop   developer  2026-10-16T19:55:56Z  -                     active
$ sc token revoke 3f5d576b-e73a-4ce0-a5b2-61410cd488ed
token 3f5d576b-e73a-4ce0-a5b2-61410cd488ed revoked
$ sc token revoke-machine laptop
1 token(s) revoked for 'laptop'
$ sc token revoke not-a-uuid
error: invalid token id
```

Revocation is immediate for open MITM tunnels (checked before every request); it only takes effect on
passthrough tunnels when they end (bounded by the idle timeout and lifetime). See
[proxy-internals.md](proxy-internals.md#authentication-and-revocation).

## `sc ca`

The proxy re-signs HTTPS for the hosts that have rules with a local CA whose X.509 name constraints are limited
to the domains **derived from the rules**. There is no command to add or remove a domain: creating a rule for a new host
adds it, deleting the last rule that needs it removes it. Details: [tokens-and-ca.md](tokens-and-ca.md).

| Command | Meaning |
|---|---|
| `sc ca export` | Print the CA certificate (PEM, public part only) on stdout. |
| `sc ca status` | List the permitted domains (read-only; a wildcard rule `*.x` shows as `x`). |

```
$ sc ca status
permitted domains:
$ sc ca status
permitted domains:
  api.github.com
  gitlab.com
  x.example
$ sc ca export > sg-ca.pem
$ head -2 sg-ca.pem
-----BEGIN CERTIFICATE-----
MIIBzzCCAXWgAwIBAgIQGLka/vxjiCk9HHYWLBt+VzAKBggqhkjOPQQDAjAdMRsw
$ sc --json ca status
{
  "domains": [
    "localhost"
  ]
}
```

(The first `ca status` is a fresh vault; the second comes after `secret add gh --host api.github.com ...`,
`secret add gl --host '*.gitlab.com' ...` and a rule for `x.example`.)

**When agents must reload the certificate.** Every `secret add` or `rule add` whose host is new to the CA prints
`warning: the CA certificate changed: agents must reload it (sc ca export)`. **Re-export the certificate and restart or
reconfigure the agents**: a client still holding the previous certificate refuses the newly permitted name, because the
old certificate has narrower constraints. Leaf certificates issued earlier stay valid. Removing a host (deleting its last
rule, a secret or a role) re-issues the certificate too, but agents holding the old one keep working, so no reload is
needed for removals.

A wildcard rule `*.example.com` permits `example.com` (and therefore all its subdomains), since that is how X.509 name
constraints work; the CA does not consult the Public Suffix List, so a rule for `*.github.io` or `*.co.uk` would let the CA
sign for every site under it. Write rules for exact hosts. When no rule remains the CA falls back to a placeholder
(`invalid`) that permits nothing real.

There is no command to rotate the CA key.

## `sc audit`

```
sc audit [--role <ROLE>] [--host <HOST>] [--since <UNIX_TS>] [--limit <N>]
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
$ sc audit --limit 6
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
$ sc --json audit --limit 1
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

## `sc login-url`

```
sc login-url
```

Mints a fresh single-use login link for the web UI and prints it. It works through the admin socket only (the
web listener cannot mint its own credentials), needs no restart, and can be run as often as you like. Each link
works once and expires after 10 minutes; at most 8 pending links are kept (older ones are dropped).

```
$ sc login-url
http://localhost:45081/#t=7bb9d66e57d13ce721571a5cfdf300cceb87ebf3f815177884d0ba79821baa83
$ sc --json login-url
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
| `cannot reach the vault at <socket> (is `sc serve` running?): No such file or directory (os error 2)` | No server, or the wrong socket path. Start `sc serve`, or pass `--socket`/`SC_SOCKET` (remember the default depends on `XDG_RUNTIME_DIR`). |
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
| `invalid name: use [a-z0-9._-], max 64 chars` | Secret name. |
| `role name must be [a-z0-9_-]` | Role name. |
| `unknown role` | `secret add --role`, `rule add` or `token create` with a role that does not exist. |
| `a secret needs at least one rule: ...` | The server (400) when `POST /secrets` carries no rules. The CLI cannot send this: its parser requires `--host` and `--header`/`--query`. |
| `several roles exist (<names>): choose one with --role` | `secret add` without `--role` when more than one role exists (CLI). |
| `this is the last rule of its secret: delete the secret instead, or add another rule first` | `rule rm` of the only rule of a secret (409). |
| `deleting this role would leave secrets without rules: <names>; ...` | `role rm` of a role whose rules are the only ones of some secrets (409); up to 5 names, then `and N more`. |
| `too many rules for one secret (max 20)` | `POST /secrets` with more than 20 rules (400; the CLI sends one). |
| `secret '<name>' not found` | `rule add --secret` (raised by the CLI). |
| `host_pattern must be a lowercase hostname or *.hostname (no IPs)` | Bad `--host`. |
| `--query injects the bare secret: the template must be `{secret}` (got `...`)` | `--query` with another template (CLI). |
| `invalid token id` | `token revoke` argument is not a UUID. |
| `machine must be 1-128 characters without control characters` | `--machine`. |
| `domain rejected: <reason>` | `secret add` or `rule add` whose host the CA cannot permit (for example `reserved` for the placeholder TLD `invalid`); nothing is created. |
| `internal error` | The server hit an unexpected condition (details only in its stderr log). |

### From the argument parser (exit code 2)

```
$ sc rule add --role reviewer --host localhost --secret upstream-key
error: the following required arguments were not provided:
  <--header <HEADER>|--query <QUERY>>
$ echo v | sc secret add k
error: the following required arguments were not provided:
  --host <HOST>
  <--header <HEADER>|--query <QUERY>>
$ sc role add x --unmatched foo
error: invalid value 'foo' for '--unmatched <UNMATCHED>'
  [possible values: passthrough, deny]
$ sc audit --limit 5000
error: invalid value '5000' for '--limit <LIMIT>': 5000 is not in 1..=1000
$ sc token create --machine m --role reviewer --ttl 11y
error: invalid value '11y' for '--ttl <TTL>': expected seconds or a duration like 30m, 12h, 7d
```

### `sc serve` start-up errors

| Message | Cause and fix |
|---|---|
| `no key source: use --key-file, SC_MASTER_KEY or --passphrase` | None given. |
| `ambiguous key source: use exactly one of --key-file, SC_MASTER_KEY, --passphrase` | More than one given. |
| `key file <f> is accessible to group/others (mode 644); run `chmod 600 <f>`` | The key file must be `0600`. |
| `cannot read key file <f>: No such file or directory (os error 2)` | Wrong path or unreadable. In a container: see the Docker key pitfall in the README. |
| `the key is not valid: expected base64 of exactly 32 bytes (generate one with `sc keygen`)` | Corrupt or wrong file/variable. The value is never echoed. |
| `could not unlock the vault with the given key source` | Wrong key, wrong passphrase, key kind different from the one the vault was created with, or a damaged vault. Deliberately non-specific. |
| `database schema version 99 is not supported by this build (supports 1)` | The database was written by a different version of the program. Use a matching `sc`. |
| `--passphrase needs a terminal to prompt on; use --key-file or SC_MASTER_KEY when running unattended` | No TTY on stdin. |
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
