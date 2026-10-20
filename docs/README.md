# Secret Custodian documentation

Index of the documentation. New here? Start with the [project README](../README.md) (what it is, a verified quick start,
how to configure an agent), then the page for your role below.

## I want to use it

| Page | Contents |
|---|---|
| [quickstart.md](quickstart.md) | The full verified walkthrough: build, configure, call a real upstream, read the audit log. |
| [cli-reference.md](cli-reference.md) | Every `sg` command, flag, default, env var, exit code, output example and error message; secret input rules; the `token create` environment block; TTL syntax. |
| [operations.md](operations.md) | Installing from source and Docker, directories and permissions, key management, backups, upgrades, a systemd user service, containers and networking, trusting the CA on agents, routine tasks, observability, troubleshooting table. |
| [policy-and-rules.md](policy-and-rules.md) | Roles, `Unmatched`, rule fields and validation, host/method matching, path judging and its closure argument, fail-closed side effects, examples (CLI and JSON). |
| [tokens-and-ca.md](tokens-and-ca.md) | Token format, verification and revocation, `Proxy-Authorization` parsing, the name-constrained CA, leaf certificates, agent trust setup. |

## I want to understand or audit it

| Page | Contents |
|---|---|
| [security-model.md](security-model.md) | Assets, trust boundaries, attacker models, mitigations mapped to code, non-goals and residual risks, hardening history, deployment checklist. |
| [proxy-internals.md](proxy-internals.md) | Full request lifecycle (CONNECT/MITM, passthrough, plain HTTP), authentication and revocation, header rewriting, network policy, limits and timeouts, every audit decision, every error response. |
| [admin-api.md](admin-api.md) | The admin API: both listeners (Unix socket and web), authentication, guards, every route with request, response and errors. |
| [architecture.md](architecture.md) | Purpose and threat model summary, crate map and dependency diagram, process layout, the sequence of one injected request, concurrency model, design decisions. |
| [crypto-and-keys.md](crypto-and-keys.md) | Key hierarchy (KEK, DEK), key sources, Argon2id parameters, AES-256-GCM format, every AAD, zeroization limits, rotation status, failure modes, attacker table. |
| [database-schema.md](database-schema.md) | Every table and column, ER diagram, `meta` keys, plaintext vs ciphertext, permissions and WAL, init/open failure behaviour, versioning status, backup. |

## I want to change it

| Page | Contents |
|---|---|
| [testing.md](testing.md) | Test strategy, inventory per crate (542 tests), what the end-to-end scripts assert, how the security regression tests are organised, how to add tests, known gaps. |
| [dependency-hygiene.md](dependency-hygiene.md) | `cargo-deny`/`cargo-audit` configuration, what they check, how to run them locally. |
| [releasing.md](releasing.md) | The CI pipeline, how to publish a version (tag `vX.Y.Z`), the static musl binary, package registry, release and Docker image, building the package locally. |
| [Spec](specs/2026-10-16-secret-guardian-vault.md) | Approved-for-review design: purpose, threat model, storage, tokens, proxy, CA, admin, phases (in Spanish). Where it differs from the code, the code wins. |
| [Plan](plans/2026-10-16-secret-guardian-vault.md) | Step-by-step implementation plan for phase 1 (in Spanish); a historical reference. |

## Conventions

- The reference pages describe the code at the commit they were written against and cite files and functions so they can be
  checked. Where a page and the code disagree, the code wins; please fix the page.
- The spec and plan are written in Spanish; everything else is in English.
- Commands, flags, outputs and error messages in the guides were copied from real runs of the binary.
