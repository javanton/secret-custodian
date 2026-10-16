# Secret Guardian documentation

Index of the technical documentation. Pages marked "coming" are not written yet because the code they
describe (the `admin`, `cli` and `sg` crates, Docker packaging, the plain-HTTP proxy path) is not implemented.

## Design documents

| Page | Contents |
|---|---|
| [Spec](specs/2026-10-16-secret-guardian-vault.md) | Approved-for-review design: purpose, threat model, storage, tokens, proxy, CA, admin, phases (in Spanish). |
| [Plan](plans/2026-10-16-secret-guardian-vault.md) | Step-by-step implementation plan for phase 1; a reference, where it differs from the code the code wins. |

## Reference

| Page | Contents |
|---|---|
| [architecture.md](architecture.md) | Purpose and threat model, crate map and dependency diagram, sequence of one injected HTTPS request, concurrency model, design decisions. |
| [database-schema.md](database-schema.md) | Every table and column, ER diagram, `meta` keys, plaintext vs ciphertext, permissions and WAL, init/open failure behaviour, versioning status, backup. |
| [crypto-and-keys.md](crypto-and-keys.md) | Key hierarchy (KEK, DEK), Argon2id parameters, AES-256-GCM format, every AAD, zeroization limits, rotation status, failure modes, attacker table. |
| [policy-and-rules.md](policy-and-rules.md) | Roles, `Unmatched`, rule fields and validation, host/method matching, path judging and its closure argument, fail-closed side effects, examples. |
| [tokens-and-ca.md](tokens-and-ca.md) | Token format, verification and revocation, `Proxy-Authorization` parsing, the name-constrained CA, leaf certificates, agent trust setup. |

## Coming with the CLI/Docker release

| Page | Contents |
|---|---|
| `proxy-internals.md` | Coming with the CLI/Docker release. |
| `security-model.md` | Coming with the CLI/Docker release. |
| `operations.md` | Coming with the CLI/Docker release. |
| `cli-reference.md` | Coming with the CLI/Docker release. |
