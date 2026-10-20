# Fuzzing

Coverage-guided fuzzing (libFuzzer through `cargo-fuzz`) of the code that parses or judges
attacker-controlled input. The fuzz crate lives in `fuzz/` and is its own Cargo workspace, so the main
workspace keeps building on the stable toolchain and the fuzz dependencies never reach the product.

## What is fuzzed and why

| Target | Entry point | Invariants checked |
|---|---|---|
| `normalize_path` | `sg_policy::normalize_path` | no panic; output absolute, no `.`/`..`/empty segment, at most input length + 1, idempotent (docs/policy-and-rules.md 6.1) |
| `normalize_host` | `sg_policy::normalize_host` | no panic; idempotent; when `Some`: lowercase, no control characters, <= 253 bytes, no trailing dot |
| `path_judging` | `sg_policy::evaluate` over rules accepted by `insert_rule_in` | no panic; a path-restricted rule never allows a request whose readings (0..n times percent-decoded) contain a dot segment, a non-ASCII or control character, or leave the rule prefix after normalisation (section 6, "closed by construction") |
| `proxy_auth_header` | `sg_auth::extract_proxy_token` | no panic; a token only comes out of a `Bearer`/`Basic` header, never empty; a well-formed Basic header returns exactly its password |
| `token_verify` | `sg_auth::TokenVerifier::verify` | no panic; anything byte-different from the minted token (random strings and byte-level mutations of a genuine token) is `Err` |
| `ca_domain` | `sg_ca::CaService::prepare_domains` | no panic; a domain set is accepted if and only if every entry satisfies the documented DNS rules (lowercase, no IP, no single label except `localhost`, <= 253 bytes, labels <= 63) |

Targets that need state (`path_judging`, `token_verify`, `ca_domain`) create one throwaway vault per
process under `$TMPDIR/sg-fuzz-*`; `scripts/fuzz.sh` removes leftovers.

## Setup (once, per user)

    rustup toolchain install nightly --profile minimal
    cargo install cargo-fuzz --locked

libFuzzer is C++: building needs a C++ compiler (`g++`/`clang++`) on the host.

## Running

    scripts/fuzz.sh            # every target, 60 s each
    scripts/fuzz.sh 300        # 5 minutes each

The script exits non-zero if any target crashes, hangs (10 s per input) or exceeds 2 GiB RSS.
One target, by hand (from `fuzz/`):

    cd fuzz
    cargo +nightly fuzz run normalize_path -- -max_total_time=300

The fuzz crate has its own `Cargo.lock`; it was seeded from the root one so dependency versions match.

## Reproducing and minimising a crash

A failing input is saved as `fuzz/artifacts/<target>/crash-<hash>` (or `timeout-`, `oom-`).

    cd fuzz
    cargo +nightly fuzz run  <target> artifacts/<target>/crash-<hash>     # reproduce
    cargo +nightly fuzz tmin <target> artifacts/<target>/crash-<hash>     # minimise
    xxd artifacts/<target>/minimized-from-<hash>                          # inspect

Turn the minimised input into a regular unit test next to the code under test, then fix the code.

## Adding a target

1. Create `fuzz/fuzz_targets/<name>.rs` (`#![no_main]`, `fuzz_target!(|data: &[u8]| { ... })`).
2. Add a matching `[[bin]]` entry (`name`, `path`, `test = false`, `doc = false`, `bench = false`) to `fuzz/Cargo.toml`.
3. Add a few hand-written seeds as `fuzz/corpus/<name>/seed-N`. Only `seed-*` files are tracked;
   corpus growth from runs is git-ignored.
4. Keep an iteration cheap (cap sizes) and assert real invariants, not just "does not panic".

## Limits

- Fuzzing finds inputs that violate an assertion or crash; it cannot prove their absence. A clean run
  covers the explored part of the input space only, and invariants not written as assertions are not checked.
- Oracles in the targets are re-implementations of the documented rules; a bug shared by code and oracle
  is invisible.
- Only the functions listed above are exercised, in isolation. The proxy, the admin API and TLS handling
  are not fuzzed; `judge_readings` is crate-private and is reached through `evaluate`.
- `token_verify` cannot seed a valid token file (the signing key is random per vault); it mutates a token
  minted in-process instead.
- `ca_domain` is slow (certificate generation per accepted set), so it executes far fewer inputs per second.
