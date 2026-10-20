# Releasing

How CI works and how to publish a version. The pipeline is `.github/workflows/`; the packaging logic lives in
`scripts/package-release.sh` so you can run the same steps locally.

## What runs on every branch and pull request

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml):

| Job | What it does |
|---|---|
| `check` | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` (with `node` installed so the web UI's JS tests run) |
| `e2e` | `scripts/e2e.sh`: real `curl` through the real proxy to a local TLS upstream |
| `dependency-hygiene` | `cargo deny check`: advisories, licenses, bans, sources (see [dependency-hygiene.md](dependency-hygiene.md)) |

GitHub's own [Dependabot](../.github/dependabot.yml) opens pull requests for outdated Cargo, Docker and Actions
dependencies on a weekly schedule; secret scanning and push protection are repository settings, automatic on a
public GitHub repository.

`scripts/e2e-docker.sh` is not in CI (it needs a Docker daemon of its own); run it before a release when you touch the
Dockerfile or anything in the container path.

## Publishing a version

1. Bump `version` under `[workspace.package]` in `Cargo.toml` (and let `Cargo.lock` follow: `cargo build`). Commit on a
   branch, merge it.
2. Tag the merge commit with the same number, prefixed by `v`, and push the tag:

   ```sh
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

3. [`.github/workflows/release.yml`](../.github/workflows/release.yml) (only tags matching `vMAJOR.MINOR.PATCH`) runs:

   | Job | Result |
   |---|---|
   | `binary` | Builds the static `x86_64-unknown-linux-musl` binary with `scripts/package-release.sh`, which **fails if the tag differs from the `Cargo.toml` version**, if the binary is not statically linked, or if `sg --version` does not print the version. Produces `sg-vX.Y.Z-x86_64-linux.tar.gz` (binary, `LICENSE`, `README.md`) and `SHA256SUMS`, uploaded as a build artifact. |
   | `publish-release` | Creates the GitHub Release for the tag (`gh release create`) and attaches both files directly as release assets. |
   | `publish-image` | Builds the `Dockerfile` and pushes `:vX.Y.Z` and `:latest` to the GitHub Container Registry (`ghcr.io/<owner>/<repo>`). |

The archive is reproducible in its packaging (fixed file order, owner, mtime, no gzip timestamp); the compiled binary
itself is not guaranteed to be bit-for-bit reproducible across toolchain versions.

## Building the release package locally

Needs the musl target and `musl-gcc` (`apt-get install musl-tools`, `rustup target add x86_64-unknown-linux-musl`):

```sh
scripts/package-release.sh v0.1.0     # writes ./dist/sg-v0.1.0-x86_64-linux.tar.gz and ./dist/SHA256SUMS
```

To build it exactly as CI does without installing anything, use the same image:

```sh
docker run --rm -v "$PWD":/src:ro -v /tmp/sg-dist:/out -e CARGO_TARGET_DIR=/tmp/t -e DIST_DIR=/out -w /src rust:1-bookworm \
  bash -c 'apt-get update -qq && apt-get install -y -qq musl-tools && rustup target add x86_64-unknown-linux-musl && scripts/package-release.sh v0.1.0'
```

Validate the workflow YAML itself (no GitHub account needed) with [`actionlint`](https://github.com/rhysd/actionlint):

```sh
docker run --rm -v "$PWD":/repo:ro -w /repo rhysd/actionlint:latest
```

## Notes and limits

- Only Linux x86_64 is built. aarch64 needs an ARM runner or cross-compilation and is not set up.
- musl's allocator is slower than glibc's under heavy multi-threaded allocation; the proxy's workload is I/O bound, so it
  is not expected to matter, but the Docker image (Debian, glibc) is available if you prefer it.
- `SHA256SUMS` detects a corrupted download. It does not authenticate the release: anyone who can edit the release
  page can replace both files. Signing the checksums (for example with minisign or cosign) is a possible later step.
- `publish-image` needs `permissions: packages: write` on the workflow (already set) and a public or appropriately
  visible package setting on the repository the first time an image is pushed, or it stays private by default.
