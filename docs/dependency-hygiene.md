# Dependency hygiene
## Dependency hygiene

`deny.toml` configures [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny): known security
advisories (RustSec), license allow-list, duplicate/wildcard dependency bans, and that every crate
comes from crates.io. Run it the same way CI does:

```sh
cargo install --locked cargo-deny    # once
cargo deny check
```

`cargo audit` (RustSec advisories only, no license/bans checks) is a faster subset for a quick local
check. Workspace crates set `publish = false`: this is an application, not a set of libraries meant
for crates.io, and it lets `cargo-deny`'s wildcard-dependency check accept the internal path
dependencies between crates without disabling the check for real external dependencies.
