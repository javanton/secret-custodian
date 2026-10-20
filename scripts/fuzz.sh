#!/usr/bin/env bash
# Run every cargo-fuzz target for N seconds each (default 60). Exits non-zero if any target
# crashes, times out or runs out of memory. Requires: rustup nightly + cargo-fuzz (docs/fuzzing.md).
set -u
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

secs="${1:-60}"
case "$secs" in '' | *[!0-9]*) echo "usage: $0 [seconds-per-target]" >&2; exit 2 ;; esac

cd fuzz
targets=$(cargo +nightly fuzz list) || { echo "cargo-fuzz not available" >&2; exit 2; }
failed=()
for t in $targets; do
  echo "=== $t (${secs}s) ==="
  if ! cargo +nightly fuzz run "$t" -- -max_total_time="$secs" -rss_limit_mb=2048 -timeout=10; then
    failed+=("$t")
  fi
done
# Vaults created by the targets (never removed by a process that may abort).
rm -rf "${TMPDIR:-/tmp}"/sg-fuzz-*

if [ "${#failed[@]}" -gt 0 ]; then
  echo "FAILED targets: ${failed[*]} (reproducers in fuzz/artifacts/<target>/)" >&2
  exit 1
fi
echo "all targets ran ${secs}s without a crash"
