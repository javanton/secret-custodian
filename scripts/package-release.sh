#!/usr/bin/env bash
# Builds the static Linux x86_64 `sg` binary and packs it for a release.
#
#   scripts/package-release.sh vX.Y.Z
#
# Output (in $DIST_DIR, default ./dist):
#   sg-vX.Y.Z-x86_64-linux.tar.gz   sg + LICENSE + README.md
#   SHA256SUMS
#
# Needs the musl target (`rustup target add x86_64-unknown-linux-musl`) and `musl-gcc`
# (Debian/Ubuntu: `apt-get install musl-tools`). The tag must match the workspace version.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:?usage: scripts/package-release.sh vX.Y.Z}"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "tag must look like v1.2.3, got '$TAG'" >&2; exit 2; }

VERSION="$(awk -F'"' '/^version *=/ { print $2; exit }' Cargo.toml)"
if [ "v$VERSION" != "$TAG" ]; then
  echo "tag $TAG does not match the workspace version $VERSION in Cargo.toml" >&2
  exit 1
fi

TARGET=x86_64-unknown-linux-musl
DIST="${DIST_DIR:-dist}"
NAME="sg-$TAG-x86_64-linux"

CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --locked --target "$TARGET" -p sg
BIN="${CARGO_TARGET_DIR:-target}/$TARGET/release/sg"

# A static binary has no program interpreter (PT_INTERP). `ldd` is not usable here: on glibc it exits 0
# and prints "statically linked" for static-PIE binaries.
command -v readelf >/dev/null || { echo "readelf is required (apt-get install binutils)" >&2; exit 2; }
if readelf -lW "$BIN" | grep -q 'INTERP'; then
  echo "$BIN is dynamically linked; the release binary must be static" >&2
  exit 1
fi
OUT="$("$BIN" --version)"
case "$OUT" in
  *"$VERSION"*) ;;
  *) echo "'$BIN --version' printed '$OUT', expected it to contain $VERSION" >&2; exit 1 ;;
esac

rm -rf "$DIST/$NAME"
mkdir -p "$DIST/$NAME"
cp "$BIN" LICENSE README.md "$DIST/$NAME/"
# Reproducible archive: fixed order, owner and mtime; gzip without a timestamp.
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime='@0' -C "$DIST" -cf - "$NAME" | gzip -9n > "$DIST/$NAME.tar.gz"
rm -rf "$DIST/$NAME"
(cd "$DIST" && sha256sum "$NAME.tar.gz" > SHA256SUMS)
echo "wrote $DIST/$NAME.tar.gz"
cat "$DIST/SHA256SUMS"
