#!/bin/sh
# Build java4shell-check release artifacts into dist/.
#
# Produces:
#   dist/java4shell-check-<version>.tar.gz   normal folder distribution
#   dist/j4s-check.sh                        single-file, self-extracting build
#   dist/SHA256SUMS.txt                      checksums for both
#
# Usage: ./build.sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
J4S_VERSION=$(cat VERSION)

STAGE=$(mktemp -d 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 1; }
trap 'rm -rf "$STAGE"' EXIT INT TERM

# ---------------------------------------------------------- folder staging
PKG="$STAGE/java4shell-check"
mkdir -p "$PKG"
cp check.sh check-image.sh check-container.sh check-port.sh check-host.sh report.sh AGENTS.md CLAUDE.md \
   LICENSE VERSION CHANGELOG.md README.md TESTING.md "$PKG/"
cp -R cloud lib tests "$PKG/"

mkdir -p dist
TARBALL="dist/java4shell-check-$J4S_VERSION.tar.gz"
# No macOS metadata (xattrs / AppleDouble files): GNU tar on Linux prints a
# warning per file for them.
export COPYFILE_DISABLE=1
if tar --no-xattrs -cf /dev/null -C "$STAGE" java4shell-check 2>/dev/null; then
  TAR_FLAGS="--no-xattrs"
  tar --no-mac-metadata -cf /dev/null -C "$STAGE" java4shell-check 2>/dev/null && TAR_FLAGS="$TAR_FLAGS --no-mac-metadata"
else
  TAR_FLAGS=""
fi
# shellcheck disable=SC2086
tar $TAR_FLAGS -C "$STAGE" -czf "$TARBALL" java4shell-check

# ------------------------------------------------- single-file self-extractor
# The archive is appended as base64 after a marker; the script extracts
# itself to a temp dir and runs check.sh from there, then cleans up.
SINGLE="dist/j4s-check.sh"
{
  cat <<HDR
#!/bin/sh
# java4shell-check $J4S_VERSION - single-file release (self-extracting).
#
# Non-intrusive checker for CVE-2026-114938 ("Java4Shell"). Linux.
# Full documentation: README inside the archive, or the project page.
#
# Usage:   sh j4s-check.sh                 the JDK + environment on this host
#          sudo sh j4s-check.sh host       every running JVM on this node (containers too)
#          sh j4s-check.sh port <port>     the Java service behind a local port (or: port --pid <pid>)
#          sh j4s-check.sh image <image>   a Docker image
#          sh j4s-check.sh container <c>   a running Docker container
#          sh j4s-check.sh report [files]  Markdown report from collected results
# Verify the SHA256 against SHA256SUMS.txt before running.
set -u
J4S_TMP=\$(mktemp -d 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
trap 'rm -rf "\$J4S_TMP"' EXIT INT TERM
if ! sed -n '/^__J4S_ARCHIVE__\$/,\$p' "\$0" | tail -n +2 | base64 -d >/dev/null 2>&1; then
  B64D="base64 -D"    # older macOS base64 (admin workstations running image/container modes)
else
  B64D="base64 -d"
fi
sed -n '/^__J4S_ARCHIVE__\$/,\$p' "\$0" | tail -n +2 | \$B64D | tar xz -C "\$J4S_TMP" \
  || { echo "ERROR: self-extraction failed (truncated download?)"; exit 2; }
J4S_DIR="\$J4S_TMP/java4shell-check"
case "\${1:-}" in
  host)      shift; sh "\$J4S_DIR/check-host.sh" "\$@" ;;
  port)      shift; sh "\$J4S_DIR/check-port.sh" "\$@" ;;
  image)     shift; sh "\$J4S_DIR/check-image.sh" "\$@" ;;
  container) shift; sh "\$J4S_DIR/check-container.sh" "\$@" ;;
  report)    shift; sh "\$J4S_DIR/report.sh" "\$@" ;;
  *)         sh "\$J4S_DIR/check.sh" "\$@" ;;
esac
exit \$?
__J4S_ARCHIVE__
HDR
  base64 < "$TARBALL"
} > "$SINGLE"
chmod +x "$SINGLE"

# ---------------------------------------------------------------- checksums
SUMS="dist/SHA256SUMS.txt"
if command -v sha256sum >/dev/null 2>&1; then
  ( cd dist && sha256sum "java4shell-check-$J4S_VERSION.tar.gz" j4s-check.sh ) > "$SUMS"
else
  ( cd dist && shasum -a 256 "java4shell-check-$J4S_VERSION.tar.gz" j4s-check.sh ) > "$SUMS"
fi

echo "built:"
sed 's/^/  /' "$SUMS"
echo "  $SINGLE ($(wc -c < "$SINGLE" | tr -d ' ') bytes)"
echo "  $TARBALL ($(wc -c < "$TARBALL" | tr -d ' ') bytes)"
