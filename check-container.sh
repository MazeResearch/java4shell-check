#!/bin/sh
# java4shell-check: check a RUNNING Docker container and every JVM in it.
#
# usage: ./check-container.sh <container-name-or-id>
#
# Bonus over image mode: docker exec inherits the container's real runtime
# environment (JAVA_TOOL_OPTIONS=... passed with -e are honored), and every
# running JVM in the container is checked with check-port.sh --pid, which
# reads its EFFECTIVE flags (jcmd) and detects a JDK replaced under a JVM
# that was not restarted.
#
# What it touches: copies check.sh, check-port.sh and lib/ into the
# container's /tmp/.j4s-check, runs them with docker exec, and removes them
# (as root inside the container). Read-only root filesystems and shell-less
# (distroless) containers are instead replayed in a fresh, short-lived
# container of the same image ID with the same environment variables (not the
# same volumes) via check-image.sh, and the JVM options from the app's command
# line are printed.
#
# Exit codes (same as check.sh): 0 safe, 1 VULNERABLE, 2 error, 3 uncertain.

set -u

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh" || { echo "ERROR: lib/j4s-common.sh missing"; exit 2; }

[ $# -ge 1 ] || { echo "usage: $0 <container>"; exit 2; }
CTR=$1

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 2; }
docker container inspect "$CTR" >/dev/null 2>&1 || { echo "ERROR: no such container: $CTR"; exit 2; }

echo "java4shell-check (container mode) for CVE-2026-114938"
echo "===================================================="
echo "version: $(j4s_tool_version "$TOOL_DIR")"
echo "container: $CTR"
echo

DEST=/tmp/.j4s-check
CLEANUP() {
  # docker cp creates root-owned files: remove them as root inside the container.
  if ! docker exec -u 0 "$CTR" rm -rf "$DEST" >/dev/null 2>&1; then
    echo "WARNING: could not remove $DEST from container $CTR; remove it manually."
  fi
}

# worst-of: 1 (vulnerable) > 3 (uncertain) > 2 (error) > 0 (safe).
# Any other code (126/127 cannot run, 137 killed, ...) counts as an error.
norm() { case "$1" in 0|1|2|3) echo "$1" ;; *) echo 2 ;; esac; }
worse() {
  _a=$(norm "$1"); _b=$(norm "$2")
  for _c in 1 3 2 0; do
    if [ "$_a" = "$_c" ] || [ "$_b" = "$_c" ]; then echo "$_c"; return; fi
  done
}

# Only the options relevant to this CVE from the app's command line (full
# command lines often contain secrets).
app_options() {
  docker top "$CTR" -o pid,args 2>/dev/null | awk 'NR > 1' | while IFS= read -r _l; do
    _o=$(j4s_relevant_opts "$_l")
    printf '  pid %s: %s\n' "$(printf '%s' "$_l" | awk '{print $1}')" "${_o:-(no relevant JVM options)}"
  done
}

# Replay in a fresh container of the same image (by image ID, not tag) with
# the same environment variables - same JDK, same CPU, same env options; not
# the same volumes or mounts. Used when the tool cannot be copied in
# (read-only root filesystem) or the container has no shell.
replay() { # $1 = reason
  echo "$1"
  echo "replaying the check in a fresh container of the same image with the same environment..."
  echo
  IMG_ID=$(docker container inspect -f '{{.Image}}' "$CTR")
  IMG_NAME=$(docker container inspect -f '{{.Config.Image}}' "$CTR")
  ENVF=$(mktemp 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
  trap 'rm -f "$ENVF"; rm -rf "${STAGE:-}"' EXIT
  trap 'rm -f "$ENVF"; rm -rf "${STAGE:-}"; exit 130' INT TERM
  docker container inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CTR" | grep -v '^$' > "$ENVF"
  J4S_ENV_FILE=$ENVF J4S_TARGET="container $CTR (replayed from image $IMG_NAME)" "$TOOL_DIR/check-image.sh" "$IMG_ID"
  RC=$(norm $?)
  echo
  echo "== JVM options on the application command line in $CTR (they override the environment) =="
  app_options
  echo "note: replayed check - if the options above set -XX:-UseBASE64Intrinsics or"
  echo "note: -XX:UseAVX=2 (and nothing later re-enables it), the running app is mitigated."
  exit "$RC"
}

SH=""
for s in /bin/sh /bin/bash /usr/bin/sh /busybox/sh; do
  if docker exec "$CTR" "$s" -c true >/dev/null 2>&1; then SH=$s; break; fi
done
[ -n "$SH" ] || replay "no shell in the container (distroless or similar)."

# Copy only what runs inside (works for running containers, unlike volumes).
STAGE=$(mktemp -d 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
trap 'rm -rf "$STAGE"' EXIT
trap 'rm -rf "$STAGE"; CLEANUP; exit 130' INT TERM
cp "$TOOL_DIR/check.sh" "$TOOL_DIR/check-port.sh" "$TOOL_DIR/VERSION" "$STAGE/" && cp -R "$TOOL_DIR/lib" "$STAGE/" \
  || { echo "ERROR: cannot stage the tool"; exit 2; }
# mktemp -d creates a 0700 directory; the container's user (often not root)
# must be able to read the copy.
chmod -R a+rX "$STAGE"
docker cp "$STAGE/." "$CTR:$DEST" >/dev/null 2>&1 \
  || replay "cannot copy the tool into the container (read-only filesystem or no /tmp)."

# --- the container's JDK + environment, then every running JVM in it ---
echo "shell found: $SH"
echo
docker exec -e J4S_MODE=container -e J4S_TARGET="container $CTR (JDK + env)" "$CTR" "$SH" "$DEST/check.sh"
ENV_RC=$(norm $?)
JPIDS=$(docker exec "$CTR" "$SH" -c '
  for d in /proc/[0-9]*; do
    p=${d#/proc/}
    [ "$p" = "$$" ] && continue
    grep -qE "/lib(jvm|j9vm[0-9]*)\.so" "$d/maps" 2>/dev/null && echo "$p"
  done' 2>/dev/null)
# The running JVMs decide (their own command-line flags count); the JDK + env
# check above only decides when no JVM is running.
RC=""
for p in $JPIDS; do
  case "$p" in *[!0-9]*) continue ;; esac
  echo
  echo "################ running JVM pid $p (inside the container) ################"
  docker exec -e J4S_MODE=container-jvm -e J4S_TARGET="container $CTR pid $p" "$CTR" "$SH" "$DEST/check-port.sh" --pid "$p"
  _rc=$(norm $?)
  RC=$(worse "${RC:-0}" "$_rc")
done
if [ -z "$RC" ]; then
  RC=$ENV_RC
  echo
  echo "note: no running JVM found in the container; the verdict above covers its JDK and environment only."
fi
CLEANUP
echo
echo "container exit code (worst of its running JVMs, or the JDK + env check if none run): $RC"
exit "$RC"
