#!/bin/sh
# java4shell-check: run the checker against a Docker IMAGE (without
# modifying it): the image's JDK version and flags (with its environment),
# and the CPU of the Docker host. The tool is streamed into short-lived
# containers (no bind mounts).
#
# What it touches: pulls the image if it is not present, starts short-lived
# containers from it with networking disabled (--network none) and removes
# them, plus a helper container (busybox, pinned by digest) to read the
# docker host's CPU for images without a shell.
#
# usage: ./check-image.sh <image>[:tag]
#
# Optional: J4S_ENV_FILE=<file> passes extra environment (docker --env-file
# format) to every probe container - used by check-container.sh to replay a
# running container's environment.
#
# Exit codes (same as check.sh):
#   0 not vulnerable / not exploitable as configured
#   1 VULNERABLE
#   2 error
#   3 uncertain

set -u

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh" || { echo "ERROR: lib/j4s-common.sh missing"; exit 2; }

[ $# -ge 1 ] || { echo "usage: $0 <image>[:tag]"; exit 2; }
IMAGE=$1

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 2; }

echo "java4shell-check (image mode) for CVE-2026-114938"
echo "================================================"
echo "version: $(j4s_tool_version "$TOOL_DIR")"
echo "image: $IMAGE"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null 2>&1 \
  || { echo "ERROR: cannot resolve image"; exit 2; }

# Platform sanity: an image for another architecture runs under emulation
# (QEMU/Rosetta), which never exposes AVX-512 - the result would describe the
# emulator, not production. Compared at runtime (what the container really
# runs as), since `docker image inspect` can be blank for multi-platform images.
norm_arch() {
  case "$1" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "$1" ;;
  esac
}
HOST_ARCH=$(norm_arch "$(docker info -f '{{.Architecture}}' 2>/dev/null)")
EMULATED=0
check_emulation() { # $1 = architecture seen inside the container
  _ca=$(norm_arch "$1")
  echo "container arch: ${_ca:-?}   docker host arch: ${HOST_ARCH:-?}"
  if [ -n "$_ca" ] && [ -n "$HOST_ARCH" ] && [ "$_ca" != "$HOST_ARCH" ]; then
    EMULATED=1
    echo "WARNING: the image runs under emulation on this docker host ($_ca on $HOST_ARCH),"
    echo "WARNING: which hides AVX-512. This run cannot tell you about production. Run it on"
    echo "WARNING: a docker host of the image's architecture (e.g. the prod node pool)."
  fi
}
echo

TMPOUT=$(mktemp 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
STAGE=$(mktemp -d 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
trap 'rm -f "$TMPOUT"; rm -rf "$STAGE"' EXIT
trap 'rm -f "$TMPOUT"; rm -rf "$STAGE"; exit 130' INT TERM
cp "$TOOL_DIR/check.sh" "$TOOL_DIR/VERSION" "$STAGE/" && cp -R "$TOOL_DIR/lib" "$STAGE/" \
  || { echo "ERROR: cannot stage the tool"; exit 2; }

# docker run for every probe container: removed afterwards, no network, and
# the replayed environment when called from check-container.sh.
dr() {
  if [ -n "${J4S_ENV_FILE:-}" ] && [ -r "${J4S_ENV_FILE}" ]; then
    docker run --rm --network none --env-file "$J4S_ENV_FILE" "$@"
  else
    docker run --rm --network none "$@"
  fi
}

finish() { # $1 = exit code, $2 = verdict text. Under emulation the CPU seen
  # is the emulator's, so a CPU-based "safe" proves nothing (version- and
  # flag-based answers still hold).
  if [ "$EMULATED" -eq 1 ] && [ "$1" -eq 0 ]; then
    case "$2" in
      *"ON THIS HOST"*)
        echo "(exit 3 instead of 0: the CPU verdict was obtained under emulation)"
        printf 'J4S_RESULT\tmode=image\ttarget=%s\tjdk=-\tversion=-\tvstat=-\thw=EMULATED\tflags=-\tclass=UNCERTAIN\texit=3\n' "$(j4s_safe "${J4S_TARGET:-$IMAGE}")"
        exit 3 ;;
    esac
  fi
  exit "$1"
}

# --- fast path: image has a shell -> stream the tool in and run check.sh ---
for SH in /bin/sh /bin/bash /usr/bin/sh /usr/bin/bash /bin/busybox; do
  if dr --entrypoint "$SH" "$IMAGE" -c true >/dev/null 2>&1; then
    echo "shell found in image: $SH"
    check_emulation "$(dr --entrypoint "$SH" "$IMAGE" -c 'uname -m' 2>/dev/null)"
    echo
    # shellcheck disable=SC2016
    tar -C "$STAGE" -cf - . | dr -i -e J4S_MODE=image -e J4S_TARGET="${J4S_TARGET:-$IMAGE}" \
      --entrypoint "$SH" "$IMAGE" -c \
      'd=$(mktemp -d 2>/dev/null) || d=/tmp/.j4s-check; mkdir -p "$d" && tar -xf - -C "$d" && sh "$d/check.sh"' \
      > "$TMPOUT" 2>&1
    RC=$?
    if grep -q '^J4S_RESULT' "$TMPOUT"; then
      cat "$TMPOUT"
      finish $RC "$(grep '^VERDICT:' "$TMPOUT")"
    fi
    echo "the tool could not run inside the image (no tar or no writable /tmp?); falling back to direct java probing"
    sed 's/^/  /' "$TMPOUT" | tail -n 5
    break
  fi
done

# --- fallback: no shell (distroless etc.) -> drive the java binary directly ---
echo "no shell in image; falling back to direct java probing"
echo

run_java() { # $1 = java path, rest = args
  _jp=$1; shift
  dr --entrypoint "$_jp" "$IMAGE" "$@"
}

# Candidate 1: the image's own ENTRYPOINT/CMD often IS the java binary.
ENTRY_JAVA=$(docker image inspect -f '{{json .Config.Entrypoint}} {{json .Config.Cmd}}' "$IMAGE" \
  | tr ',"[] ' '\n\n\n\n\n' | grep -E '^/.*/java$' | head -n 1)

JP=""
for c in $ENTRY_JAVA \
         /usr/bin/java /opt/java/openjdk/bin/java /usr/lib/jvm/bin/java \
         /java/bin/java /opt/cfw/java/bin/java /usr/local/bin/java; do
  [ -n "$c" ] || continue
  if run_java "$c" -version >/dev/null 2>&1; then
    JP="$c"
    break
  fi
done
# Candidate 2: PATH entries from the image env.
if [ -z "$JP" ]; then
  PTH=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" \
        | sed -n 's|^PATH=||p' | head -n 1)
  for d in $(printf '%s' "$PTH" | tr ':' ' '); do
    if run_java "$d/java" -version >/dev/null 2>&1; then
      JP="$d/java"
      break
    fi
  done
fi
if [ -z "$JP" ]; then
  # Maybe a java exists but refuses to start (bad options in the image env).
  for c in $ENTRY_JAVA /usr/bin/java /opt/java/openjdk/bin/java; do
    OUT=$(run_java "$c" -version 2>&1) && continue
    case "$OUT" in
      *"Could not create the Java Virtual Machine"*|*"Unrecognized VM option"*)
        j4s_jvm_start_failure "$OUT"; exit 2 ;;
    esac
  done
  echo "ERROR: could not locate a java binary in the image; run check.sh inside the container manually."
  exit 2
fi
echo "java found: $JP"

echo
echo "== runtime =="
JAVA_V_OUT=$(run_java "$JP" -version 2>&1)
printf '%s\n' "$JAVA_V_OUT" | grep -v 'Picked up ' | LC_ALL=C tr -d '\000-\010\013-\037\177' | sed 's/^/  /'
JAVA_VERSION=$(j4s_safe "$(j4s_version_string "$JAVA_V_OUT")")
VSTAT=$(j4s_classify_version "$JAVA_VERSION" "$JAVA_V_OUT")
echo "version: $JAVA_VERSION -> $VSTAT"
j4s_version_note "$VSTAT" "$JAVA_VERSION"

echo
echo "== jvm flags (defaults + image env) =="
PFF=$(run_java "$JP" -XX:+PrintFlagsFinal -version 2>/dev/null || true)
j4s_parse_flags "$PFF"
echo "flags: $FLAG_STATUS ($FLAG_DETAIL)"
docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" \
  | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' | while IFS= read -r _e; do
    _o=$(j4s_relevant_opts "${_e#*=}")
    printf '  env %s: %s\n' "${_e%%=*}" "${_o:-(no relevant JVM options)}"
  done

echo
echo "== hardware (docker host CPU, read by a helper container on the same daemon) =="
# Arch the image really runs as (catches emulation, e.g. amd64 on arm64).
check_emulation "$(run_java "$JP" -XshowSettings:properties -version 2>&1 | sed -n 's/^ *os\.arch = //p' | head -n 1)"
HELPER=busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662   # busybox:1.36
CPUINFO=$(docker run --rm --network none "$HELPER" cat /proc/cpuinfo 2>/dev/null)
if [ -n "$CPUINFO" ]; then
  j4s_cpu_eval "$CPUINFO" "$(docker run --rm --network none "$HELPER" uname -m 2>/dev/null)"
else
  HW="HW_UNKNOWN"; HW_DETAIL="could not read the docker host's CPU (helper image $HELPER unavailable?)"
fi
echo "  $HW ($HW_DETAIL)"

echo
echo "== summary =="
echo "version: $JAVA_VERSION -> $VSTAT"
echo "hardware: $HW ($HW_DETAIL) [docker host CPU]"
echo "flags:   $FLAG_STATUS ($FLAG_DETAIL)"
echo
j4s_verdict
j4s_print_verdict
echo "Recommended reading: https://calif.io/java4shell/"
JAVA_BIN=$JP
j4s_result_line image "${J4S_TARGET:-$IMAGE}"
finish $EXIT_CODE "$VERDICT"
