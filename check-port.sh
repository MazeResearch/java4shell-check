#!/bin/sh
# java4shell-check: check the Java service behind a local TCP port (or PID).
#
# usage: ./check-port.sh <port>
#        ./check-port.sh --pid <pid>
#
# This does NOT speak HTTP to the service - by design. There is no response
# oracle for CVE-2026-114938: patched and unpatched JVMs produce identical
# HTTP responses for every input, and sending a trigger input to a vulnerable,
# warmed service performs a real out-of-bounds heap write in the application.
#
# Instead, this resolves  port -> listening process -> its JDK  and checks
# exactly the runtime the service uses:
#   1. Find the PID listening on the port (lsof / ss / /proc/net/tcp).
#      Docker-published ports are delegated to check-container.sh.
#   2. Identify the JVM from /proc only: its JDK (mapped libjvm), the JDK's
#      version (the JDK's release file, read through /proc/<pid>/root), and
#      whether the JDK was replaced on disk since the process started.
#      No binary belonging to the target is ever executed by this script.
#   3. Read the process's EFFECTIVE flags with `jcmd <pid> VM.flags -all`.
#      When run as root, jcmd runs as the process's own user (setpriv), never
#      as root. Without jcmd, the flags are rebuilt from the command line,
#      option files and environment with the JVM's precedence rules.
#   4. Verdict for the running service: its JDK version x this CPU x its
#      effective flags.
#
# Run as root or as the process owner (other users' /proc entries are
# unreadable otherwise). Linux only.
#
# Exit codes: 0 not exploitable as running, 1 VULNERABLE, 2 error, 3 uncertain.

set -u

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh" || { echo "ERROR: lib/j4s-common.sh missing"; exit 2; }

PORT=""
PID=""
case "${1:-}" in
  --pid) PID=${2:-} ;;
  --version) echo "java4shell-check $(j4s_tool_version "$TOOL_DIR")"; exit 0 ;;
  -h|--help) sed -n '2,/^# Exit codes/p' "$0"; exit 0 ;;
  "") echo "usage: $0 <port> | --pid <pid>"; exit 2 ;;
  *) PORT=$1 ;;
esac
case "${PORT}${PID}" in
  ''|*[!0-9]*) echo "ERROR: port/pid must be numeric"; exit 2 ;;
esac
[ -d /proc/self ] || { echo "ERROR: /proc not available (Linux only)"; exit 2; }

echo "java4shell-check (port mode) for CVE-2026-114938"
echo "================================================"
echo "version: $(j4s_tool_version "$TOOL_DIR")"
[ -n "$PORT" ] && echo "port: $PORT"
[ -n "$PID" ] && echo "pid: $PID"
echo

docker_ctr_for_port() {
  docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
    | grep -E ":$1->" | head -n 1 | cut -d' ' -f1
}

# ---------------------------------------------------------------- find PID
if [ -z "$PID" ]; then
  if command -v lsof >/dev/null 2>&1; then
    PID=$(lsof -t -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null | head -n 1)
  fi
  if [ -z "$PID" ] && command -v ss >/dev/null 2>&1; then
    PID=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$"' \
         | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' | head -n 1)
  fi
  if [ -z "$PID" ] && [ -r /proc/net/tcp ]; then
    HEXPORT=$(printf '%04X' "$PORT")
    INODES=$(awk -v p=":$HEXPORT" 'NR>1 && $2 ~ p"$" && $4=="0A" {print $10}' \
             /proc/net/tcp /proc/net/tcp6 2>/dev/null || true)
    for ino in $INODES; do
      for piddir in /proc/[0-9]*; do
        for fdpath in "$piddir"/fd/*; do
          case "$(readlink "$fdpath" 2>/dev/null || echo x)" in
            "socket:[$ino]") PID=${piddir#/proc/}; break 3 ;;
          esac
        done
      done
    done
  fi
  if [ -z "$PID" ]; then
    echo "no local process is listening on :$PORT (checked lsof/ss//proc/net/tcp)"
    # Docker NAT mode has no host-side listener; look for a published container.
    if command -v docker >/dev/null 2>&1; then
      CTR=$(docker_ctr_for_port "$PORT")
      if [ -n "$CTR" ]; then
        echo "port $PORT is published by Docker container: $CTR"
        echo "delegating to container mode..."
        exec "$TOOL_DIR/check-container.sh" "$CTR"
      fi
    fi
    echo "ERROR: cannot resolve what listens on :$PORT. Is the service running?"
    echo "Mapping a socket to a process owned by another user needs root (with CAP_SYS_PTRACE)"
    echo "or the process owner. Alternatively: $0 --pid <pid>"
    exit 2
  fi
  echo "listening process pid: $PID"
fi

# --------------------------------------------------------------- identify
[ -r "/proc/$PID/cmdline" ] || { echo "ERROR: no such process (or no permission): $PID"; exit 2; }
CMD0=$(tr '\000' '\n' < "/proc/$PID/cmdline" 2>/dev/null | head -n 1)

# Docker's userland proxy: the real service is a container.
case "$CMD0" in
  *docker-proxy)
    echo "listener is the Docker proxy - resolving the container behind :$PORT"
    if [ -n "$PORT" ] && command -v docker >/dev/null 2>&1; then
      CTR=$(docker_ctr_for_port "$PORT")
      if [ -n "$CTR" ]; then
        echo "container: $CTR - delegating to container mode..."
        exec "$TOOL_DIR/check-container.sh" "$CTR"
      fi
    fi
    echo "ERROR: could not map the Docker port to a container."
    exit 2
    ;;
esac

j4s_inspect_pid "$PID"
if [ "$PID_IS_JVM" -ne 1 ]; then
  if [ -r "/proc/$PID/maps" ]; then
    echo "ERROR: pid $PID is not a JVM (no libjvm mapped)."
  else
    echo "ERROR: cannot read /proc/$PID/maps - run as root or as the process owner."
  fi
  exit 2
fi
JAVA_BIN="$JHOME/bin/java"
JAVA_VERSION=$VER
printf 'jdk:     %s (%s)\n' "${JHOME:-?}" "${VENDOR:-unknown vendor}"
printf 'options: %s\n' "$(j4s_relevant_opts "$(tr '\000' ' ' < "/proc/$PID/cmdline" 2>/dev/null)")"

# ---------------------------------------------- effective flags of the process
echo
echo "== running process flags (authoritative for this service) =="
REAL_FLAGS=""
REAL_SRC=""
REAL_VERSION_OUT=""
RUN_VER=""
JCMD=""
for j in "$JHOME/bin/jcmd" "$(dirname "$JHOME")/bin/jcmd"; do
  [ -x "/proc/$PID/root$j" ] && { JCMD="/proc/$PID/root$j"; break; }
done
# jcmd belongs to the target's JDK, so it is never run with more privilege
# than the target itself: as root it runs as the process owner via setpriv,
# otherwise as the caller (attach only works for the same user anyway).
run_jcmd() { # $1 = pattern the real output must contain, rest = jcmd command
  _pat=$1; shift
  _uid=$(awk '/^Uid:/{print $2}' "/proc/$PID/status" 2>/dev/null)
  _gid=$(awk '/^Gid:/{print $2}' "/proc/$PID/status" 2>/dev/null)
  if [ "$(id -u)" = "0" ]; then
    [ -n "$_uid" ] && [ "$_uid" != "0" ] && command -v setpriv >/dev/null 2>&1 || return 0
    _o=$(setpriv --reuid="$_uid" --regid="$_gid" --clear-groups "$JCMD" "$PID" "$@" 2>/dev/null)
  elif [ "$(id -u)" = "$_uid" ]; then
    _o=$("$JCMD" "$PID" "$@" 2>/dev/null)
  else
    return 0
  fi
  printf '%s\n' "$_o" | grep -q "$_pat" && printf '%s' "$_o"
  return 0
}
if [ -n "$JCMD" ]; then
  REAL_FLAGS=$(run_jcmd ' UseBASE64Intrinsics ' VM.flags -all)
  [ -n "$REAL_FLAGS" ] && REAL_SRC="jcmd $PID VM.flags -all (effective values)"
  REAL_VERSION_OUT=$(run_jcmd '^JDK ' VM.version)
fi

ARGFILE=0
ENV_READABLE=1
if [ -z "$REAL_FLAGS" ]; then
  # No jcmd (JRE images), root process, or attach failed: rebuild from the
  # command line, option files and environment.
  j4s_proc_flags "$PID" "$(j4s_major "$VER")"
  REAL_FLAGS=$PROC_FLAGS
  ARGFILE=$PROC_ARGFILE
  ENV_READABLE=$PROC_ENV_READABLE
  REAL_SRC="command line + option files + environment (jcmd not used)"
  [ "$ENV_READABLE" -eq 0 ] && REAL_SRC="$REAL_SRC; environment NOT readable"
fi
j4s_parse_flags "$REAL_FLAGS"
echo "  source: $REAL_SRC"
echo "  effective: $FLAG_STATUS ($FLAG_DETAIL)"
TRUSTED=1
case "$REAL_SRC" in
  jcmd*) ;;
  *)
    if [ "$ARGFILE" -eq 1 ]; then
      TRUSTED=0
      echo "  note: some options come from a file this tool could not read (or -XX:Flags=);"
      echo "  note: run as root or the process owner, or install a full JDK (jcmd)."
    fi
    if [ "$ENV_READABLE" -eq 0 ]; then
      TRUSTED=0
      echo "  note: cannot read the process environment (_JAVA_OPTIONS can override the command line)."
    fi
    ;;
esac
# A mitigation we cannot fully see is not credited.
if [ $TRUSTED -eq 0 ] && { [ "$FLAG_STATUS" = "FLAG_OFF" ] || [ "$FLAG_STATUS" = "FLAG_AVX2" ]; }; then
  FLAG_STATUS="FLAG_UNKNOWN"
fi

# ------------------------------------------------- version of the running JVM
echo
echo "== running JVM =="
if [ -n "$REAL_VERSION_OUT" ]; then
  # jcmd VM.version: "JDK 21.0.13" - what the process actually runs, even when
  # the JDK on disk has been replaced since.
  RUN_VER=$(j4s_safe "$(printf '%s\n' "$REAL_VERSION_OUT" | sed -n 's/^JDK \([0-9][^ ]*\).*/\1/p' | head -n 1)")
  if [ -n "$RUN_VER" ]; then
    JAVA_VERSION=$RUN_VER
    _full=$REAL_VERSION_OUT
    [ "$OPENJ9" -eq 1 ] && _full="$_full
OpenJ9"
    VSTAT=$(j4s_classify_version "$RUN_VER" "$_full")
    echo "  source: jcmd $PID VM.version"
  fi
elif [ "$STALE" -eq 0 ]; then
  echo "  source: $JHOME/release (read through /proc/$PID/root)"
fi
printf '  version: %s -> %s\n' "${JAVA_VERSION:-unknown}" "$VSTAT"
j4s_version_note "$VSTAT" "$JAVA_VERSION"

# ------------------------------------------------------------------ CPU
j4s_cpu_eval "$(cat /proc/cpuinfo 2>/dev/null)" "$(uname -m 2>/dev/null)"
echo "  cpu:     $HW ($HW_DETAIL)"

# ------------------------------------------------------------- verdict
echo
echo "== verdict for the running service (pid $PID) =="
if [ "$STALE" -eq 1 ]; then
  echo "WARNING: the JDK on disk was replaced after this process started (deleted binary/libjvm"
  echo "WARNING: still mapped). The service still runs the OLD JDK."
fi
j4s_verdict
if [ "$STALE" -eq 1 ] && [ "$EXIT_CODE" -ne 0 ]; then
  if [ "$EXIT_CODE" -eq 1 ]; then
    VERDICT="$VERDICT. The JDK on disk was replaced after it started: patching the disk is not enough, restart it"
  else
    VERDICT="RESTART REQUIRED - it runs a JDK that has since been replaced on disk${RUN_VER:+ (running: $RUN_VER, $VSTAT)}. Restart it, then re-run this check"
    EXIT_CODE=3
  fi
fi
echo "flags source: $REAL_SRC"
j4s_print_verdict
j4s_result_line "${J4S_MODE:-process}" "${J4S_TARGET:-$(uname -n 2>/dev/null) pid $PID${PORT:+ port $PORT}}"
exit $EXIT_CODE
