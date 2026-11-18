#!/bin/sh
# java4shell-check: inventory EVERY running JVM on a Linux host - including
# JVMs inside containers on that host - and classify each.
#
# usage: sudo ./check-host.sh            human-readable report
#        sudo ./check-host.sh --machine  only J4S_* lines (for fleet runs)
#
# Strictly read-only and passive. For each process it only READS /proc:
#   - /proc/<pid>/maps     -> is it a JVM (libjvm / OpenJ9), where is its JDK,
#                             and was that JDK replaced on disk since it started
#   - /proc/<pid>/root/<jdk>/release  -> JDK version, vendor, JVM variant
#   - /proc/<pid>/cmdline + environ   -> effective -XX flags, rebuilt with the
#                             JVM's precedence rules
#   - /proc/<pid>/cgroup   -> container id
# It starts no JVM, does not attach to any JVM (no jcmd), sends no signals and
# writes nothing. The verdict per JVM combines version x CPU x effective
# flags - the three conditions the advisories give for exploitability.
#
# Machine-readable lines (tab-separated key=value; printed after the human
# report, or alone with --machine; report.sh reads them):
#   J4S_JVM  host= hw= pid= ctr= name= jdk= vendor= version= vstat= flags= stale= class=
#   (ctr = container id; name = the container's HOSTNAME: on plain Docker the
#   12-character container id unless --hostname was set, on Kubernetes the
#   pod name)
#   J4S_HOST host= hw= jvms= vulnerable= worst=
# class: VULNERABLE | RESTART_REQUIRED | PROBABLY_FIXED | UNCERTAIN |
#        MITIGATED | NOT_VULNERABLE
#
# Exit codes: 0 no JVM vulnerable, 1 at least one VULNERABLE JVM,
#             3 restart-required / probably-fixed / uncertain JVMs, 2 error.
# Run as root: reading other users' /proc entries needs it.

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh" || { echo "ERROR: lib/j4s-common.sh missing"; exit 2; }

MACHINE=0
case "${1:-}" in
  --machine) MACHINE=1 ;;
  -h|--help) sed -n '2,/^# Run as root/p' "$0"; exit 0 ;;
  --version) echo "java4shell-check $(j4s_tool_version "$TOOL_DIR")"; exit 0 ;;
esac

set -u

say() { [ $MACHINE -eq 1 ] || printf '%s\n' "$*"; }

[ -d /proc/self ] || { echo "ERROR: /proc not available (Linux only)"; exit 2; }
for _tool in awk sed grep tr sort cut head readlink uname id; do
  command -v "$_tool" >/dev/null 2>&1 || {
    echo "ERROR: required tool missing: $_tool"
    [ $MACHINE -eq 1 ] && printf 'J4S_HOST\terror=missing-tool-%s\n' "$_tool"
    exit 2
  }
done

say "java4shell-check (host inventory) for CVE-2026-114938"
say "====================================================="
say "version: $(j4s_tool_version "$TOOL_DIR")"
[ "$(id -u)" = "0" ] || say "WARNING: not root - JVMs owned by other users will be missed or partially read."
say

# ------------------------------------------------------------------ CPU
j4s_cpu_eval "$(cat /proc/cpuinfo 2>/dev/null)" "$(uname -m)"
say "cpu: $(uname -m) -> $HW ($HW_DETAIL)"
say

# ------------------------------------------------------------- JVMs
N=0; VULN=0; WORST=0
rank() { case "$1" in 1) echo 4 ;; 3) echo 3 ;; 2) echo 2 ;; *) echo 1 ;; esac; }
HOSTNAME_SAFE=$(j4s_safe "$(uname -n)")
LINES=""

for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  [ "$pid" = "$$" ] && continue
  j4s_inspect_pid "$pid"
  [ "$PID_IS_JVM" -eq 1 ] || continue
  N=$((N + 1))
  SHOWN_VER=${VER:-unknown}
  # A replaced JDK's release file describes the NEW JDK, not this JVM's code.
  [ "$STALE" -eq 1 ] && SHOWN_VER="replaced-on-disk(now:${VER:-?})"

  j4s_proc_flags "$pid" "$(j4s_major "$VER")"
  j4s_parse_flags "$PROC_FLAGS"
  # Default (flag not set anywhere) = intrinsic enabled, UseAVX at CPU maximum.
  FLAGS_SHOWN=$FLAG_STATUS
  [ "$FLAG_STATUS" = "FLAG_UNKNOWN" ] && FLAGS_SHOWN="default(enabled)"
  [ "$PROC_ARGFILE" -eq 1 ] && FLAGS_SHOWN="$FLAGS_SHOWN+options-file-unreadable"
  [ "$PROC_ENV_READABLE" -eq 0 ] && FLAGS_SHOWN="$FLAGS_SHOWN+env-unreadable"
  # A mitigation we can't fully see is not credited.
  if { [ "$PROC_ARGFILE" -eq 1 ] || [ "$PROC_ENV_READABLE" -eq 0 ]; } && \
     { [ "$FLAG_STATUS" = "FLAG_OFF" ] || [ "$FLAG_STATUS" = "FLAG_AVX2" ]; }; then
    FLAG_STATUS="FLAG_UNKNOWN"
  fi

  j4s_verdict
  if [ "$STALE" -eq 1 ] && [ "$EXIT_CODE" -ne 0 ]; then
    VERDICT="RESTART REQUIRED - JDK replaced on disk after this JVM started; it still runs the old code"
    EXIT_CODE=3
  fi
  CLASS=$(j4s_class)
  [ "$CLASS" = "VULNERABLE" ] && VULN=$((VULN + 1))
  [ "$(rank "$EXIT_CODE")" -gt "$(rank "$WORST")" ] && WORST=$EXIT_CODE

  CTR=$(sed -n 's#.*[/-]\([0-9a-f]\{64\}\)\(\.scope\)\{0,1\}$#\1#p' "$d/cgroup" 2>/dev/null | head -n 1 | cut -c1-12)
  CNAME=""
  if [ -n "$CTR" ] && [ "$PROC_ENV_READABLE" -eq 1 ]; then
    # The container's hostname, to tell containers apart in the report.
    CNAME=$(tr '\n\000' '\001\n' < "$d/environ" 2>/dev/null | sed -n 's/^HOSTNAME=//p' | head -n 1)
    CNAME=$(j4s_safe "$CNAME")
  fi

  if [ $MACHINE -eq 0 ]; then
    printf 'JVM pid %s%s%s\n' "$pid" "${CTR:+  container $CTR}" "${CNAME:+  ($CNAME)}"
    printf '  jdk:     %s  (%s)\n' "${JHOME:-?}" "${VENDOR:-unknown vendor}"
    printf '  version: %s -> %s\n' "$SHOWN_VER" "$VSTAT"
    printf '  flags:   %s (%s)\n' "$FLAGS_SHOWN" "$FLAG_DETAIL"
    [ "$STALE" -eq 1 ] && printf '  STALE:   JDK replaced on disk after this JVM started\n'
    printf '  => %s - %s\n\n' "$CLASS" "$VERDICT"
  fi
  LINES="$LINES$(printf 'J4S_JVM\thost=%s\thw=%s\tpid=%s\tctr=%s\tname=%s\tjdk=%s\tvendor=%s\tversion=%s\tvstat=%s\tflags=%s\tstale=%s\tclass=%s' \
    "$HOSTNAME_SAFE" "$HW" "$pid" "${CTR:--}" "${CNAME:--}" "${JHOME:--}" "$(printf '%s' "${VENDOR:--}" | tr ' ' '_')" \
    "$SHOWN_VER" "$VSTAT" "$FLAGS_SHOWN" "$STALE" "$CLASS")
"
done

say "== host summary =="
say "cpu: $HW   JVMs found: $N   vulnerable: $VULN"
[ $N -eq 0 ] && say "no running JVM found (as $(id -un 2>/dev/null || id -u))."
# Machine-readable lines (always printed, so saved output works with report.sh).
[ $MACHINE -eq 0 ] && echo
printf '%s' "$LINES"
printf 'J4S_HOST\thost=%s\thw=%s\tjvms=%s\tvulnerable=%s\tworst=%s\n' "$HOSTNAME_SAFE" "$HW" "$N" "$VULN" "$WORST"
exit $WORST
