#!/bin/sh
# java4shell-check: in-place checker for CVE-2026-114938 ("Java4Shell")
#
# Runs ON a Linux host (or inside any container) against the Java runtime
# found there, and decides from the three conditions the advisories give for
# exploitability:
#   1. JDK version  - classified against the published affected ranges
#                     (and OpenJ9, which does not contain the code).
#   2. CPU          - x86-64 with avx512f, avx512bw, avx512vbmi and bmi2
#                     (/proc/cpuinfo). ARM64 never runs the vulnerable code.
#   3. JVM flags    - effective UseBASE64Intrinsics / UseAVX / JIT settings
#                     (-XX:+PrintFlagsFinal, honoring JAVA_TOOL_OPTIONS etc.).
#
# Changes nothing: it starts `java -version` and `java -XX:+PrintFlagsFinal
# -version` as short-lived JVMs with this environment's options (so anything
# JAVA_TOOL_OPTIONS loads, e.g. a -javaagent, starts too) and reads
# /proc/cpuinfo. The tool itself makes no network connections.
#
# Exit codes:
#   0  not vulnerable / not exploitable as configured
#   1  VULNERABLE (affected JDK + AVX-512 VBMI CPU + intrinsic enabled)
#   2  error running the check
#   3  uncertain - guidance printed
#
# Scope: this answers for the JDK on disk with the environment's options. For
# a RUNNING service (its own command-line flags, a JDK replaced since it
# started) use check-port.sh, or check-host.sh for every JVM on the node.
#
# Sources: https://calif.io/java4shell/ , OpenJDK advisory 2026-11-17,
# fix commit openjdk/jdk 5177a70 (JDK-8393212).

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh" || { echo "ERROR: $TOOL_DIR/lib/j4s-common.sh missing"; exit 2; }
J4S_VERSION=$(j4s_tool_version "$TOOL_DIR")

case "${1:-}" in
  --version) echo "java4shell-check $J4S_VERSION"; exit 0 ;;
  -h|--help) sed -n '2,/^# fix commit/p' "$0"; exit 0 ;;
esac

set -u

echo "java4shell-check for CVE-2026-114938"
echo "===================================="
echo "version: ${J4S_VERSION}"
echo "tool dir: $TOOL_DIR"
echo

# ---------------------------------------------------------------- 1. java
JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ]; then
  JAVA_BIN="${JAVA_HOME}/bin/java"
fi
if [ -z "$JAVA_BIN" ]; then
  for c in java /usr/bin/java /usr/local/bin/java /opt/java/openjdk/bin/java /usr/java/default/bin/java; do
    if command -v "$c" >/dev/null 2>&1; then
      JAVA_BIN=$(command -v "$c")
      break
    fi
  done
fi
if [ -z "$JAVA_BIN" ]; then
  for p in /usr/lib/jvm/*/bin/java /usr/lib/jvm/*/jre/bin/java /opt/java/*/bin/java /opt/*/jdk/bin/java; do
    if [ -x "$p" ]; then
      JAVA_BIN="$p"
      break
    fi
  done
fi
if [ -z "$JAVA_BIN" ]; then
  echo "ERROR: no java runtime found. Set JAVA_HOME or extend PATH."
  exit 2
fi
echo "== runtime =="
printf 'java: %s\n' "$JAVA_BIN"
# -XX:-UsePerfData: don't leave hsperfdata files behind.
JAVA_V_OUT=$("$JAVA_BIN" -XX:-UsePerfData -version 2>&1)
JAVA_V_RC=$?
if [ $JAVA_V_RC -ne 0 ]; then
  j4s_jvm_start_failure "$JAVA_V_OUT"
  exit 2
fi
printf '%s\n' "$JAVA_V_OUT" | grep -v 'Picked up ' | LC_ALL=C tr -d '\000-\010\013-\037\177' | sed 's/^/  /'
JAVA_VERSION=$(j4s_safe "$(j4s_version_string "$JAVA_V_OUT")")

# ------------------------------------------------------------- 2. version
VSTAT=$(j4s_classify_version "$JAVA_VERSION" "$JAVA_V_OUT")
echo "version: $JAVA_VERSION -> $VSTAT"
j4s_version_note "$VSTAT" "$JAVA_VERSION"

# ------------------------------------------------------------ 3. hardware
CPUINFO=""
[ -r /proc/cpuinfo ] && CPUINFO=$(cat /proc/cpuinfo 2>/dev/null)
j4s_cpu_eval "$CPUINFO" "$(uname -m 2>/dev/null)"
echo
echo "== hardware =="
echo "cpu: $(uname -m 2>/dev/null) -> $HW (${HW_DETAIL:-could not read CPU flags})"

# ---------------------------------------------------------------- 4. flags
PFF=$("$JAVA_BIN" -XX:-UsePerfData -XX:+PrintFlagsFinal -version 2>/dev/null || true)
j4s_parse_flags "$PFF"
echo
echo "== jvm flags (fresh JVM: defaults + inherited env) =="
echo "flags: $FLAG_STATUS ($FLAG_DETAIL)"
# Only the options relevant to this CVE are shown (these variables often
# carry secrets such as passwords or agent keys).
ENV_SEEN=0
for _v in JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS; do
  eval "_val=\${$_v-__unset__}"   # fixed variable names only
  # shellcheck disable=SC2154
  [ "$_val" = "__unset__" ] && continue
  ENV_SEEN=1
  _o=$(j4s_relevant_opts "$_val")
  printf '  env %s: %s\n' "$_v" "${_o:-(no relevant JVM options)}"
done
[ $ENV_SEEN -eq 1 ] || echo "  env: no JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS / _JAVA_OPTIONS set"

# --------------------------------------------------------------- 5. verdict
echo
echo "== summary =="
echo "version: $JAVA_VERSION -> $VSTAT"
echo "hardware: $HW (${HW_DETAIL:-unknown})"
echo "flags:   $FLAG_STATUS ($FLAG_DETAIL)"
echo
j4s_verdict
j4s_print_verdict
echo
echo "Recommended reading: https://calif.io/java4shell/"
echo "OpenJDK advisory:    https://openjdk.org/groups/vulnerability/advisories/2026-11-17"
j4s_result_line "${J4S_MODE:-host-jdk}" "${J4S_TARGET:-$(uname -n 2>/dev/null)}"
exit $EXIT_CODE
