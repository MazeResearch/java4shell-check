# shellcheck shell=sh
# java4shell-check shared logic: version classification, JVM flag parsing,
# process inspection, CPU evaluation and the verdict engine
# (version x CPU x flags). Sourced, never executed, by every check script
# (check.sh, check-host.sh, check-port.sh, check-container.sh,
# check-image.sh) so that every mode reaches the same verdict from the same
# evidence. POSIX sh only.

J4S_FALLBACK_VERSION="1.0.0"

# j4s_tool_version <tool dir>
j4s_tool_version() {
  if [ -r "$1/VERSION" ]; then
    head -n 1 "$1/VERSION"
  else
    printf '%s\n' "$J4S_FALLBACK_VERSION"
  fi
}

# j4s_safe <text>  -> the text without control characters (tabs, newlines,
# escape sequences). Everything read from a target (versions, paths, env
# values, hostnames) goes through this before it is printed.
j4s_safe() {
  printf '%s' "$1" | LC_ALL=C tr -d '\000-\037\177'
}

# j4s_relevant_opts <text>  -> only the JVM options that matter for this CVE
# (so command lines and environments, which often hold secrets, are never
# printed in full).
j4s_relevant_opts() {
  printf '%s\n' "$1" | LC_ALL=C tr -d '\000-\010\013-\037\177' | tr ' \t' '\n\n' | grep -E \
    -- '^(-XX:[+-](UseBASE64Intrinsics|UseCompiler|TieredCompilation)|-XX:(UseAVX|TieredStopAtLevel|CompilationMode|VMOptionsFile|Flags)=.*|-Xint|-Xmixed|@.+)$' \
    | tr '\n' ' ' | sed 's/ $//'
}

# j4s_version_string <full `java -version` output>  -> the quoted version
j4s_version_string() {
  printf '%s\n' "$1" | grep -v 'Picked up ' | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n 1
}

# j4s_classify_version <version> <full `java -version` output, or the JDK's
# release file>
#
# Prints one of:
#   NOT_HOTSPOT           Eclipse OpenJ9 (IBM Semeru etc.): no HotSpot stub
#   NOT_AFFECTED_VERSION  predates the vulnerable code (<= 17.0.5, 8, 11, ...)
#   AFFECTED_VERSION      inside a published affected range
#   AFFECTED_EOL_VERSION  22-24, 26: EOL interim releases forked after 21.0.0
#                         (which contains the code); they never get the fix
#   UNCONFIRMED_VERSION   18-20: whether these contain the code is not
#                         confirmed by the advisories
#   FIXED_PATCH_ASSUMED   same update, patch level >= 1 (e.g. 21.0.13.1):
#                         the fixed-build numbering is ASSUMED, not confirmed
#   FIXED_VERSION         a later update release (e.g. 21.0.14): ships after
#                         the 2026-11-17 fix
#   NEWER_THAN_ADVISORY   GA feature release 28+ (ships after the fix)
#   EA_BUILD              early-access build: content depends on build date
#   UNKNOWN_VERSION       could not parse
#
# Affected ranges (OpenJDK/Oracle advisories, 2026-11-17):
#   17.0.6 .. 17.0.21, 21.0.0 .. 21.0.13, 25.0.0 .. 25.0.5, 27.0.0 .. 27.0.1,
#   Oracle's Java 8 performance build 8u511b33-perf. Standard 8 and 11 builds
#   do not contain the vulnerable code.
j4s_classify_version() {
  _v=$1
  # "Picked up JAVA_TOOL_OPTIONS: ..." lines echo user options (e.g. -ea,
  # -XX:-UsePerfData) and must not be mistaken for build information.
  _full=$(printf '%s\n' "$2" | grep -v 'Picked up ')
  case "$_full" in
    *OpenJ9*) echo "NOT_HOTSPOT"; return ;;
  esac
  if [ -z "$_v" ]; then
    echo "UNKNOWN_VERSION"
    return
  fi
  case "$_v" in
    *-ea*|*-internal*) echo "EA_BUILD"; return ;;
  esac
  if printf '%s\n' "$_full" | grep -qE -- '-ea([+ ."]|$)'; then
    echo "EA_BUILD"
    return
  fi
  _n=$(printf '%s' "$_v" | sed 's/[-+].*//')
  case "$_n" in
    1.8.*|8|8.*)
      # Only Oracle's performance build carries the vulnerable stub.
      if printf '%s\n' "$_v $_full" | grep -qiE -- '-perf([^a-z]|$)'; then
        echo "AFFECTED_VERSION"
      else
        echo "NOT_AFFECTED_VERSION"
      fi
      return
      ;;
  esac
  printf '%s\n' "$_n" | awk -F'.' '
    $1 !~ /^[0-9]+$/ { print "UNKNOWN_VERSION"; exit }
    {
      major = ($1 == "1") ? $2 + 0 : $1 + 0
      u = $3 + 0
      p = $4 + 0
      if (major <= 16) { print "NOT_AFFECTED_VERSION"; exit }
      if (major >= 28) { print "NEWER_THAN_ADVISORY";  exit }
      if (major == 17) { last = 21; first = 6 }
      else if (major == 21) { last = 13; first = 0 }
      else if (major == 25) { last = 5;  first = 0 }
      else if (major == 27) { last = 1;  first = 0 }
      else if (major >= 18 && major <= 20) { print "UNCONFIRMED_VERSION"; exit }
      else { print "AFFECTED_EOL_VERSION"; exit }
      if (u < first)              { print "NOT_AFFECTED_VERSION"; exit }
      if (u > last)               { print "FIXED_VERSION";        exit }
      if (u == last && p >= 1)    { print "FIXED_PATCH_ASSUMED";  exit }
      print "AFFECTED_VERSION"
    }'
}

# j4s_major <version>  -> feature release number (8 for 1.8.x)
j4s_major() {
  printf '%s\n' "$1" | sed 's/[-+].*//' | awk -F'.' '{ print ($1 == "1") ? $2 + 0 : $1 + 0 }'
}

# j4s_version_note <status> <version>  -> human note lines (may be empty)
j4s_version_note() {
  case "$1" in
    NOT_HOTSPOT)
      echo "  note: Eclipse OpenJ9 JVM - CVE-2026-114938 is in HotSpot's x86 stub; OpenJ9 does not contain it." ;;
    AFFECTED_EOL_VERSION)
      echo "  note: EOL interim release that contains the vulnerable code; it will never receive a fix. Upgrade to a fixed LTS." ;;
    UNCONFIRMED_VERSION)
      echo "  note: JDK 18-20: the advisories do not confirm whether these contain the vulnerable code. EOL either way - upgrade." ;;
    FIXED_PATCH_ASSUMED)
      echo "  note: fixed-build numbering (patch level >= 1 of the last affected update) is ASSUMED;"
      echo "  note: confirm against your vendor's advisory." ;;
    EA_BUILD)
      echo "  note: early-access build - may predate the fix; cannot be classified by version." ;;
  esac
  if [ "$(j4s_major "$2")" = "8" ]; then
    if [ "$1" = "AFFECTED_VERSION" ]; then
      echo "  note: Oracle Java 8 performance build detected - this build contains the vulnerable code."
    else
      echo "  note: standard Java 8 does not contain the vulnerable code (only Oracle's 8u511b33-perf build does)."
    fi
  fi
}

# j4s_flag_value <PrintFlagsFinal/VM.flags output> <flag name>
j4s_flag_value() {
  printf '%s\n' "$1" | awk -v n="$2" '$2==n {for (i=3;i<=NF;i++) if ($i=="=") {print $(i+1); exit}}'
}

# j4s_hw_eval "<present flags>"  -> sets HW / HW_DETAIL from the subset of
# {avx512f avx512bw avx512vbmi bmi2} that the CPU advertises.
j4s_hw_eval() {
  _miss=""
  for _f in avx512f avx512bw avx512vbmi bmi2; do
    case " $1 " in
      *" $_f "*) ;;
      *) _miss="$_miss $_f" ;;
    esac
  done
  if [ -z "$_miss" ]; then
    HW="HW_VULNERABLE"
    HW_DETAIL="present: $1"
  else
    HW="HW_SAFE"
    HW_DETAIL="present: ${1:-none} | missing:$_miss"
  fi
}

# j4s_cpu_eval <cpuinfo text> <arch from uname -m>  -> sets HW / HW_DETAIL
# The architecture is ground truth: the vulnerable code exists only in the
# x86-64 HotSpot build, so any non-x86-64 machine is HW_SAFE whatever
# /proc/cpuinfo claims. (J4S_TEST_ARCH overrides the arch for tests/run.sh
# only, to exercise the x86-64 path on other hardware.)
j4s_cpu_eval() {
  _arch=${J4S_TEST_ARCH:-$2}
  _line=$(printf '%s\n' "$1" | grep -m1 -E '^(flags|Features)')
  _present=""
  case "$_line" in
    flags*) _present=$(printf '%s\n' "$_line" | tr ' \t' '\n\n' | grep -E '^(avx512f|avx512bw|avx512vbmi|bmi2)$' | sort -u | tr '\n' ' ' | sed 's/ $//') ;;
  esac
  case "$_arch" in
    x86_64|amd64)
      if [ -n "$_line" ]; then
        j4s_hw_eval "$_present"
      else
        HW="HW_UNKNOWN"; HW_DETAIL="x86-64, but CPU flags not readable (Linux /proc/cpuinfo needed)"
      fi ;;
    aarch64|arm64|arm*)
      HW="HW_SAFE"; HW_DETAIL="$_arch CPU - the vulnerable x86-64 code path does not exist"
      [ -n "$_present" ] && HW_DETAIL="$HW_DETAIL (note: /proc/cpuinfo lists x86 flags, which an $_arch machine cannot have - ignored)" ;;
    "")
      case "$_line" in
        flags*) j4s_hw_eval "$_present" ;;
        Features*) HW="HW_SAFE"; HW_DETAIL="ARM CPU" ;;
        *) HW="HW_UNKNOWN"; HW_DETAIL="CPU not readable" ;;
      esac ;;
    *)
      HW="HW_SAFE"; HW_DETAIL="$_arch CPU - the vulnerable code is x86-64 only" ;;
  esac
}

# j4s_parse_flags <PrintFlagsFinal or `jcmd <pid> VM.flags -all` output>
# Sets FLAG_STATUS / FLAG_DETAIL:
#   FLAG_OFF         UseBASE64Intrinsics=false          (mitigated)
#   FLAG_AVX2        UseAVX <= 2                         (mitigated, x86 only)
#   FLAG_NOC2        C2 JIT disabled or capped below C2  (not a supported mitigation)
#   FLAG_ON          intrinsic enabled, AVX-512 allowed
#   FLAG_UNKNOWN     defaults (no UseAVX flag on ARM; no explicit flag on a process)
#   FLAG_UNREADABLE  the JVM printed no flags at all
j4s_parse_flags() {
  _pff=$1
  B64FLAG=$(j4s_flag_value "$_pff" UseBASE64Intrinsics)
  USEAVX=$(j4s_flag_value "$_pff" UseAVX)
  _usecomp=$(j4s_flag_value "$_pff" UseCompiler)
  _tiered=$(j4s_flag_value "$_pff" TieredCompilation)
  _stop=$(j4s_flag_value "$_pff" TieredStopAtLevel)
  _mode=$(j4s_flag_value "$_pff" CompilationMode)
  FLAG_STATUS="FLAG_UNKNOWN"
  FLAG_DETAIL="UseBASE64Intrinsics=${B64FLAG:-n/a} UseAVX=${USEAVX:-n/a}"
  if [ -z "$(printf '%s' "$_pff" | tr -d '[:space:]')" ]; then
    FLAG_STATUS="FLAG_UNREADABLE"
    FLAG_DETAIL="the JVM did not report its flags"
    return
  fi
  _noc2=""
  [ "$_usecomp" = "false" ] && _noc2="JIT disabled (UseCompiler=false, e.g. -Xint)"
  if [ -z "$_noc2" ] && [ "$_tiered" = "true" ] && [ -n "$_stop" ] && [ "$_stop" -lt 4 ] 2>/dev/null; then
    _noc2="C2 never runs (TieredStopAtLevel=$_stop)"
  fi
  [ -z "$_noc2" ] && [ "$_mode" = "quick-only" ] && _noc2="C2 never runs (CompilationMode=quick-only)"

  if [ "$B64FLAG" = "false" ]; then
    FLAG_STATUS="FLAG_OFF"
    FLAG_DETAIL="UseBASE64Intrinsics=false (mitigated)"
  elif [ -n "$USEAVX" ] && [ "$USEAVX" -le 2 ] 2>/dev/null; then
    FLAG_STATUS="FLAG_AVX2"
    FLAG_DETAIL="UseAVX=$USEAVX <= 2 (mitigated)"
  elif [ -n "$_noc2" ]; then
    FLAG_STATUS="FLAG_NOC2"
    FLAG_DETAIL="$_noc2"
  elif [ -n "$B64FLAG" ] && [ -n "$USEAVX" ]; then
    FLAG_STATUS="FLAG_ON"
  fi
}

# j4s_jdk_home_of <path of the mapped libjvm / libj9vm>  -> the JDK home
#   <home>/lib/server/libjvm.so           (JDK 9+)
#   <home>/jre/lib/<arch>/server/libjvm.so (JDK 8)
#   <home>/lib/j9vm/libjvm.so, <home>/lib/default/libj9vm29.so (OpenJ9)
j4s_jdk_home_of() {
  printf '%s\n' "$1" | sed -E 's#/(jre/)?lib(/[^/]+)?/[^/]+/lib(jvm|j9vm[0-9]*)\.so$##'
}

# j4s_inspect_pid <pid>
# Identifies the JVM running as <pid> WITHOUT executing anything: reads
# /proc/<pid>/maps (is it a JVM, where is its JDK, was the JDK replaced since
# it started) and the JDK's release file through /proc/<pid>/root (version,
# vendor, variant). Sets:
#   PID_IS_JVM (0/1), JHOME, VER, VENDOR, VSTAT, STALE (0/1), OPENJ9 (0/1)
# A replaced JDK (STALE=1) makes VSTAT=UNKNOWN_VERSION: the release file on
# disk then describes the new JDK, not the code this JVM runs.
j4s_inspect_pid() {
  _d="/proc/$1"
  PID_IS_JVM=0; JHOME=""; VER=""; VENDOR=""; VSTAT="UNKNOWN_VERSION"; STALE=0; OPENJ9=0
  [ -r "$_d/maps" ] || return 0
  _lib=$(grep -m1 -E '/lib(jvm|j9vm[0-9]*)\.so( \(deleted\))?$' "$_d/maps" 2>/dev/null) || return 0
  [ -n "$_lib" ] || return 0
  PID_IS_JVM=1
  case "$_lib" in *"(deleted)"*) STALE=1 ;; esac
  case "$(readlink "$_d/exe" 2>/dev/null)" in *" (deleted)") STALE=1 ;; esac
  grep -q 'libj9vm' "$_d/maps" 2>/dev/null && OPENJ9=1
  JHOME=$(j4s_jdk_home_of "$(printf '%s\n' "$_lib" | awk '{print $6}')")
  _rel=""
  for _c in "$_d/root$JHOME/release" "$_d/root$(dirname "$JHOME")/release"; do
    [ -r "$_c" ] && { _rel=$(head -c 65536 "$_c" 2>/dev/null); break; }
  done
  VER=$(printf '%s\n' "$_rel" | sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' | head -n 1)
  VENDOR=$(printf '%s\n' "$_rel" | sed -n 's/^IMPLEMENTOR="\(.*\)"$/\1/p' | head -n 1)
  _full=$_rel
  [ $OPENJ9 -eq 1 ] && _full="$_full
OpenJ9"
  case "$_rel" in *'JVM_VARIANT="Openj9"'*) _full="$_full
OpenJ9" ;; esac
  if [ $STALE -eq 1 ]; then
    VSTAT="UNKNOWN_VERSION"
  else
    VSTAT=$(j4s_classify_version "$VER" "$_full")
  fi
  JHOME=$(j4s_safe "$JHOME"); VER=$(j4s_safe "$VER"); VENDOR=$(j4s_safe "$VENDOR")
}

# --- j4s_proc_flags internals -------------------------------------------
# One launcher token at a time, tracking where the JVM options end.
_j4s_opt_token() {
  [ "$_pf_done" -eq 1 ] && return 0
  if [ "$_pf_skip" -eq 1 ]; then _pf_skip=0; return 0; fi
  case "$1" in
    -cp|-classpath|--class-path|-p|--module-path|--upgrade-module-path|--add-modules|--limit-modules|--add-exports|--add-opens|--add-reads|--patch-module|--source|--enable-native-access)
      _pf_skip=1 ;;
    -jar|-m|--module) _pf_done=1 ;;
    --module=*) _pf_done=1 ;;
    -XX:Flags=*) PROC_ARGFILE=1 ;;
    -*) _pf_jvm="$_pf_jvm
$1" ;;
    *) _pf_done=1 ;;   # main class or source file: application arguments follow
  esac
}
# Tokens of an option file or option variable: whitespace-separated, quotes
# removed, comment lines dropped.
_j4s_split() {
  printf '%s\n' "$1" | grep -v '^[[:space:]]*#' | tr ' \t\001' '\n\n\n' | sed -e "s/^[\"']//" -e "s/[\"']\$//" | grep -v '^$'
}

# j4s_proc_flags <pid> [<java major version>]
# Rebuilds a process's effective -XX values WITHOUT attaching to it, from the
# sources the JVM reads, in its precedence order (later wins):
#   JAVA_TOOL_OPTIONS < JDK_JAVA_OPTIONS (launcher, JDK 9+) < command line
#   < _JAVA_OPTIONS
# @argfiles and -XX:VMOptionsFile= are expanded in launcher order by reading
# them through /proc/<pid>/root and /proc/<pid>/cwd. Sets PROC_FLAGS
# (synthetic PrintFlagsFinal text for j4s_parse_flags), PROC_ARGFILE=1 when an
# option source could not be expanded (unreadable file, -XX:Flags=), and
# PROC_ENV_READABLE=0/1.
j4s_proc_flags() {
  _pid=$1
  _major=${2:-}
  PROC_ENV_READABLE=0
  PROC_ARGFILE=0
  _environ=""
  # NUL-separated entries; newlines inside values become \001 so that one
  # variable can never be read as another.
  if [ -r "/proc/$_pid/environ" ]; then
    _environ=$(tr '\n\000' '\001\n' < "/proc/$_pid/environ" 2>/dev/null) && PROC_ENV_READABLE=1
  fi
  _tokens=$(tr '\n\000' '\001\n' < "/proc/$_pid/cmdline" 2>/dev/null)

  _pf_jvm=""; _pf_skip=0; _pf_done=0
  _old_ifs=$IFS
  IFS='
'
  _first=1
  for _t in $_tokens; do
    if [ $_first -eq 1 ]; then _first=0; continue; fi   # argv[0]
    [ $_pf_done -eq 1 ] && break
    _f=""
    case "$_t" in
      @@*) _j4s_opt_token "${_t#@}"; continue ;;
      @*) [ $_pf_skip -eq 0 ] && _f=${_t#@} ;;
      -XX:VMOptionsFile=*) _f=${_t#-XX:VMOptionsFile=} ;;
    esac
    if [ -z "$_f" ]; then
      _j4s_opt_token "$_t"
      continue
    fi
    case "$_f" in
      /*) _p="/proc/$_pid/root$_f" ;;
      *)  _p="/proc/$_pid/cwd/$_f" ;;
    esac
    if [ -r "$_p" ]; then
      for _a in $(_j4s_split "$(head -c 1048576 "$_p" 2>/dev/null)"); do
        _j4s_opt_token "$_a"
      done
    else
      PROC_ARGFILE=1
    fi
  done
  IFS=$_old_ifs

  _env() { printf '%s\n' "$_environ" | sed -n "s/^$1=//p" | head -n 1; }
  _jdk_opts=""
  [ "$_major" != "8" ] && _jdk_opts=$(_env JDK_JAVA_OPTIONS)
  _all=$(printf '%s\n%s\n%s\n%s\n' \
    "$(_j4s_split "$(_env JAVA_TOOL_OPTIONS)")" \
    "$(_j4s_split "$_jdk_opts")" \
    "$_pf_jvm" \
    "$(_j4s_split "$(_env _JAVA_OPTIONS)")")
  printf '%s\n' "$_all" | grep -qE '^@|^-XX:(Flags|VMOptionsFile)=' && PROC_ARGFILE=1
  PROC_FLAGS=$(printf '%s\n' "$_all" | awk '
    /^-XX:\+UseBASE64Intrinsics$/ { b = "true" }
    /^-XX:-UseBASE64Intrinsics$/  { b = "false" }
    /^-XX:UseAVX=[0-9]+$/         { a = substr($0, 12) }
    /^-Xint$/                     { c = "false" }
    /^-Xmixed$/                   { c = "true" }
    /^-XX:-UseCompiler$/          { c = "false" }
    /^-XX:\+UseCompiler$/         { c = "true" }
    /^-XX:TieredStopAtLevel=[0-9]+$/ { s = substr($0, 23) }
    /^-XX:-TieredCompilation$/    { t = "false" }
    /^-XX:\+TieredCompilation$/   { t = "true" }
    /^-XX:CompilationMode=/       { m = substr($0, 21) }
    END {
      if (b != "") print "bool UseBASE64Intrinsics = " b
      if (a != "") print "intx UseAVX = " a
      if (c != "") print "bool UseCompiler = " c
      print "bool TieredCompilation = " (t != "" ? t : "true")
      if (s != "") print "intx TieredStopAtLevel = " s
      if (m != "") print "ccstr CompilationMode = " m
    }')
}

# j4s_jvm_start_failure <output of a failed java invocation>
# Explains why the JVM refused to start (most often: an x86-only option such
# as -XX:UseAVX pushed fleet-wide to an ARM host).
j4s_jvm_start_failure() {
  echo "ERROR: the JVM refuses to start in this environment:"
  printf '%s\n' "$1" | LC_ALL=C tr -d '\000-\010\013-\037\177' | sed 's/^/  /'
  case "$1" in
    *"Unrecognized VM option 'UseAVX"*)
      echo
      echo "  -XX:UseAVX is an x86-64-only option. This JVM is not x86-64 (e.g. ARM64), so"
      echo "  EVERY Java process started with these options fails the same way."
      echo "  Remove -XX:UseAVX from the environment on non-x86 hosts. ARM64 is not"
      echo "  affected by CVE-2026-114938; if you need one fleet-wide flag, use"
      echo "  -XX:-UseBASE64Intrinsics, which every HotSpot architecture accepts."
      ;;
    *"Unrecognized VM option"*|*"Could not create the Java Virtual Machine"*)
      echo
      echo "  A JVM option set in the environment (JAVA_TOOL_OPTIONS, _JAVA_OPTIONS,"
      echo "  JDK_JAVA_OPTIONS) is not accepted by this JVM. Every Java process started"
      echo "  with these options fails the same way. Fix the options, then re-run."
      ;;
  esac
}

# j4s_verdict  (reads VSTAT, HW, FLAG_STATUS, FLAG_DETAIL)
# Decides from version x CPU x effective flags, the three conditions the
# advisories give for exploitability. Sets VERDICT, EXIT_CODE
# (0 not vulnerable / not exploitable, 1 vulnerable, 3 uncertain) and
# VERDICT_NOTE.
j4s_verdict() {
  VERDICT="UNCERTAIN - could not determine vulnerability"
  EXIT_CODE=3
  VERDICT_NOTE=""

  case "$VSTAT" in
    AFFECTED_VERSION|AFFECTED_EOL_VERSION)
      _affected=1
      _portable_note="NOTE: this JDK build contains the vulnerable code. It IS exploitable on any host with AVX-512 VBMI (Intel Ice Lake or newer, AMD Zen 4 or newer) - check every host/node it runs on, and patch it." ;;
    *) _affected=0; _portable_note="" ;;
  esac

  # 1. Builds that do not contain the vulnerable code.
  case "$VSTAT" in
    NOT_HOTSPOT)
      VERDICT="NOT VULNERABLE - Eclipse OpenJ9 JVM; the vulnerable code exists only in HotSpot"
      EXIT_CODE=0; return ;;
    NOT_AFFECTED_VERSION)
      VERDICT="NOT VULNERABLE - this version does not contain the vulnerable code"
      EXIT_CODE=0; return ;;
    FIXED_VERSION|NEWER_THAN_ADVISORY)
      VERDICT="NOT VULNERABLE - update released after the 2026-11-17 fix"
      EXIT_CODE=0; return ;;
  esac

  # 2. The CPU cannot run the vulnerable code path.
  if [ "$HW" = "HW_SAFE" ]; then
    VERDICT="NOT VULNERABLE ON THIS HOST - CPU cannot reach the vulnerable code path (no AVX-512 VBMI)"
    EXIT_CODE=0
    VERDICT_NOTE=$_portable_note
    return
  fi

  # 3. The intrinsic is switched off.
  if [ "$FLAG_STATUS" = "FLAG_OFF" ] || [ "$FLAG_STATUS" = "FLAG_AVX2" ]; then
    VERDICT="NOT EXPLOITABLE AS CONFIGURED - $FLAG_DETAIL (patch anyway)"
    EXIT_CODE=0
    return
  fi

  case "$VSTAT" in
    FIXED_PATCH_ASSUMED)
      VERDICT="PROBABLY FIXED - patch-level build of the last affected update; the fixed build numbers are not confirmed yet. Confirm with your vendor's advisory"
      EXIT_CODE=3; return ;;
    UNCONFIRMED_VERSION|EA_BUILD|UNKNOWN_VERSION)
      VERDICT="UNCERTAIN - $VSTAT cannot be classified by version (hardware: $HW). Upgrade to a fixed release"
      EXIT_CODE=3; return ;;
  esac

  # Affected version from here on.
  if [ "$FLAG_STATUS" = "FLAG_UNREADABLE" ] && [ "$HW" = "HW_VULNERABLE" ]; then
    VERDICT="UNCERTAIN - affected JDK on an AVX-512 VBMI CPU, but the JVM's flags could not be read. Check them with: java -XX:+PrintFlagsFinal -version"
    EXIT_CODE=3
    return
  fi
  if [ "$FLAG_STATUS" = "FLAG_NOC2" ]; then
    VERDICT="UNCERTAIN - affected version; $FLAG_DETAIL, which is not a supported mitigation. Patch, or set -XX:-UseBASE64Intrinsics"
    EXIT_CODE=3
    return
  fi
  if [ "$_affected" -eq 1 ] && [ "$HW" = "HW_VULNERABLE" ]; then
    VERDICT="VULNERABLE - affected JDK ($VSTAT) on an AVX-512 VBMI CPU with the Base64 intrinsic enabled. Patch, or set -XX:-UseBASE64Intrinsics and restart"
    EXIT_CODE=1
    return
  fi
  if [ "$_affected" -eq 1 ]; then
    VERDICT="UNCERTAIN - affected JDK; CPU capability could not be determined ($HW)"
    EXIT_CODE=3
    VERDICT_NOTE=$_portable_note
  fi
}

# j4s_class  (reads VERDICT) -> prints the report class for it
j4s_class() {
  case "$VERDICT" in
    "NOT EXPLOITABLE AS CONFIGURED"*) echo "MITIGATED" ;;
    "NOT VULNERABLE"*)                echo "NOT_VULNERABLE" ;;
    "VULNERABLE"*)                    echo "VULNERABLE" ;;
    "PROBABLY FIXED"*)                echo "PROBABLY_FIXED" ;;
    "RESTART REQUIRED"*)              echo "RESTART_REQUIRED" ;;
    *)                                echo "UNCERTAIN" ;;
  esac
}

# j4s_result_line <mode> <target>  (reads JAVA_BIN, JAVA_VERSION, VSTAT, HW,
# FLAG_STATUS, VERDICT, EXIT_CODE) -> one tab-separated machine line, parsed
# by report.sh:
#   J4S_RESULT mode= target= jdk= version= vstat= hw= flags= class= exit=
j4s_result_line() {
  printf 'J4S_RESULT\tmode=%s\ttarget=%s\tjdk=%s\tversion=%s\tvstat=%s\thw=%s\tflags=%s\tclass=%s\texit=%s\n' \
    "$(j4s_safe "$1")" "$(j4s_safe "$2")" "$(j4s_safe "${JAVA_BIN:--}")" "$(j4s_safe "${JAVA_VERSION:--}")" \
    "${VSTAT:--}" "${HW:--}" "${FLAG_STATUS:--}" "$(j4s_class)" "${EXIT_CODE:-3}"
}

# j4s_print_verdict  -> prints VERDICT (and its note)
j4s_print_verdict() {
  printf 'VERDICT: %s\n' "$VERDICT"
  [ -n "$VERDICT_NOTE" ] && printf '%s\n' "$VERDICT_NOTE"
  return 0
}
