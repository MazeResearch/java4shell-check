#!/bin/sh
# java4shell-check: turn collected results into one Markdown report.
#
# usage: ./report.sh [files...] > report.md      (or pipe results on stdin)
#
# Input: any mix of output from check.sh, check-port.sh, check-image.sh,
# check-container.sh (their J4S_RESULT lines) and check-host.sh (J4S_JVM /
# J4S_HOST lines), and cloud/aws-ssm-host-check.sh --out files (the same
# lines prefixed with an instance id, plus J4S_NORESULT rows for instances
# that could not be checked). Other lines are ignored, so whole terminal logs
# can be fed in; a leading location prefix is kept in the "Where" column.
# Duplicate targets keep the last result.
# A container's "JDK + env" row is dropped when its running JVMs were checked
# (so each container counts once, by its real JVMs). The same JVM checked by
# two methods (a node inventory and a container check) appears twice: use one
# method per machine.
#
# --template  also emit Scope / Not checked / Recommended actions sections
#             with placeholders, for the person or agent writing the report.

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TEMPLATE=0
[ "${1:-}" = "--template" ] && { TEMPLATE=1; shift; }
J4S_VERSION=$(head -n 1 "$TOOL_DIR/VERSION" 2>/dev/null || echo unknown)
NOW=$(date -u '+%Y-%m-%d %H:%M UTC')

cat "$@" | tr -d '\r' | awk -F'\t' -v toolver="$J4S_VERSION" -v now="$NOW" -v template="$TEMPLATE" '
# Fields can come from inside containers (paths, versions, hostnames): strip
# control characters and neutralise Markdown/HTML before printing.
function esc(x) {
  gsub(/[[:cntrl:]]/, "", x)
  gsub(/\|/, "/", x); gsub(/</, "(", x); gsub(/>/, ")", x)
  gsub(/\[/, "(", x); gsub(/\]/, ")", x); gsub(/`/, "\047", x)
  return x
}
function kv(start,   i, a) {
  delete F
  for (i = start; i <= NF; i++) { split($i, a, "="); F[a[1]] = substr($i, length(a[1]) + 2) }
}
function reason(c, vs, hw, fl) {
  if (c == "MITIGATED") return "flags: " fl
  if (vs == "NOT_HOTSPOT") return "Eclipse OpenJ9 (not HotSpot)"
  if (vs == "NOT_AFFECTED_VERSION") return "version predates the vulnerable code"
  if (vs == "FIXED_VERSION" || vs == "NEWER_THAN_ADVISORY") return "fixed release"
  if (hw == "HW_SAFE") return "CPU has no AVX-512 VBMI (this host only)"
  return "-"
}
function confirm(c, vs, hw, fl) {
  if (c == "PROBABLY_FIXED") return "confirm the build against the vendor advisory"
  if (vs == "UNCONFIRMED_VERSION") return "JDK 18-20: upgrade to a fixed LTS"
  if (vs == "EA_BUILD") return "early-access build: upgrade to a GA fixed release"
  if (vs == "UNKNOWN_VERSION") return "identify the JDK version"
  if (hw == "HW_UNKNOWN" || hw == "EMULATED") return "check on a host of the production CPU"
  if (fl ~ /NOC2/) return "JIT limited by flags: patch or set -XX:-UseBASE64Intrinsics"
  if (fl ~ /UNREADABLE/) return "read flags: java -XX:+PrintFlagsFinal -version"
  return "see the tool output for this target"
}
{
  # find the J4S_ field; anything before it is a location prefix
  k = 0
  for (i = 1; i <= NF; i++) if ($i ~ /^J4S_(RESULT|JVM|HOST|NORESULT)$/) { k = i; break }
  if (!k) next
  pre = ""
  for (i = 1; i < k; i++) pre = pre (pre == "" ? "" : " ") $i
  type = $k
  kv(k + 1)
  # A machine the fleet runner could not reach, or whose output was incomplete.
  if (type == "J4S_NORESULT") { ek = (pre != "" ? pre : "(unknown)"); if (!(ek in err)) eord[++ne] = ek; err[ek] = F["status"]; next }
  if (type == "J4S_HOST") {
    if ("error" in F) { ek = (pre != "" ? pre : "(host)"); if (!(ek in err)) eord[++ne] = ek; err[ek] = "error: " F["error"]; next }
    h = (pre != "" ? pre " " : "") F["host"]
    hosts[h] = F["hw"]
    next
  }
  if (type == "J4S_JVM") {
    who = (F["ctr"] != "-" ? "container " ((("name" in F) && F["name"] != "-") ? F["name"] : F["ctr"]) : "host process")
    key = (pre != "" ? pre " / " : "") F["host"] " / " who " / pid " F["pid"]
    jdk = F["vendor"]; gsub(/_/, " ", jdk); jdk = jdk " " F["jdk"]
    vs = F["vstat"]; hw = F["hw"]; fl = F["flags"]; ver = F["version"]
  } else {
    key = (pre != "" ? pre " / " : "") F["mode"] ": " F["target"]
    jdk = ("jdk" in F ? F["jdk"] : "-"); vs = F["vstat"]; hw = F["hw"]; fl = F["flags"]; ver = F["version"]
    if (F["mode"] == "container") { cn = F["target"]; sub(/ \(JDK \+ env\)$/, "", cn); envof[key] = (pre != "" ? pre " / " : "") cn }
    if (F["mode"] == "container-jvm") { cn = F["target"]; sub(/ pid [0-9]+$/, "", cn); hasjvm[(pre != "" ? pre " / " : "") cn] = 1 }
  }
  if (!(key in cls)) order[++n] = key
  cls[key] = F["class"]; V[key] = ver; VS[key] = vs; HWK[key] = hw; FL[key] = fl; JDK[key] = jdk
}
END {
  # drop container env rows whose JVMs were checked individually
  m = 0
  for (i = 1; i <= n; i++) { k = order[i]; if ((k in envof) && (envof[k] in hasjvm)) continue; keep[++m] = k }
  n = m; for (i = 1; i <= n; i++) order[i] = keep[i]
  for (i = 1; i <= n; i++) count[cls[order[i]]]++
  print "# Java4Shell (CVE-2026-114938) exposure report"
  print ""
  print "Generated " now " with java4shell-check " toolver ". Verdicts come from JDK version x CPU (AVX-512 VBMI) x effective JVM flags, read-only."
  if (template) {
    print ""
    print "## Scope"
    print ""
    print "_What was checked: machines, accounts, regions, clusters, images, and when._"
    print ""
    print "## Not checked, and why"
    print ""
    print "_No access, declined by the user, managed services, unsupported OS, nodes without a result (see the end of this report)._"
    print ""
    print "## Recommended actions, in order"
    print ""
    print "_1. VULNERABLE: upgrade to the vendor fixed build and restart; until then -XX:-UseBASE64Intrinsics + restart. 2. RESTART_REQUIRED: restart. 3. PROBABLY_FIXED: confirm the build with the vendor. 4. MITIGATED: still patch. 5. Include client machines (build agents, workers, CLI tools)._"
  }
  print ""
  print "## Summary"
  print ""
  print "| Class | JVMs / targets | Meaning |"
  print "|---|---|---|"
  split("VULNERABLE RESTART_REQUIRED UNCERTAIN PROBABLY_FIXED MITIGATED NOT_VULNERABLE", C, " ")
  M["VULNERABLE"] = "Affected JDK on an AVX-512 VBMI CPU with the intrinsic enabled. **Act now.**"
  M["RESTART_REQUIRED"] = "JDK replaced on disk; the running JVM still has the old code"
  M["UNCERTAIN"] = "Could not be decided; see what to confirm"
  M["PROBABLY_FIXED"] = "Patch-level build of the last affected update; confirm with the vendor"
  M["MITIGATED"] = "Affected JDK, intrinsic disabled by flags. Patch anyway"
  M["NOT_VULNERABLE"] = "Code absent, fixed, or CPU cannot run it"
  for (i = 1; i <= 6; i++) printf "| %s | %d | %s |\n", C[i], count[C[i]] + 0, M[C[i]]
  nh = 0; for (h in hosts) { nh++; hc[hosts[h]]++ }
  print ""
  printf "Nodes inventoried: %d (AVX-512 VBMI: %d, no VBMI / ARM: %d, unknown: %d). Targets without a result: %d.\n", nh, hc["HW_VULNERABLE"] + 0, hc["HW_SAFE"] + 0, hc["HW_UNKNOWN"] + 0, ne
  if (count["VULNERABLE"] > 0) {
    print ""
    print "## Vulnerable: act now"
    print ""
    print "| Where | JDK | Version | Flags |"
    print "|---|---|---|---|"
    for (i = 1; i <= n; i++) { k = order[i]; if (cls[k] == "VULNERABLE") printf "| %s | %s | %s (%s) | %s |\n", esc(k), esc(JDK[k]), esc(V[k]), esc(VS[k]), esc(FL[k]) }
    print ""
    print "Fix: upgrade to the fixed build named in your JDK vendor advisory and restart. Until then: add `-XX:-UseBASE64Intrinsics` (e.g. via `JAVA_TOOL_OPTIONS`), restart, and re-check the running process. Do not use `-XX:UseAVX=2` on ARM hosts: the JVM will not start."
  }
  if (count["RESTART_REQUIRED"] > 0) {
    print ""
    print "## Restart required"
    print ""
    print "| Where | Version on disk | Flags |"
    print "|---|---|---|"
    for (i = 1; i <= n; i++) { k = order[i]; if (cls[k] == "RESTART_REQUIRED") printf "| %s | %s | %s |\n", esc(k), esc(V[k]), esc(FL[k]) }
  }
  if (count["UNCERTAIN"] + count["PROBABLY_FIXED"] > 0) {
    print ""
    print "## Needs confirmation"
    print ""
    print "| Where | Version | CPU | Flags | Class | To confirm |"
    print "|---|---|---|---|---|---|"
    for (i = 1; i <= n; i++) { k = order[i]; if (cls[k] == "UNCERTAIN" || cls[k] == "PROBABLY_FIXED") printf "| %s | %s (%s) | %s | %s | %s | %s |\n", esc(k), esc(V[k]), esc(VS[k]), esc(HWK[k]), esc(FL[k]), esc(cls[k]), confirm(cls[k], VS[k], HWK[k], FL[k]) }
  }
  if (count["MITIGATED"] + count["NOT_VULNERABLE"] > 0) {
    print ""
    print "## Not exploitable"
    print ""
    print "| Where | Version | Class | Reason |"
    print "|---|---|---|---|"
    cpunote = 0
    for (i = 1; i <= n; i++) { k = order[i]; if (cls[k] == "MITIGATED" || cls[k] == "NOT_VULNERABLE") { r = reason(cls[k], VS[k], HWK[k], FL[k]); if (r ~ /^CPU/) cpunote = 1; printf "| %s | %s (%s) | %s | %s |\n", esc(k), esc(V[k]), esc(VS[k]), esc(cls[k]), esc(r) } }
    if (cpunote) {
      print ""
      print "\"CPU has no AVX-512 VBMI\" holds for that host only: the same JDK on an Ice Lake / Zen 4 or newer host is exploitable."
    }
  }
  if (ne > 0) {
    print ""
    print "## No result"
    print ""
    print "| Target | Status |"
    print "|---|---|"
    for (i = 1; i <= ne; i++) printf "| %s | %s |\n", esc(eord[i]), esc(err[eord[i]])
  }
  if (n == 0 && ne == 0) { print ""; print "No java4shell-check results found in the input." }
}'
