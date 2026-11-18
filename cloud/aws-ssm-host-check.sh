#!/bin/sh
# java4shell-check Tier 1: per-node JVM inventory over AWS SSM Run Command.
#
# Runs check-host.sh --machine on EC2 instances (EKS nodes included) and
# aggregates the results: every running JVM on every node - in containers
# too - with its JDK version, effective flags, restart state and class.
#
# What runs on each instance: check-host.sh, gzip+base64 inline, piped into
# `sh` (no file is written). Review it first with --emit-payload. It only READS /proc - it starts no JVM, attaches to no JVM and
# changes nothing. Typical runtime: < 2 s per node.
#
# DRY RUN BY DEFAULT: without --run it only prints the target list and the
# exact command it would send. Nothing is sent.
#
# Usage:
#   ./aws-ssm-host-check.sh --region <r> [--profile <p>]
#        [--targets i-a,i-b,...]   default: the aws-sweep.sh candidates
#                                  (avx512vbmi-yes + unknown) that are
#                                  SSM-online Linux instances
#        [--run]                   actually send the command
#        [--concurrency 10]        SSM MaxConcurrency (default 10)
#        [--out <file.tsv>]        also write the per-JVM rows to a file
#        [--emit-payload <file>]   write the exact script that would run on
#                                  each instance, then exit (no AWS calls) -
#                                  review it before using --run
#
# Requires: ssm:SendCommand (AWS-RunShellScript), ssm:ListCommandInvocations,
# ssm:DescribeInstanceInformation, ec2:DescribeInstances.
#
# Exit codes: 0 no JVM at risk, 1 at least one VULNERABLE JVM,
#             3 restart-required / uncertain JVMs or nodes without a result,
#             2 error.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOL_DIR=$(dirname "$SCRIPT_DIR")
J4S_VERSION=$(head -n 1 "$TOOL_DIR/VERSION" 2>/dev/null || echo unknown)

REGION=""
PROFILE_OPT=""
TARGETS=""
RUN=0
CONC=10
OUT=""
EMIT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --region)      [ $# -ge 2 ] || { echo "--region needs a value"; exit 2; }; REGION=$2; shift 2 ;;
    --profile)     [ $# -ge 2 ] || { echo "--profile needs a value"; exit 2; }; PROFILE_OPT="--profile $2"; shift 2 ;;
    --targets)     [ $# -ge 2 ] || { echo "--targets needs a value"; exit 2; }; TARGETS=$(printf '%s' "$2" | tr ',' ' '); shift 2 ;;
    --run)         RUN=1; shift ;;
    --concurrency) [ $# -ge 2 ] || { echo "--concurrency needs a value"; exit 2; }; CONC=$2; shift 2 ;;
    --out)         [ $# -ge 2 ] || { echo "--out needs a value"; exit 2; }; OUT=$2; shift 2 ;;
    --emit-payload) [ $# -ge 2 ] || { echo "--emit-payload needs a value"; exit 2; }; EMIT=$2; shift 2 ;;
    -h|--help)     sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)"; exit 2 ;;
  esac
done
build_payload() { # $1 = output file. Self-contained: shared lib + check-host.sh
  {
    echo "#!/bin/sh"
    echo "# java4shell-check $J4S_VERSION host inventory payload (lib/j4s-common.sh + check-host.sh)"
    echo "TOOL_DIR=/nonexistent"
    sed -e '/^#/d' -e "s/^J4S_FALLBACK_VERSION=.*/J4S_FALLBACK_VERSION=\"$J4S_VERSION\"/" "$TOOL_DIR/lib/j4s-common.sh"
    sed -e '1,/^TOOL_DIR=/d' -e '/^\. "\$TOOL_DIR\/lib\/j4s-common.sh"/d' -e '/^# shellcheck source=/d' "$TOOL_DIR/check-host.sh"
  } > "$1"
  sh -n "$1" || { echo "ERROR: payload failed a syntax check"; exit 2; }
}
if [ -n "$EMIT" ]; then
  build_payload "$EMIT"
  echo "payload written to $EMIT ($(wc -c < "$EMIT" | tr -d ' ') bytes). Run on a node as: sudo sh $EMIT --machine"
  exit 0
fi

[ -n "$REGION" ] || { echo "ERROR: --region is required"; exit 2; }
command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found"; exit 2; }
AWSR="aws $PROFILE_OPT --region $REGION"

echo "java4shell-check Tier 1 (SSM host inventory) for CVE-2026-114938"
echo "================================================================="
echo "version: $J4S_VERSION   region: $REGION   mode: $( [ $RUN -eq 1 ] && echo RUN || echo 'DRY RUN (add --run to send)')"
echo

# ------------------------------------------------------------ targets
TMPD=$(mktemp -d 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
trap 'rm -rf "$TMPD"' EXIT
trap 'rm -rf "$TMPD"; exit 130' INT TERM

# The aws call's own exit status is checked (a failure here, e.g. bad
# credentials, must be an error, not "every instance unreachable").
# shellcheck disable=SC2086
if ! $AWSR ssm describe-instance-information \
  --query 'InstanceInformationList[?PingStatus==`Online` && PlatformType==`Linux`].InstanceId' \
  --output text > "$TMPD/online.raw" 2>"$TMPD/err"; then
  echo "ERROR: ssm describe-instance-information failed (credentials / permissions?):"
  sed 's/^/  /' "$TMPD/err"
  exit 2
fi
tr '\t' '\n' < "$TMPD/online.raw" | grep '^i-' | sort -u > "$TMPD/online"

if [ -z "$TARGETS" ]; then
  # shellcheck disable=SC2086
  "$SCRIPT_DIR/aws-sweep.sh" $PROFILE_OPT --region "$REGION" --skip-eks > "$TMPD/sweep" 2>&1
  SWEEP_RC=$?
  if [ $SWEEP_RC -ne 0 ]; then
    echo "ERROR: the CPU sweep failed (exit $SWEEP_RC), so no candidates could be selected:"
    tail -n 5 "$TMPD/sweep" | sed 's/^/  /'
    exit 2
  fi
  awk -F'\t' '$1 ~ /^i-/ && ($4 == "avx512vbmi-yes" || $4 == "unknown") {print $1}' "$TMPD/sweep" | sort -u > "$TMPD/cand"
  echo "candidates from the CPU sweep (avx512vbmi-yes + unknown): $(wc -l < "$TMPD/cand" | tr -d ' ')"
else
  printf '%s\n' $TARGETS | grep '^i-' | sort -u > "$TMPD/cand"
  echo "targets given: $(wc -l < "$TMPD/cand" | tr -d ' ')"
fi
comm -12 "$TMPD/cand" "$TMPD/online" > "$TMPD/targets"
comm -23 "$TMPD/cand" "$TMPD/online" > "$TMPD/unreachable"
NT=$(wc -l < "$TMPD/targets" | tr -d ' ')
NU=$(wc -l < "$TMPD/unreachable" | tr -d ' ')
echo "reachable via SSM (online, Linux): $NT"
[ "$NU" -gt 0 ] && echo "NOT reachable via SSM (check these another way): $NU -> $(tr '\n' ' ' < "$TMPD/unreachable")"
if [ "$NT" -eq 0 ]; then
  echo "nothing to send."
  # Unreachable candidates are unchecked, not safe.
  [ "$NU" -gt 0 ] && exit 3
  exit 0
fi

build_payload "$TMPD/payload.sh"
B64=$(gzip -9c < "$TMPD/payload.sh" | base64 | tr -d '\n')
# Decompressor fallbacks: gunzip -> python3 -> zcat -> busybox. If none
# exists the node reports J4S_NORESULT with a reason instead of failing silently.
UNZ='if command -v gunzip >/dev/null 2>&1; then Z=gunzip; elif command -v python3 >/dev/null 2>&1; then Z=py; elif command -v zcat >/dev/null 2>&1; then Z=zcat; elif command -v busybox >/dev/null 2>&1; then Z=bb; else printf "J4S_HOST\\terror=no-decompressor\\n"; exit 0; fi; unz() { case $Z in gunzip) gunzip -c ;; zcat) zcat ;; bb) busybox gunzip -c ;; py) python3 -c "import sys,gzip;sys.stdout.buffer.write(gzip.decompress(sys.stdin.buffer.read()))" ;; esac; }'
CMD="$UNZ; echo $B64 | base64 -d | unz | sh -s -- --machine; echo J4S_EXIT=\$?"
echo "payload: check-host.sh $J4S_VERSION ($(wc -c < "$TMPD/payload.sh" | tr -d ' ') bytes, sha256 $( (sha256sum 2>/dev/null || shasum -a 256) < "$TMPD/payload.sh" | cut -c1-16)...)"
echo "command on each instance: echo <payload gzip+base64, $(printf '%s' "$B64" | wc -c | tr -d ' ') chars> | base64 -d | <gunzip|python3|zcat> | sh -s -- --machine"
echo

if [ $RUN -eq 0 ]; then
  echo "targets:"
  sed 's/^/  /' "$TMPD/targets"
  echo
  echo "DRY RUN - nothing sent. Re-run with --run to execute on the $NT instance(s) above."
  exit 0
fi

# ------------------------------------------------------------ send
# JSON-encode the command (it contains double quotes).
if command -v python3 >/dev/null 2>&1; then
  CMD="$CMD" python3 -I -c 'import json,os;print(json.dumps({"commands":[os.environ["CMD"]]}))' > "$TMPD/params.json"
else
  printf '{"commands":["%s"]}' "$(printf '%s' "$CMD" | sed 's/\\/\\\\/g; s/"/\\"/g')" > "$TMPD/params.json"
fi
# send-command accepts at most 50 instance ids per call: batch.
split -l 50 "$TMPD/targets" "$TMPD/batch."
: > "$TMPD/cmdids"
for b in "$TMPD"/batch.*; do
  # shellcheck disable=SC2086,SC2046
  CMD_ID=$($AWSR ssm send-command --document-name AWS-RunShellScript \
    --instance-ids $(tr '\n' ' ' < "$b") \
    --parameters "file://$TMPD/params.json" \
    --comment "java4shell-check $J4S_VERSION host inventory (read-only)" \
    --timeout-seconds 120 --max-concurrency "$CONC" --max-errors 100% \
    --query 'Command.CommandId' --output text 2>"$TMPD/err") \
    || { echo "ERROR: send-command failed:"; cat "$TMPD/err"; exit 2; }
  echo "sent: command id $CMD_ID ($(wc -l < "$b" | tr -d ' ') instances)"
  echo "$CMD_ID" >> "$TMPD/cmdids"
  sed "s/^/$CMD_ID /" "$b" >> "$TMPD/pairs"
done

# wait for every batch (max ~10 min). The CLI paginates list-command-invocations
# (a JMESPath query then runs per page), so count the pending instance ids
# rather than asking for a length. A failed call counts as "still pending".
POLL=${J4S_SSM_POLL_SECONDS:-5}
i=0
while [ $i -lt 120 ]; do
  PENDING=0
  while read -r cid; do
    # shellcheck disable=SC2086
    if ids=$($AWSR ssm list-command-invocations --command-id "$cid" \
        --query 'CommandInvocations[?Status==`Pending` || Status==`InProgress` || Status==`Delayed`].InstanceId' \
        --output text 2>/dev/null); then
      n=$(printf '%s\n' "$ids" | tr '\t' '\n' | grep -c '^i-')
    else
      n=1
    fi
    PENDING=$((PENDING + n))
  done < "$TMPD/cmdids"
  [ "$PENDING" -eq 0 ] && break
  i=$((i + 1)); sleep "$POLL"
done
[ "$PENDING" -eq 0 ] || echo "WARNING: $PENDING invocation(s) still pending after the wait; collecting what is available."

# ------------------------------------------------------------ collect
# Per instance with get-command-invocation: its StandardOutputContent holds up
# to 24,000 characters (list-command-invocations --details truncates at
# 2,500, which would silently drop JVMs on busy nodes). A node whose output
# lacks the final J4S_HOST line is reported as incomplete, never as covered.
mkdir -p "$TMPD/out"
while read -r cid iid; do
  # shellcheck disable=SC2086
  $AWSR ssm get-command-invocation --command-id "$cid" --instance-id "$iid" \
    --query '[Status,StandardOutputContent]' --output json > "$TMPD/out/$iid.json" 2>/dev/null \
    || printf '["NoInvocation", ""]\n' > "$TMPD/out/$iid.json"
done < "$TMPD/pairs"

# Flatten: one row per JVM, prefixed with the instance id. Uses python3 if
# present (robust JSON), else jq.
if command -v python3 >/dev/null 2>&1; then
  python3 -I -c '
import json, os, sys
d = sys.argv[1]
for name in sorted(os.listdir(d)):
    iid = name[:-5]
    try:
        status, out = json.load(open(os.path.join(d, name)))
    except Exception:
        status, out = "Unreadable", ""
    lines = (out or "").splitlines()
    # A truncated last row has no class= field: drop it.
    rows = [l for l in lines if l.startswith("J4S_HOST\t")
            or (l.startswith("J4S_JVM\t") and "\tclass=" in l)]
    for l in rows:
        print(iid + "\t" + l)
    if not any(l.startswith("J4S_HOST\t") for l in rows):
        why = "incomplete-output" if rows else "no-output"
        print(iid + "\tJ4S_NORESULT\tstatus=" + str(status) + "/" + why)
' "$TMPD/out" > "$TMPD/rows"
elif command -v jq >/dev/null 2>&1; then
  for f in "$TMPD"/out/*.json; do
    iid=$(basename "$f" .json)
    jq -r --arg i "$iid" '. as [$s, $o]
      | (($o // "") | split("\n") | map(select(startswith("J4S_HOST\t") or (startswith("J4S_JVM\t") and contains("\tclass="))))) as $r
      | ($r[] | "\($i)\t\(.)"),
        (if ($r | map(select(startswith("J4S_HOST\t"))) | length) == 0
         then "\($i)\tJ4S_NORESULT\tstatus=\($s)/\(if ($r|length)>0 then "incomplete-output" else "no-output" end)"
         else empty end)' "$f"
  done > "$TMPD/rows"
else
  echo "ERROR: need python3 or jq to parse results"; exit 2
fi
# Candidates SSM could not reach are unchecked: keep them in the results.
awk 'NF { print $0 "\tJ4S_NORESULT\tstatus=not-reachable-via-SSM" }' "$TMPD/unreachable" >> "$TMPD/rows"
[ -n "$OUT" ] && cp "$TMPD/rows" "$OUT" && echo "per-JVM rows written to: $OUT"

echo
echo "== results =="
awk -F'\t' '
  $2=="J4S_HOST" && $0 ~ /error=/ { nerr++; next }
  $2=="J4S_HOST"     { nodes++; for(i=3;i<=NF;i++){split($i,kv,"="); if(kv[1]=="jvms") jv+=kv[2]} }
  $2=="J4S_NORESULT" { nores++ }
  $2=="J4S_JVM"      { for(i=3;i<=NF;i++){split($i,kv,"="); f[kv[1]]=kv[2]} cls[f["class"]]++ }
  END {
    printf "nodes with a result: %d   nodes with an error: %d   nodes without output: %d   JVMs found: %d\n", nodes, nerr, nores, jv
    for (c in cls) printf "  %-17s %d\n", c, cls[c]
  }' "$TMPD/rows"
echo
echo "VULNERABLE / RESTART_REQUIRED / UNCERTAIN JVMs (instance, container, JDK, version, flags, class):"
awk -F'\t' '$2=="J4S_JVM" {
    for(i=3;i<=NF;i++){split($i,kv,"="); f[kv[1]]=kv[2]}
    if (f["class"]=="VULNERABLE" || f["class"]=="RESTART_REQUIRED" || f["class"]=="UNCERTAIN")
      printf "  %s  %s  %s %s  %s  %s  %s\n", $1, (f["name"]!="-" && f["name"]!="" ? f["name"] : f["ctr"]), f["vendor"], f["jdk"], f["version"], f["flags"], f["class"]
  }' "$TMPD/rows" | sort -k7,7 -k1,1
grep -qE 'J4S_NORESULT|J4S_HOST.*error=' "$TMPD/rows" && { echo; echo "nodes without a usable result (check these another way):"; awk -F'\t' '$2=="J4S_NORESULT" || ($2=="J4S_HOST" && $0 ~ /error=/) {print "  " $1 "  " $3}' "$TMPD/rows"; }

if awk -F'\t' '$2=="J4S_JVM" && $0 ~ /class=VULNERABLE/ {f=1} END{exit !f}' "$TMPD/rows"; then exit 1; fi
if grep -qE 'class=(RESTART_REQUIRED|UNCERTAIN|PROBABLY_FIXED)|J4S_NORESULT|J4S_HOST.*error=' "$TMPD/rows"; then exit 3; fi
[ "$NU" -gt 0 ] && exit 3
exit 0
