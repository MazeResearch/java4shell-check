#!/bin/sh
# java4shell-check cloud sweep (Tier 0): API-only, read-only, agentless.
#
# Enumerates EC2 instances and EKS node groups and classifies each by
# hardware capability for CVE-2026-114938 using the instance-type CPU map.
# No instance is touched; nothing is sent to any instance.
#
# The output splits the fleet into:
#   avx512vbmi-yes  candidates  - hardware CAN execute the vulnerable path;
#                                 run java4shell-check on them (SSM Tier 1)
#   avx512vbmi-no / arm        - definitively NOT vulnerable via this path
#   unknown                     - new/rare families; treat as candidates
#
# Usage:
#   ./aws-sweep.sh [--region <r>] [--profile <p>] [--include-stopped]
#                  [--skip-eks] [--fail-on-candidates] [--mock-dir <dir>]
#
# Requires: AWS CLI v2 with read access to ec2:DescribeInstances,
# eks:ListClusters, eks:ListNodegroups, eks:DescribeNodegroup.
#
# Exit codes: 0 ok (or 1 with --fail-on-candidates when candidate OR unknown
# instances / node-group types exist), 2 error.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MAP="$SCRIPT_DIR/instance-cpu-map.csv"
J4S_VERSION=$(head -n 1 "$SCRIPT_DIR/../VERSION" 2>/dev/null || echo unknown)

REGION_OPT=""
PROFILE_OPT=""
STATES="running"
SKIP_EKS=0
FAIL_ON_CANDIDATES=0
MOCK_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --region)     [ $# -ge 2 ] || { echo "--region needs a value"; exit 2; }; REGION_OPT="--region $2"; shift 2 ;;
    --profile)    [ $# -ge 2 ] || { echo "--profile needs a value"; exit 2; }; PROFILE_OPT="--profile $2"; shift 2 ;;
    --include-stopped) STATES="running,stopped"; shift ;;
    --skip-eks)   SKIP_EKS=1; shift ;;
    --fail-on-candidates) FAIL_ON_CANDIDATES=1; shift ;;
    --mock-dir)   [ $# -ge 2 ] || { echo "--mock-dir needs a value"; exit 2; }; MOCK_DIR=$2; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)"; exit 2 ;;
  esac
done

[ -r "$MAP" ] || { echo "ERROR: CPU map not found: $MAP"; exit 2; }
TMPE=$(mktemp 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
trap 'rm -f "$TMPE"' EXIT
trap 'rm -f "$TMPE"; exit 130' INT TERM
if [ -z "$MOCK_DIR" ]; then
  command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found"; exit 2; }
fi

# ---------------------------------------------------------- classification
# family token: part before the first dot (c7i.metal-24xl -> c7i), minus a
# -flex suffix (m7i-flex.large -> m7i)
family_of() {
  printf '%s' "$1" | cut -d. -f1 | sed -e 's/-flex$//'
}

# classify <cloud> <family>  -> "class|confidence|cpu_gen"
classify() {
  awk -F, -v c="$1" -v f="$2" '
    NR>1 && $1==c && $2==f { print $3 "|" $4 "|" $5; exit }
  ' "$MAP"
}

CAND=0; CLEAR=0; UNKN=0
NG_CAND=0; NG_CLEAR=0; NG_UNKN=0
count_class() { # <class> <ec2|ng>
  case "$1" in
    avx512vbmi-yes) [ "$2" = ec2 ] && CAND=$((CAND+1))  || NG_CAND=$((NG_CAND+1)) ;;
    avx512vbmi-no|arm) [ "$2" = ec2 ] && CLEAR=$((CLEAR+1)) || NG_CLEAR=$((NG_CLEAR+1)) ;;
    *)              [ "$2" = ec2 ] && UNKN=$((UNKN+1))  || NG_UNKN=$((NG_UNKN+1)) ;;
  esac
}
classify_emit() { # instance-id, type, state, name
  fam=$(family_of "$2")
  row=$(classify aws "$fam")
  cls=${row%%|*}; rest=${row#*|}; conf=${rest%%|*}; gen=${rest#*|}
  [ -z "$cls" ] && { cls="unknown"; conf=""; gen="not in map"; }
  count_class "$cls" ec2
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$fam" "$cls" "${conf:-?}" "${gen:-?}" "${4:-$3}"
}

echo "java4shell-check cloud sweep (Tier 0, read-only) for CVE-2026-114938"
echo "===================================================================="
echo "version: $J4S_VERSION"
[ -n "$MOCK_DIR" ] && echo "mode: MOCK ($MOCK_DIR)"
echo

# ------------------------------------------------------------------- EC2
echo "== EC2 instances (state: $STATES) =="
if [ -n "$MOCK_DIR" ]; then
  [ -r "$MOCK_DIR/instances.txt" ] || { echo "ERROR: $MOCK_DIR/instances.txt missing"; exit 2; }
  while IFS="$(printf '\t')" read -r iid itype state name; do
    [ -n "$iid" ] || continue
    case ",$STATES," in *",$state,"*) ;; *) continue ;; esac
    classify_emit "$iid" "$itype" "$state" "$name"
  done < "$MOCK_DIR/instances.txt"
else
  TMPF=$(mktemp 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
  ERRF=$(mktemp 2>/dev/null) || { echo "ERROR: mktemp failed"; exit 2; }
  # shellcheck disable=SC2086
  if ! aws ec2 describe-instances $PROFILE_OPT $REGION_OPT \
      --filters "Name=instance-state-name,Values=$STATES" \
      --query 'Reservations[].Instances[].[InstanceId,InstanceType,State.Name,Tags[?Key==`Name`].Value|[0]]' \
      --output text > "$TMPF" 2> "$ERRF"; then
    echo "ERROR: aws ec2 describe-instances failed:"; cat "$ERRF"
    rm -f "$TMPF" "$ERRF"; exit 2
  fi
  rm -f "$ERRF"
  while IFS="$(printf '\t')" read -r iid itype state name; do
    case "$iid" in i-*) ;; *) continue ;; esac
    [ -n "$itype" ] || continue
    classify_emit "$iid" "$itype" "$state" "$name"
  done < "$TMPF"
  rm -f "$TMPF"
fi

# ------------------------------------------------------------------- EKS
if [ "$SKIP_EKS" -eq 0 ]; then
  echo
  echo "== EKS node groups =="
  if [ -n "$MOCK_DIR" ]; then
    [ -r "$MOCK_DIR/eks-nodegroups.txt" ] || { echo "(no eks-nodegroups.txt - skipping EKS)"; }
    if [ -r "$MOCK_DIR/eks-nodegroups.txt" ]; then
      while IFS="$(printf '\t')" read -r cluster ng; do
        [ -n "$cluster" ] || continue
        types=$(awk -F'\t' -v n="$ng" '$1==n {$1=""; print}' "$MOCK_DIR/eks-nodegroup-desc.txt" | tr -s '\t' ' ')
        for t in $types; do
          fam=$(family_of "$t")
          row=$(classify aws "$fam"); [ -z "$row" ] && row="unknown||not in map"
          cls=${row%%|*}
          count_class "$cls" ng
          printf '%s\t%s\t%s\t%s\n' "$cluster" "$ng" "$t" "$cls"
        done
      done < "$MOCK_DIR/eks-nodegroups.txt"
    fi
  else
    # shellcheck disable=SC2086
    CLUSTERS=$(aws eks list-clusters $PROFILE_OPT $REGION_OPT --query 'clusters' --output text 2>"$TMPE") \
      || echo "WARNING: eks list-clusters failed ($(head -n 1 "$TMPE")); EKS node groups not listed"
    for c in $CLUSTERS; do
      # shellcheck disable=SC2086
      NGS=$(aws eks list-nodegroups $PROFILE_OPT $REGION_OPT --cluster-name "$c" --query 'nodegroups' --output text 2>"$TMPE") \
        || echo "WARNING: eks list-nodegroups failed for a cluster ($(head -n 1 "$TMPE"))"
      for ng in $NGS; do
        # shellcheck disable=SC2086
        TYPES=$(aws eks describe-nodegroup $PROFILE_OPT $REGION_OPT --cluster-name "$c" --nodegroup-name "$ng" \
                --query 'nodegroup.instanceTypes' --output text 2>/dev/null | tr '\t' ' ' || true)
        case "$TYPES" in
          ""|None)
            # Types set in a launch template: the running nodes are EC2
            # instances and are already classified in the EC2 section above.
            count_class unknown ng
            printf '%s\t%s\t%s\t%s\n' "$c" "$ng" "(launch template - see its EC2 nodes above)" "unknown"
            continue ;;
        esac
        for t in $TYPES; do
          fam=$(family_of "$t")
          row=$(classify aws "$fam"); [ -z "$row" ] && row="unknown||not in map"
          cls=${row%%|*}
          count_class "$cls" ng
          printf '%s\t%s\t%s\t%s\n' "$c" "$ng" "$t" "$cls"
        done
      done
    done
  fi
fi

# ---------------------------------------------------------------- summary
echo
echo "== summary =="
echo "EC2 instances:"
echo "  candidates (hardware CAN execute the vulnerable path): $CAND"
echo "  hard-cleared (CPU cannot reach the path):              $CLEAR"
echo "  unknown families (treat as candidates):                $UNKN"
if [ "$SKIP_EKS" -eq 0 ]; then
  echo "EKS node-group instance types (nodes are also EC2 instances above):"
  echo "  candidate types: $NG_CAND   cleared types: $NG_CLEAR   unknown types: $NG_UNKN"
fi
echo "Note: this sweep covers one region per run (--region)."
echo
echo "NEXT STEP: candidates need the in-place runtime check (JDK version,"
echo "flags, JIT). Push java4shell-check via SSM Run Command - see README."
echo "A 'yes' instance class is NOT a vulnerability verdict on its own; a"
echo "'no'/arm instance is definitively clear for THIS vulnerability."

TOTAL_RISK=$((CAND + UNKN + NG_CAND + NG_UNKN))
if [ "$FAIL_ON_CANDIDATES" -eq 1 ] && [ "$TOTAL_RISK" -gt 0 ]; then
  echo
  echo "RESULT: $((CAND + UNKN)) candidate/unknown instance(s), $((NG_CAND + NG_UNKN)) candidate/unknown node-group type(s)"
  exit 1
fi
exit 0
