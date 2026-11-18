#!/bin/sh
# java4shell-check test suite.
#
# usage: tests/run.sh            unit tests + Docker integration tests
#        tests/run.sh --unit     unit tests only (no Docker needed)
#
# Unit tests exercise the version classifier, the flag parser, the CPU
# evaluation, the verdict engine and report.sh with crafted inputs.
# Integration tests run every mode against real JDK images on the local
# Docker daemon. The CPU is simulated so the results are the same on any
# host: a fake /proc/cpuinfo is bind-mounted and J4S_TEST_ARCH=x86_64 makes
# the tool treat the machine as x86-64. Every container the suite starts is
# labelled `j4s-test` and removed at the end.

set -u

TOOL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=../lib/j4s-common.sh
. "$TOOL_DIR/lib/j4s-common.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); }
bad()  { FAIL=$((FAIL + 1)); echo "FAIL: $*"; }
eq()   { if [ "$2" = "$3" ]; then ok; else bad "$1: expected '$3', got '$2'"; fi; }

# ------------------------------------------------------------------ unit
echo "== unit: version classifier"
while IFS='|' read -r ver full want; do
  [ -n "$ver" ] || continue
  eq "classify $ver" "$(j4s_classify_version "$ver" "$full")" "$want"
done <<'EOF'
1.8.0_511|OpenJDK Runtime Environment|NOT_AFFECTED_VERSION
1.8.0_511|Java HotSpot(TM) 64-Bit Server VM (build 25.511-b33-perf)|AFFECTED_VERSION
11.0.25||NOT_AFFECTED_VERSION
16.0.2||NOT_AFFECTED_VERSION
17.0.5||NOT_AFFECTED_VERSION
17.0.6||AFFECTED_VERSION
17.0.21||AFFECTED_VERSION
17.0.21.0.3||AFFECTED_VERSION
17.0.21.1||FIXED_PATCH_ASSUMED
17.0.22||FIXED_VERSION
18.0.2.1||UNCONFIRMED_VERSION
19.0.2||UNCONFIRMED_VERSION
20.0.2||UNCONFIRMED_VERSION
21||AFFECTED_VERSION
21.0.13+11||AFFECTED_VERSION
21.0.13.0.3|Java HotSpot(TM) 64-Bit Server VM|AFFECTED_VERSION
21.0.13.0.3|Eclipse OpenJ9 VM|NOT_HOTSPOT
21.0.13.1||FIXED_PATCH_ASSUMED
21.0.14||FIXED_VERSION
22.0.2||AFFECTED_EOL_VERSION
25.0.5||AFFECTED_VERSION
25.0.6||FIXED_VERSION
26.0.1||AFFECTED_EOL_VERSION
27.0.1||AFFECTED_VERSION
27.0.1.1||FIXED_PATCH_ASSUMED
28||NEWER_THAN_ADVISORY
28-ea||EA_BUILD
21-ea||EA_BUILD
garbage||UNKNOWN_VERSION
EOF
eq "classify empty" "$(j4s_classify_version "" "")" "UNKNOWN_VERSION"
eq "classify OpenJ9 without version" "$(j4s_classify_version "" "Eclipse OpenJ9 VM")" "NOT_HOTSPOT"
eq "classify 8 + 'Picked up -XX:-UsePerfData'" "$(j4s_classify_version 1.8.0_402 "Picked up JAVA_TOOL_OPTIONS: -XX:-UsePerfData
OpenJDK 64-Bit Server VM (build 25.402-b06, mixed mode)")" "NOT_AFFECTED_VERSION"
eq "classify 21 + 'Picked up -ea'" "$(j4s_classify_version 21.0.13 "Picked up JAVA_TOOL_OPTIONS: -ea")" "AFFECTED_VERSION"
eq "classify EA from build string" "$(j4s_classify_version 28 "OpenJDK Runtime Environment (build 28-ea+5-123)")" "EA_BUILD"

echo "== unit: helpers"
eq "jdk home 9+" "$(j4s_jdk_home_of /opt/java/openjdk/lib/server/libjvm.so)" "/opt/java/openjdk"
eq "jdk home 8" "$(j4s_jdk_home_of /usr/lib/jvm/j8/jre/lib/amd64/server/libjvm.so)" "/usr/lib/jvm/j8"
eq "jdk home OpenJ9 j9vm" "$(j4s_jdk_home_of /opt/java/openjdk/lib/j9vm/libjvm.so)" "/opt/java/openjdk"
eq "jdk home OpenJ9 default" "$(j4s_jdk_home_of /opt/java/openjdk/lib/default/libj9vm29.so)" "/opt/java/openjdk"
eq "safe strips control chars" "$(j4s_safe "$(printf '21.0.5\033[2J\tpod=x')")" "21.0.5[2Jpod=x"
eq "relevant opts drop secrets" "$(j4s_relevant_opts "-Xmx1g -Ddb.password=hunter2 -javaagent:/a.jar=key=abc -XX:-UseBASE64Intrinsics @/etc/app.args")" "-XX:-UseBASE64Intrinsics @/etc/app.args"

echo "== unit: flag parser"
flags() { j4s_parse_flags "$1"; echo "$FLAG_STATUS"; }
eq "intrinsic off" "$(flags 'bool UseBASE64Intrinsics = false {product}')" "FLAG_OFF"
eq "avx2" "$(flags 'bool UseBASE64Intrinsics = true
intx UseAVX = 2')" "FLAG_AVX2"
eq "on" "$(flags 'bool UseBASE64Intrinsics = true
intx UseAVX = 3')" "FLAG_ON"
eq "xint" "$(flags 'bool UseBASE64Intrinsics = true
intx UseAVX = 3
bool UseCompiler = false')" "FLAG_NOC2"
eq "tiered stop 1" "$(flags 'bool UseBASE64Intrinsics = true
intx UseAVX = 3
bool TieredCompilation = true
intx TieredStopAtLevel = 1')" "FLAG_NOC2"
eq "stop 1 without tiered" "$(flags 'bool UseBASE64Intrinsics = true
intx UseAVX = 3
bool TieredCompilation = false
intx TieredStopAtLevel = 1')" "FLAG_ON"
eq "empty" "$(flags '')" "FLAG_UNREADABLE"
eq "arm defaults" "$(flags 'bool UseBASE64Intrinsics = true')" "FLAG_UNKNOWN"

echo "== unit: CPU evaluation"
cpu() { J4S_TEST_ARCH='' j4s_cpu_eval "$1" "$2"; echo "$HW"; }
X86_VBMI='flags		: fpu sse avx2 bmi2 avx512f avx512bw avx512vbmi'
X86_PLAIN='flags		: fpu sse avx2 bmi2 avx512f avx512bw'
ARM='Features	: fp asimd evtstrm aes'
eq "x86 vbmi" "$(cpu "$X86_VBMI" x86_64)" "HW_VULNERABLE"
eq "x86 no vbmi" "$(cpu "$X86_PLAIN" x86_64)" "HW_SAFE"
eq "x86 no flags" "$(cpu "" x86_64)" "HW_UNKNOWN"
eq "arm" "$(cpu "$ARM" aarch64)" "HW_SAFE"
eq "arm with x86 flags" "$(cpu "$X86_VBMI" aarch64)" "HW_SAFE"
eq "other arch" "$(cpu "" s390x)" "HW_SAFE"

echo "== unit: verdict engine"
verdict() { VSTAT=$1 HW=$2 FLAG_STATUS=$3 FLAG_DETAIL=x; j4s_verdict; echo "$EXIT_CODE $(j4s_class)"; }
eq "vulnerable" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_ON)" "1 VULNERABLE"
eq "vulnerable, default flags" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_UNKNOWN)" "1 VULNERABLE"
eq "eol vulnerable" "$(verdict AFFECTED_EOL_VERSION HW_VULNERABLE FLAG_ON)" "1 VULNERABLE"
eq "mitigated off" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_OFF)" "0 MITIGATED"
eq "mitigated avx2" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_AVX2)" "0 MITIGATED"
eq "cpu safe" "$(verdict AFFECTED_VERSION HW_SAFE FLAG_ON)" "0 NOT_VULNERABLE"
eq "cpu unknown" "$(verdict AFFECTED_VERSION HW_UNKNOWN FLAG_ON)" "3 UNCERTAIN"
eq "noc2" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_NOC2)" "3 UNCERTAIN"
eq "flags unreadable" "$(verdict AFFECTED_VERSION HW_VULNERABLE FLAG_UNREADABLE)" "3 UNCERTAIN"
eq "openj9" "$(verdict NOT_HOTSPOT HW_VULNERABLE FLAG_ON)" "0 NOT_VULNERABLE"
eq "old version" "$(verdict NOT_AFFECTED_VERSION HW_VULNERABLE FLAG_ON)" "0 NOT_VULNERABLE"
eq "fixed" "$(verdict FIXED_VERSION HW_VULNERABLE FLAG_ON)" "0 NOT_VULNERABLE"
eq "probably fixed" "$(verdict FIXED_PATCH_ASSUMED HW_VULNERABLE FLAG_ON)" "3 PROBABLY_FIXED"
eq "18-20" "$(verdict UNCONFIRMED_VERSION HW_VULNERABLE FLAG_ON)" "3 UNCERTAIN"
eq "ea" "$(verdict EA_BUILD HW_VULNERABLE FLAG_ON)" "3 UNCERTAIN"

echo "== unit: report.sh"
REPORT_IN=$(printf '%s\n' \
  "J4S_RESULT	mode=container	target=container web (JDK + env)	jdk=/j	version=21.0.13	vstat=AFFECTED_VERSION	hw=HW_VULNERABLE	flags=FLAG_ON	class=VULNERABLE	exit=1" \
  "J4S_RESULT	mode=container-jvm	target=container web pid 1	jdk=/j	version=21.0.13	vstat=AFFECTED_VERSION	hw=HW_VULNERABLE	flags=FLAG_ON	class=VULNERABLE	exit=1" \
  "J4S_RESULT	mode=container	target=container idle (JDK + env)	jdk=/j	version=17.0.5	vstat=NOT_AFFECTED_VERSION	hw=HW_VULNERABLE	flags=FLAG_ON	class=NOT_VULNERABLE	exit=0" \
  "J4S_JVM	host=n1	hw=HW_VULNERABLE	pid=7	ctr=abc	name=api-0	jdk=/opt/j	vendor=Eclipse_Adoptium	version=17.0.6	vstat=AFFECTED_VERSION	flags=FLAG_OFF	stale=0	class=MITIGATED" \
  "J4S_HOST	host=n1	hw=HW_VULNERABLE	jvms=1	vulnerable=0	worst=0" \
  "node-2	J4S_HOST	error=missing-tool-awk" \
  "i-0abc	J4S_NORESULT	status=Success/incomplete-output" \
  "J4S_RESULT	mode=host-jdk	target=evil <img src=x onerror=alert(1)> [x](http://e)	jdk=/j	version=21.0.13	vstat=AFFECTED_VERSION	hw=HW_VULNERABLE	flags=FLAG_OFF	class=MITIGATED	exit=0" \
  "unrelated log line | with a pipe")
REPORT=$(printf '%s\n' "$REPORT_IN" | sh "$TOOL_DIR/report.sh")
row() { printf '%s\n' "$REPORT" | awk -F'|' -v c=" $1 " '$2 == c {gsub(/ /, "", $3); print $3}'; }
eq "report vulnerable (container counted once)" "$(row VULNERABLE)" "1"
eq "report mitigated" "$(row MITIGATED)" "2"
eq "report escapes markdown/html" "$(printf '%s\n' "$REPORT" | grep -c -E '<img|\]\(http')" "0"
eq "report not vulnerable (container without JVM rows kept)" "$(row NOT_VULNERABLE)" "1"
eq "report no-result rows" "$(printf '%s\n' "$REPORT" | grep -c -E '^\| (node-2|i-0abc) ')" "2"
eq "report names the container" "$(printf '%s\n' "$REPORT" | grep -c 'n1 / container api-0 / pid 7')" "1"
eq "report nodes" "$(printf '%s\n' "$REPORT" | grep -c 'Nodes inventoried: 1 ')" "1"
eq "report empty input" "$(printf '\n' | sh "$TOOL_DIR/report.sh" | tail -n 1)" "No java4shell-check results found in the input."

echo "== unit: cloud/aws-sweep.sh with the bundled mock data"
_o=$(sh "$TOOL_DIR/cloud/aws-sweep.sh" --mock-dir "$TOOL_DIR/cloud/mock" --fail-on-candidates 2>&1); _rc=$?
eq "sweep: candidates fail the gate (exit 1)" "$_rc" "1"
eq "sweep: EKS candidate node-group types counted" "$(printf '%s\n' "$_o" | grep -c 'candidate types: 2 ')" "1"

echo "== unit: cloud/aws-ssm-host-check.sh against a fake aws CLI"
if command -v python3 >/dev/null 2>&1 || command -v jq >/dev/null 2>&1; then
  chmod +x "$TOOL_DIR/tests/fixtures/aws"
  FAKE_AWS_STATE=$(mktemp -d) || exit 2
  SSM_OUT="$FAKE_AWS_STATE/rows.tsv"
  _o=$(PATH="$TOOL_DIR/tests/fixtures:$PATH" FAKE_AWS_STATE=$FAKE_AWS_STATE J4S_SSM_POLL_SECONDS=0 \
       sh "$TOOL_DIR/cloud/aws-ssm-host-check.sh" --region r --targets i-1,i-2,i-3,i-9 --run --out "$SSM_OUT" 2>&1)
  _rc=$?
  eq "ssm: paginated status output does not crash the wait loop" "$(printf '%s\n' "$_o" | grep -c 'syntax error')" "0"
  eq "ssm: exit 1 (a VULNERABLE JVM)" "$_rc" "1"
  eq "ssm: vulnerable JVM collected" "$(grep -c 'i-1	J4S_JVM.*class=VULNERABLE' "$SSM_OUT")" "1"
  eq "ssm: truncated node marked incomplete" "$(grep -c 'i-3	J4S_NORESULT	status=Success/incomplete-output' "$SSM_OUT")" "1"
  eq "ssm: truncated node keeps its complete rows only" "$(grep -c 'i-3	J4S_JVM' "$SSM_OUT")" "1"
  eq "ssm: unreachable target listed" "$(grep -c 'i-9	J4S_NORESULT	status=not-reachable-via-SSM' "$SSM_OUT")" "1"
  eq "ssm: summary shows the container name" "$(printf '%s\n' "$_o" | grep -c 'i-1  web-1 ')" "1"
  _o=$(PATH="$TOOL_DIR/tests/fixtures:$PATH" FAKE_AWS_STATE=$FAKE_AWS_STATE FAKE_AWS_FAIL_LIST=1 \
       sh "$TOOL_DIR/cloud/aws-ssm-host-check.sh" --region r --targets i-1 2>&1)
  _rc=$?
  eq "ssm: listing failure is an error (exit 2)" "$_rc" "2"
  eq "ssm: listing failure is reported" "$(printf '%s\n' "$_o" | grep -c 'describe-instance-information failed')" "1"
  rm -rf "$FAKE_AWS_STATE"
else
  echo "  (skipped: needs python3 or jq)"
fi

if [ "${1:-}" = "--unit" ]; then
  echo
  echo "unit tests: $PASS passed, $FAIL failed"
  [ $FAIL -eq 0 ]; exit $?
fi

# ----------------------------------------------------------- integration
command -v docker >/dev/null 2>&1 || { echo "docker not found: run with --unit"; exit 2; }
WORK=$(mktemp -d) || exit 2
LABEL="--label j4s-test=1"
cleanup() {
  docker ps -aq --filter label=j4s-test=1 | xargs docker rm -f >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

T21=eclipse-temurin:21.0.13_9-jdk
T17=eclipse-temurin:17.0.6_10-jre
T175=eclipse-temurin:17.0.5_8-jre
SEMERU=ibm-semeru-runtimes:open-21-jre
DISTROLESS=gcr.io/distroless/java21-debian12:latest

printf '%s\n' "processor	: 0" "$X86_VBMI" > "$WORK/cpuinfo-vbmi"
printf '%s\n' "processor	: 0" "$X86_PLAIN" > "$WORK/cpuinfo-plain"
mkdir -p "$WORK/app"
cp "$TOOL_DIR/tests/fixtures/SampleServer.java" "$WORK/app/"
docker run --rm -v "$WORK/app":/app "$T21" javac --release 17 -d /app /app/SampleServer.java >/dev/null 2>&1 \
  || { echo "could not compile the demo app"; exit 2; }
SIM="-e J4S_TEST_ARCH=x86_64 -v $WORK/cpuinfo-vbmi:/proc/cpuinfo:ro"
SIM_PLAIN="-e J4S_TEST_ARCH=x86_64 -v $WORK/cpuinfo-plain:/proc/cpuinfo:ro"

result() { printf '%s\n' "$1" | grep '^J4S_RESULT' | tail -n 1 | tr '\t' '\n' | sed -n "s/^$2=//p"; }

echo "== integration: check.sh"
chk() { # label, expected class, expected exit, docker args...
  _l=$1; _c=$2; _e=$3; shift 3
  # shellcheck disable=SC2068
  _o=$(docker run --rm $LABEL -v "$TOOL_DIR":/t:ro $@ /t/check.sh 2>&1); _rc=$?
  eq "$_l class" "$(result "$_o" class)" "$_c"
  eq "$_l exit" "$_rc" "$_e"
}
chk "21.0.13 on AVX-512 VBMI" VULNERABLE 1 $SIM --entrypoint sh $T21
chk "21.0.13 on x86 without VBMI" NOT_VULNERABLE 0 $SIM_PLAIN --entrypoint sh $T21
chk "21.0.13 with -UseBASE64Intrinsics" MITIGATED 0 $SIM -e JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics --entrypoint sh $T21
chk "21.0.13 with -Xint" UNCERTAIN 3 $SIM -e JAVA_TOOL_OPTIONS=-Xint --entrypoint sh $T21
chk "17.0.6 JRE" VULNERABLE 1 $SIM --entrypoint sh $T17
chk "17.0.5" NOT_VULNERABLE 0 $SIM --entrypoint sh $T175
chk "OpenJ9" NOT_VULNERABLE 0 $SIM --entrypoint sh $SEMERU
chk "real CPU of this host, 17.0.5" NOT_VULNERABLE 0 --entrypoint sh $T175

echo "== integration: check-port.sh"
port() { # label, expected class, expected exit, image, env args (quoted), java args...
  _l=$1; _c=$2; _e=$3; _img=$4; _env=$5; shift 5
  docker rm -f j4s-test-port >/dev/null 2>&1
  # shellcheck disable=SC2086
  docker run -d --name j4s-test-port $LABEL $SIM $_env -v "$WORK/app":/app:ro -v "$TOOL_DIR":/t:ro \
    --entrypoint java "$_img" "$@" -cp /app SampleServer 5000 >/dev/null
  i=0; while [ $i -lt 30 ] && ! docker logs j4s-test-port 2>&1 | grep -q listening; do sleep 1; i=$((i + 1)); done
  _o=$(docker exec j4s-test-port sh /t/check-port.sh 5000 2>&1); _rc=$?
  eq "port $_l class" "$(result "$_o" class)" "$_c"
  eq "port $_l exit" "$_rc" "$_e"
}
port "default" VULNERABLE 1 $T21 ""
port "-X then +X" VULNERABLE 1 $T21 "" -XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics
port "-X" MITIGATED 0 $T21 "" -XX:-UseBASE64Intrinsics
port "JRE, _JAVA_OPTIONS overrides" VULNERABLE 1 $T17 "-e _JAVA_OPTIONS=-XX:+UseBASE64Intrinsics" -XX:-UseBASE64Intrinsics
port "JRE, JAVA_TOOL_OPTIONS -X" MITIGATED 0 $T17 "-e JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics"
port "OpenJ9" NOT_VULNERABLE 0 $SEMERU ""

# A process can claim any argv[0]. Port mode must never execute a binary
# derived from the target: plant a fake "java" that leaves a marker if run.
docker rm -f j4s-test-port >/dev/null 2>&1
docker run -d --name j4s-test-port $LABEL $SIM -v "$WORK/app":/app:ro -v "$TOOL_DIR":/t:ro --entrypoint bash $T21 \
  -c 'mkdir -p /tmp/evil && printf "#!/bin/sh\ntouch /tmp/PWNED\n" > /tmp/evil/java && cp /tmp/evil/java /tmp/evil/jcmd && chmod +x /tmp/evil/* && exec -a /tmp/evil/java java -cp /app SampleServer 5000' >/dev/null
i=0; while [ $i -lt 30 ] && ! docker logs j4s-test-port 2>&1 | grep -q listening; do sleep 1; i=$((i + 1)); done
_o=$(docker exec j4s-test-port sh /t/check-port.sh 5000 2>&1)
eq "port spoofed argv[0]: still classified" "$(result "$_o" class)" "VULNERABLE"
eq "port spoofed argv[0]: planted binary never ran" "$(docker exec j4s-test-port sh -c 'ls /tmp/PWNED 2>/dev/null | wc -l' | tr -d ' ')" "0"

echo "== integration: check-host.sh (simulated node)"
start() { # name, image, env, java args...
  _n=$1; _img=$2; _env=$3; shift 3
  # shellcheck disable=SC2086
  docker run -d --name "$_n" $LABEL $_env -v "$WORK/app":/app:ro --entrypoint java "$_img" "$@" -cp /app SampleServer 5000 >/dev/null
}
printf -- '-XX:-UseBASE64Intrinsics\n' > "$WORK/app/opts.txt"
start j4s-test-h1 $T21 ""
start j4s-test-h2 $T21 "" -XX:-UseBASE64Intrinsics
start j4s-test-h3 $T17 "-e _JAVA_OPTIONS=-XX:+UseBASE64Intrinsics" -XX:-UseBASE64Intrinsics
start j4s-test-h4 $T21 "" @/app/opts.txt
start j4s-test-h5 $SEMERU ""
printf -- '-cp /app SampleServer 5000 -XX:-UseBASE64Intrinsics\n' > "$WORK/app/args-after-main.txt"
start j4s-test-h7 $T21 "" --enable-native-access ALL-UNNAMED -XX:-UseBASE64Intrinsics
docker run -d --name j4s-test-h8 $LABEL -e "JAVA_TOOL_OPTIONS=-Xmx64m	-XX:-UseBASE64Intrinsics" \
  -v "$WORK/app":/app:ro --entrypoint java $T21 -cp /app SampleServer 5000 >/dev/null
docker run -d --name j4s-test-h9 $LABEL -v "$WORK/app":/app:ro --entrypoint sh $T21 \
  -c 'FOO="x
_JAVA_OPTIONS=-XX:-UseBASE64Intrinsics" exec java -cp /app SampleServer 5000' >/dev/null
docker run -d --name j4s-test-h10 $LABEL -v "$WORK/app":/app:ro --entrypoint java $T21 @/app/args-after-main.txt >/dev/null
docker run -d --name j4s-test-h6 $LABEL -v "$WORK/app":/app:ro --entrypoint sh $T21 \
  -c 'cp -a /opt/java/openjdk /opt/jdk && exec /opt/jdk/bin/java -cp /app SampleServer 5000' >/dev/null
sleep 8
docker exec j4s-test-h6 sh -c 'cp /opt/jdk/lib/server/libjvm.so /tmp/l && rm /opt/jdk/lib/server/libjvm.so && cp /tmp/l /opt/jdk/lib/server/libjvm.so'
HOST_OUT=$(docker run --rm $LABEL --privileged --pid=host $SIM -v "$TOOL_DIR":/t:ro --entrypoint sh $T21 /t/check-host.sh --machine)
hclass() {
  _pid=$(docker inspect -f '{{.State.Pid}}' "$1")
  printf '%s\n' "$HOST_OUT" | grep "^J4S_JVM" | grep "	pid=$_pid	" | tr '\t' '\n' | sed -n 's/^class=//p'
}
eq "host default" "$(hclass j4s-test-h1)" "VULNERABLE"
eq "host -X" "$(hclass j4s-test-h2)" "MITIGATED"
eq "host _JAVA_OPTIONS overrides" "$(hclass j4s-test-h3)" "VULNERABLE"
eq "host @argfile" "$(hclass j4s-test-h4)" "MITIGATED"
eq "host OpenJ9" "$(hclass j4s-test-h5)" "NOT_VULNERABLE"
eq "host replaced JDK" "$(hclass j4s-test-h6)" "RESTART_REQUIRED"
eq "host --enable-native-access value skipped" "$(hclass j4s-test-h7)" "MITIGATED"
eq "host tab-separated JAVA_TOOL_OPTIONS" "$(hclass j4s-test-h8)" "MITIGATED"
eq "host newline-smuggled env var ignored" "$(hclass j4s-test-h9)" "VULNERABLE"
eq "host argfile option after main class ignored" "$(hclass j4s-test-h10)" "VULNERABLE"

echo "== integration: check-port.sh as root against a non-root JVM (jcmd as its owner)"
docker rm -f j4s-test-port >/dev/null 2>&1
docker run -d --name j4s-test-port $LABEL $SIM --user 1000:1000 -v "$WORK/app":/app:ro -v "$TOOL_DIR":/t:ro \
  --entrypoint java $T21 -XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics -cp /app SampleServer 5000 >/dev/null
i=0; while [ $i -lt 30 ] && ! docker logs j4s-test-port 2>&1 | grep -q listening; do sleep 1; i=$((i + 1)); done
_o=$(docker exec -u 0 --privileged j4s-test-port sh /t/check-port.sh 5000 2>&1)
eq "port jcmd as owner: flags from jcmd" "$(printf '%s\n' "$_o" | grep -c '^  source: jcmd 1 VM.flags')" "1"
eq "port jcmd as owner: class" "$(result "$_o" class)" "VULNERABLE"

echo "== integration: check-container.sh"
ctr() { # label, container, expected exit
  _o=$(sh "$TOOL_DIR/check-container.sh" "$2" 2>&1); _rc=$?
  eq "container $1 exit" "$_rc" "$3"
  eq "container $1 cleaned up" "$(docker exec "$2" ls /tmp/.j4s-check 2>/dev/null | wc -l | tr -d ' ')" "0"
}
docker run -d --name j4s-test-c1 $LABEL $SIM -v "$WORK/app":/app:ro --entrypoint java $T21 -cp /app SampleServer 5000 >/dev/null
docker run -d --name j4s-test-c2 $LABEL --read-only -v "$WORK/app":/app:ro --entrypoint java $T175 -cp /app SampleServer 5000 >/dev/null
sleep 5
ctr "vulnerable" j4s-test-c1 1
ctr "read-only (replayed)" j4s-test-c2 0
docker run -d --name j4s-test-c3 $LABEL $SIM --user 1000:1000 -v "$WORK/app":/app:ro --entrypoint java $T21 -XX:-UseBASE64Intrinsics -cp /app SampleServer 5000 >/dev/null
sleep 5
ctr "non-root container" j4s-test-c3 0

echo "== integration: check-image.sh"
_o=$(sh "$TOOL_DIR/check-image.sh" $T175 2>&1); eq "image 17.0.5 class" "$(result "$_o" class)" "NOT_VULNERABLE"
_o=$(sh "$TOOL_DIR/check-image.sh" $DISTROLESS 2>&1)
eq "image distroless found java" "$(printf '%s\n' "$_o" | grep -c '^java found: ')" "1"

echo
echo "tests: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
