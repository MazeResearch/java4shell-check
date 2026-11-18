# AGENTS.md — checking an environment for Java4Shell with java4shell-check

You are an AI agent asked to find out where CVE-2026-114938 ("Java4Shell") is
exploitable in the user's environment, using this tool, and to give the user
a report. Follow this file step by step.

The tool decides from three facts per JVM: **JDK version × CPU (x86-64 with
AVX-512 VBMI) × effective JVM flags**. It sends no exploit input, the tool
itself makes no network connections, and it never changes an application, a
JVM flag or a configuration. Exactly what each mode touches:

- `check-host.sh`: only reads `/proc`. Starts no JVM, attaches to none,
  writes nothing.
- `check.sh`: starts `java -version` and `java -XX:+PrintFlagsFinal -version`
  as short-lived JVMs with the environment's options (so anything
  `JAVA_TOOL_OPTIONS` loads, such as a `-javaagent`, starts too) and reads
  `/proc/cpuinfo`.
- `check-port.sh`: reads `/proc`; never executes a binary belonging to the
  target. If the target's JDK has `jcmd`, it runs `jcmd <pid> VM.flags` /
  `VM.version` (read-only diagnostic commands; the JVM starts its attach
  listener thread to answer) as the process's own user, never as root.
- `check-container.sh`: copies `check.sh`, `check-port.sh` and `lib/` into
  the container's `/tmp/.j4s-check`, runs them with `docker exec`, then
  deletes them (as root inside the container). For containers without a
  shell or with a read-only filesystem it instead starts a short-lived
  container from the same image ID with the same environment variables (not
  the same volumes/mounts) and removes it afterwards.
- `check-image.sh`: pulls the image if it is not present, starts short-lived
  containers from it with networking disabled and removes them, plus a
  `busybox` helper pinned by digest to read the Docker host's CPU.

If the user forbids starting containers or attaching to JVMs, say which
checks that rules out and list those targets under "Not checked".

## Rules (always)

1. **Read-only.** Never send Base64 trigger inputs or any payload to a
   service, never "test" an endpoint, never run a PoC. There is no safe remote
   check for this bug; the tool works only where the JVM runs.
2. **Change nothing.** Do not set JVM flags, restart services, patch, or edit
   configuration. Recommend those actions in the report instead.
3. **Ask before touching other machines.** Running anything on this machine
   is fine. Before running on any other machine (SSH, config management, a
   cloud provider's remote execution such as AWS SSM Run Command), show the
   user the target list and the exact command, and wait for an explicit yes. Before cloud API calls, tell
   the user which account/profile and regions you will query, and wait for a
   yes. Prefer read-only/least-privilege credentials over admin ones.
4. **Root only with approval.** `check-host.sh` needs root to see other users'
   processes. Ask before using `sudo`.
5. **Keep findings private.** Hostnames, container and image names in
   the results are sensitive. Keep results and the report in local files and
   in your conversation with the user. Do not paste them into issues, chats
   or other external services unless the user asks.
6. **Don't guess.** If a check can't run somewhere, list it under "Not
   checked" in the report with the reason. Never mark something safe because
   it wasn't checked.

## Step 1 — Get the tool

If the user already has a checkout, use it. Otherwise:

```sh
git clone https://github.com/MazeResearch/java4shell-check java4shell-check
# or, a single file (verify against SHA256SUMS.txt):
curl -fsSL -o j4s-check.sh https://github.com/MazeResearch/java4shell-check/releases/latest/download/j4s-check.sh
```

Call the scripts by path (e.g. `/path/to/java4shell-check/check-host.sh`)
from a separate working directory; don't write results into the tool's
directory. Use the repo's scripts, not an old `dist/` build lying around.

With the single file, replace `./check-host.sh` with `sh j4s-check.sh host`,
`./check-port.sh` with `sh j4s-check.sh port`, `./check-image.sh` with
`sh j4s-check.sh image`, `./check-container.sh` with
`sh j4s-check.sh container`, `./report.sh` with `sh j4s-check.sh report`.

Create a results directory **outside the tool directory** and save **every**
command's full output there:

```sh
mkdir -p j4s-results      # in your working directory
```

## Step 2 — Discover what exists (read-only)

```sh
uname -s -m
grep -m1 -E '^(flags|Features)' /proc/cpuinfo 2>/dev/null | head -c 300; echo   # Linux
sysctl -n machdep.cpu.brand_string 2>/dev/null                                   # macOS
for t in java docker aws ssh ansible; do printf '%s: ' "$t"; command -v "$t" || echo no; done
docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null     # if docker exists
```

Do **not** call cloud APIs yet, not even `aws sts get-caller-identity`. Ask
the user what is in scope: this machine only, Docker on this machine, which
other Linux machines (servers, cluster nodes, cloud instances), and how they
are reached (SSH, config management, a cloud provider's remote execution).

Which Docker containers run Java:

```sh
for c in $(docker ps --format '{{.Names}}'); do
  docker top "$c" -o pid,args 2>/dev/null | grep -qi 'java' && echo "$c"
done
```

(Running `check-container.sh` on a container without Java is harmless too:
it reports that no JVM was found.)

## Step 3 — Run the right checks

| Environment | Command(s) | Notes |
|---|---|---|
| This Linux machine | `./check.sh > j4s-results/local-jdk.log 2>&1` and, with approval, `sudo ./check-host.sh > j4s-results/local-host.log 2>&1` | `check.sh`: the installed JDK + environment. `check-host.sh`: every running JVM, containers included |
| Docker on this machine: running containers | `./check-container.sh <name> > j4s-results/ctr-<name>.log 2>&1` for each container that runs Java | Checks the container's JDK and env, and every running JVM in it with its effective flags |
| Docker images (registry, CI) | `./check-image.sh <image> > j4s-results/img-<name>.log 2>&1` | Run on a host of the **production CPU architecture**; on an arm64 Mac an amd64 image is emulated and the result is reported as uncertain |
| A service on this machine | `./check-port.sh <port> > j4s-results/port-<port>.log 2>&1` | Uses the running process's real flags (`jcmd`); detects a JVM that needs a restart |
| Other Linux machines (servers, cluster nodes, cloud instances) | With approval, through the access the user chose: copy `j4s-check.sh` (verified against `SHA256SUMS.txt`), run `sudo sh j4s-check.sh host`, save the output as `j4s-results/<host>.txt` | One run covers every JVM on that machine, including JVMs in containers. Check every machine, not one per image: the CPU differs between machines |
| macOS / Windows machines | Not supported for CPU detection | A laptop is rarely production; check the servers instead |
| Docker Desktop (macOS / Windows) | Container and image checks work; they run in Docker Desktop's Linux VM | The CPU is the laptop's (Apple Silicon = ARM = not exploitable there). Treat results as "this JDK/flags", and get CPU answers from production hosts |
| AWS (EC2 instances, EKS nodes) | 1) For each region: `./cloud/aws-sweep.sh --region <r> > j4s-results/aws-sweep-<r>.log 2>&1` (read-only API; which instances CAN be hit). 2) `./cloud/aws-ssm-host-check.sh --region <r>` (dry run: target list, sends nothing). 3) With approval: `./cloud/aws-ssm-host-check.sh --region <r> --run --out j4s-results/aws-<r>.tsv` | Needs a clone of the repo. List regions with `aws ec2 describe-regions --query 'Regions[].RegionName' --output text`. Show the user the dry-run target count before step 3; `--emit-payload <file>` writes the exact script that would run, for review. `--targets i-a,i-b` limits the run to chosen instances (try two first) |
| Managed services you can't log into (Fargate, Lambda, MSK, …) | Not covered by the tool | List under "Not checked". `check-image.sh` can tell you an image's JDK and flags, but not the CPU of the platform it runs on; follow the provider's bulletin |

**One method per machine.** On a node where you run `check-host.sh`, don't
also run `check-container.sh` for its containers: the node inventory already
covers every container's JVMs, and the report would count them twice.

Exit codes: 0 = NOT_VULNERABLE or MITIGATED; 1 = VULNERABLE (in port mode
this includes a vulnerable JVM that also needs a restart, when `jcmd` reports
its running version); 3 = RESTART_REQUIRED,
PROBABLY_FIXED or UNCERTAIN; 2 = the check itself failed. A non-zero exit is a
result, not a failure of your task: keep going. The `class=` field in the
output is the authoritative label.

## Step 4 — Build the report

```sh
/path/to/java4shell-check/report.sh --template j4s-results/* > java4shell-report.md
```

`report.sh` reads every saved output (whole logs are fine) and writes the
summary table and per-JVM tables; each container counts once, by its running
JVMs. `--template` adds three sections with placeholders near the top:
**replace each placeholder** with real content:

1. **Scope** — what you checked: machines, accounts, regions, clusters,
   images, and when.
2. **Not checked, and why** — no access, user declined, managed service,
   unsupported OS, machines whose check returned an error (the report's "No
   result" table). Be specific.
3. **Recommended actions, in order**, e.g.:
   - VULNERABLE: upgrade to the fixed build named in the JDK vendor's
     advisory and restart; until then set `-XX:-UseBASE64Intrinsics` (works
     on every architecture) and restart. Never push `-XX:UseAVX=2` to ARM
     hosts: the JVM won't start.
   - RESTART_REQUIRED: restart; the JDK on disk is already updated.
   - PROBABLY_FIXED: confirm the build number against the vendor advisory.
   - MITIGATED: still patch; the flag is a stopgap.
   - Include client machines (build agents, workers, CLI tools): a Java
     client connecting to a malicious TLS server is also exploitable.

Finally, tell the user in a few lines: how many JVMs/targets are VULNERABLE,
RESTART_REQUIRED and uncertain (use the report's summary counts), the top
actions, what was not checked, and the path to `java4shell-report.md`.

## Reading results correctly

| Class | Meaning |
|---|---|
| `VULNERABLE` | Affected JDK on an AVX-512 VBMI CPU with the Base64 intrinsic enabled |
| `RESTART_REQUIRED` | The JDK was replaced on disk after the JVM started; it still runs the old code |
| `PROBABLY_FIXED` | Patch-level build of the last affected update (e.g. `21.0.13.1`); fixed build numbers are not confirmed |
| `UNCERTAIN` | Could not be decided (JDK 18–20, early-access build, unknown CPU, emulation, JIT-limiting flags) |
| `MITIGATED` | Affected JDK, intrinsic disabled by `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX<=2` |
| `NOT_VULNERABLE` | Version without the code, fixed release, OpenJ9, or a CPU that cannot run the code |

Pitfalls:

- **How strong is the flags evidence?** `source: jcmd …` = the JVM's own
  effective values (strongest). `source: command line + option files +
  environment (jcmd not used)` = rebuilt from the process's command line,
  argument files and environment with the JVM's precedence rules (JRE-only
  images have no `jcmd`); a mitigation is never credited when part of the
  options can't be read.
  `flags=default(enabled)` / `FLAG_UNKNOWN` means no explicit flag was found,
  i.e. the intrinsic is on (the JVM default).

- **"NOT VULNERABLE ON THIS HOST" is about that CPU only.** The same JDK is
  exploitable on any Intel Ice Lake+ / AMD Zen 4+ host. Say so in the report
  when the affected JDK also runs elsewhere.
- **Images are checked on the Docker host's CPU.** Check images on hosts like
  production, or rely on the node checks.
- **`check.sh` sees the environment, not a running service's own flags.**
  Prefer `check-host.sh` / `check-port.sh` for running services.
- Results describe the moment you ran them. Note the time in the report.

## Machine-readable output (if you parse it yourself)

Every check prints one line per target:

```
J4S_RESULT  mode=  target=  jdk=  version=  vstat=  hw=  flags=  class=  exit=
```

`check-host.sh` prints one line per JVM plus one per node (at the end of its
human output, or alone with `--machine`):

```
J4S_JVM   host=  hw=  pid=  ctr=  name=  jdk=  vendor=  version=  vstat=  flags=  stale=  class=
J4S_HOST  host=  hw=  jvms=  vulnerable=  worst=        (or: J4S_HOST  error=<reason>)
```

Fields are tab-separated `key=value`. `ctr` is the container id; `name` is
the container's `HOSTNAME`: on plain Docker that is the 12-character container
id unless `--hostname` was set, on Kubernetes it is the pod name.
`cloud/aws-ssm-host-check.sh --out` writes the same lines prefixed with the
instance id, plus `J4S_NORESULT` rows for instances that could not be checked.
