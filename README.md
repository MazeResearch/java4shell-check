# java4shell-check

Checks whether your JVMs are exploitable through CVE-2026-114938 ("Java4Shell"), the out-of-bounds write in OpenJDK's AVX-512 VBMI Base64 intrinsic.

A JVM is exploitable only when three things are true: it runs an affected JDK, on an x86-64 CPU with AVX-512 VBMI, with the Base64 intrinsic enabled. The tool checks all three where the JVM runs. It sends no exploit input, changes nothing and makes no network connections. Linux only (x86-64 and ARM64).

There's no safe way to check this over the network. Patched and unpatched JVMs answer every request the same way; the only difference is the heap corruption, so any probe that could detect it is the exploit. Background: [mazehq.com/blog/java4shell](https://mazehq.com/blog/java4shell).

## Before you run it

Read the scripts and understand what they do before you run them, especially on production machines. The host check runs as root, and the AWS step runs it as root across your instances. The code is plain shell and short enough to read in one sitting, and [`AGENTS.md`](AGENTS.md) lists exactly what each mode touches. Before the AWS step, review the exact script it will send with `--emit-payload`. The tool is provided as is, under the MIT license, with no warranty.

## Use it with an AI agent

Give your coding agent:

```text
Check our environment for Java4Shell (CVE-2026-114938) with https://github.com/MazeResearch/java4shell-check.
Clone it and follow its AGENTS.md. Stay read-only, ask me before running anything on
other machines or cloud accounts, and give me the report.
```

[`AGENTS.md`](AGENTS.md) tells the agent to ask what's in scope, run the right check on each machine, container, image or AWS account, and write a Markdown report of every JVM with what to do next. It never sends exploit input or changes anything, and it shows you the targets and the exact command before it touches another machine or a cloud account.

## Use it yourself

On any Linux machine, as root:

```sh
curl -fsSL -O https://github.com/MazeResearch/java4shell-check/releases/latest/download/j4s-check.sh -O https://github.com/MazeResearch/java4shell-check/releases/latest/download/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
sudo sh j4s-check.sh host
```

`host` lists every running JVM on the machine, including JVMs in containers, with its JDK version, effective flags and verdict. It only reads `/proc`: it starts no JVM and attaches to none. It needs root to see other users' processes.

To check many machines, run `host` on each one, save the outputs in a folder and merge them:

```sh
sudo sh j4s-check.sh host > j4s-results/$(hostname).txt 2>&1
sh j4s-check.sh report j4s-results/* > java4shell-report.md
```

Check every machine, not one per image: the same image is exploitable on an AVX-512 VBMI machine and safe on an ARM one.

### Modes

| Command | Checks |
|---|---|
| `j4s-check.sh host` / `check-host.sh` | Every running JVM on the machine, containers included |
| `j4s-check.sh` / `check.sh` | The JDK on disk, with this environment's options |
| `j4s-check.sh port <port>` / `check-port.sh` | The Java service behind a local port (or `--pid <pid>`) |
| `j4s-check.sh container <name>` / `check-container.sh` | A running Docker container and every JVM in it |
| `j4s-check.sh image <image>` / `check-image.sh` | A Docker image, distroless included, on this Docker host's CPU |
| `j4s-check.sh report [files]` / `report.sh` | One Markdown report from saved outputs (whole logs are fine) |
| `cloud/aws-sweep.sh`, `cloud/aws-ssm-host-check.sh` | An AWS region (see below) |

### Exit codes

| Exit | Meaning |
|---|---|
| 0 | Not vulnerable, or mitigated by flags. The output says why (version, CPU or flags). |
| 1 | Vulnerable: affected JDK, AVX-512 VBMI CPU, intrinsic enabled. |
| 3 | Needs attention: restart required, probably fixed (confirm with your vendor), or uncertain. |
| 2 | The check itself failed. |

Every script takes `--help` and `--version`.

### AWS

From a clone of the repo, one region at a time:

```sh
./cloud/aws-sweep.sh --region us-east-1                     # which instances CAN be hit (read-only API)
./cloud/aws-ssm-host-check.sh --region us-east-1            # dry run: lists targets, sends nothing
./cloud/aws-ssm-host-check.sh --emit-payload /tmp/j4s.sh    # the exact script that will run on each node
./cloud/aws-ssm-host-check.sh --region us-east-1 --run --out j4s-results/aws.tsv
./report.sh j4s-results/aws.tsv > java4shell-report.md
```

The sweep sorts EC2 instances and EKS node groups by instance family (`cloud/instance-cpu-map.csv`) into candidates (AVX-512 VBMI), cleared (ARM, or x86 without VBMI) and unknown, which it treats as candidates. The SSM step runs the host check as root on the candidates that SSM can reach, in batches of 50, without writing anything to disk. Instances it can't reach, and incomplete output, are listed as not checked. `--targets i-a,i-b` limits the run to chosen instances.

Permissions: `ec2:DescribeInstances`, `ssm:DescribeInstanceInformation`, `ssm:SendCommand`, `ssm:ListCommandInvocations`, `ssm:GetCommandInvocation`, and `eks:List*` / `eks:Describe*` for node groups.

### CI

Run on a runner with your production CPU architecture; exit 1 fails the build:

```yaml
- run: ./java4shell-check/check-image.sh "$IMAGE_REF"
```

## Fixing what it finds

Upgrade to the fixed build named in your JDK vendor's advisory, then restart every JVM. Until you can, set `JAVA_TOOL_OPTIONS=-XX:-UseBASE64Intrinsics` (accepted on every HotSpot architecture), restart, and confirm with `host` or `port`. `-XX:UseAVX=2` also works, but only on x86-64: ARM JVMs refuse to start with it.

To spot attempts, look for padded Base64 shapes in WAF logs, bursts of `IllegalArgumentException` from `java.util.Base64$Decoder`, and unexplained JVM crashes (`hs_err_pid` files).

## How it decides

The JDK version is classified against the advisories: 17.0.6 to 17.0.21, 21.0 to 21.0.13, 25.0 to 25.0.5 and 27.0 to 27.0.1 are affected, as are Oracle's `.0.3` builds, Oracle's Java 8 performance build (recognised by `-perf` in its version) and the EOL releases 22 to 24 and 26. Later updates such as `21.0.14` are fixed. A patch-level build of the last affected update, such as `21.0.13.1`, is reported as probably fixed, because the advisories don't list fixed build numbers. JDK 18 to 20 and early-access builds are reported as uncertain. Eclipse OpenJ9 (IBM Semeru) isn't HotSpot and isn't affected.

The CPU comes from `/proc/cpuinfo`: x86-64 with `avx512f`, `avx512bw`, `avx512vbmi` and `bmi2` (Intel Ice Lake or newer, AMD Zen 4 or newer). Anything that isn't x86-64 is safe.

The flags are the ones the JVM actually applies. `-XX:-UseBASE64Intrinsics` or `-XX:UseAVX=2` (or lower) mitigates. For a running process the tool rebuilds them from its command line, argument files and environment in the order the JVM reads them (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, command line, `_JAVA_OPTIONS`); on real hardware this matched the JVMs' own `jcmd VM.flags` output for every JVM tested. So `-XX:-UseBASE64Intrinsics -XX:+UseBASE64Intrinsics` correctly counts as not mitigated. `-Xint` and similar JIT limits are reported but not counted as a mitigation.

## Safety

The tool changes nothing and sends nothing to any service. [`AGENTS.md`](AGENTS.md) lists exactly what each mode touches. In short:

- `host` only reads `/proc`.
- `check.sh` starts `java -version` and `java -XX:+PrintFlagsFinal -version` with this environment's options, so a `-javaagent` set in `JAVA_TOOL_OPTIONS` starts too.
- `port` also only reads files. It never runs anything that belongs to the process it checks (no `java`, no `jcmd`): run from the host, a binary from a container's filesystem would escape that container's isolation.
- `container` copies the tool into the container's `/tmp` and removes it afterwards. Read-only and shell-less containers are checked from a fresh copy of the same image instead.
- `image` may pull the image; its containers run without network.
- Command lines and `JAVA_*OPTIONS` often hold secrets, so only the JVM options that matter for this CVE are printed.

Only run it on systems you're allowed to check.

## Limitations

- It checks whether a JVM is exploitable, not whether an attacker can reach it. Calif showed default-config reachability in Jira, Confluence, Jenkins, Keycloak, Artifactory, PingFederate and others.
- It doesn't reproduce the bug. A vendor build that backported the fix without changing its version number is still reported by its version.
- Updating the JDK doesn't fix a JVM that's already running. `host` and `port` detect it: run as root on the host, they read the version still running from memory, so a JVM that's still vulnerable stays VULNERABLE; when they can't read it, they report RESTART_REQUIRED. Rebuild images pinned to old digests too.
- Java clients count, not just servers: a client that connects to a malicious TLS server can be hit. Include build agents, workers and CLI tools.
- A laptop or CI runner that says "NOT VULNERABLE ON THIS HOST" only speaks for its own CPU. If the version is affected, the same JDK is exploitable on any AVX-512 VBMI machine, and the output says so.
- An amd64 image run on an arm64 machine runs under emulation, which hides AVX-512. `image` detects this and exits 3.
- `check.sh` sees the environment, not flags that wrapper scripts or unit files pass to a running service. Use `host` or `port` for running services.
- Linux only. On macOS, Apple Silicon is reported as ARM (safe) and Intel as unknown. The fleet scripts cover AWS only.
- Kernels older than 4.10 don't list `avx512vbmi` in `/proc/cpuinfo` even when the CPU has it.

## Testing

`tests/run.sh` runs the unit tests and the integration tests, which run every mode against real JDK images in Docker with a simulated CPU, so results are the same on any Docker host. `tests/run.sh --unit` needs no Docker.

The tool was also validated on real AWS hardware: 63 JVMs on 4 nodes, including Intel Sapphire Rapids and AMD Zen 4 machines and AMD Zen 3 and ARM controls, with every verdict matching what the JVMs reported about themselves, plus CPU readings on 43 instance families. Details in [`TESTING.md`](TESTING.md).

## References

- Discovery: [Calif, Java4Shell write-up](https://calif.io/java4shell/)
- [OpenJDK advisory 2026-11-17](https://openjdk.org/groups/vulnerability/advisories/2026-11-17); upstream fix openjdk/jdk `5177a70` (JDK-8393212)
- Why remote scanning can't work: [mazehq.com/blog/java4shell](https://mazehq.com/blog/java4shell)

## License

MIT. See [`LICENSE`](LICENSE).
