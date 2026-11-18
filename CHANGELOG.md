# Changelog

## 1.0.1 (2026-11-18)

Security fix for port mode. Upgrade if you run `check-port.sh` as root
against JVMs in containers.

- **`check-port.sh` no longer runs `jcmd` from the target's JDK.** In 1.0.0,
  port mode run as root ran the target JVM's own `jcmd` (as the JVM's user)
  to read its flags. For a JVM in a container, that binary came from the
  container's filesystem but ran in the host's namespaces, outside the
  container's isolation (host network, host filesystem, no seccomp or
  AppArmor). A malicious image could use it to run code on the node when a
  defender checked that container. Port mode now only reads files: flags are
  rebuilt from `/proc` (the method host mode already used, which matched
  `jcmd` on every JVM tested on real hardware). Host mode, container mode,
  image mode and the AWS SSM runner were not affected.
- JVMs still running a JDK that was replaced on disk: the running version is
  now read from the old libjvm still mapped in memory (read only, root on the
  host), in both host and port mode. A JVM still running a vulnerable version
  is reported VULNERABLE (with a restart note) instead of RESTART_REQUIRED;
  RESTART_REQUIRED remains when the running version can't be read.

## 1.0.0 (2026-11-18)

First public release.

java4shell-check decides whether a JVM is exploitable through CVE-2026-114938
("Java4Shell") from the three conditions the advisories give:
JDK version × CPU (x86-64 with AVX-512 VBMI) × effective JVM flags. Linux
(x86-64 and ARM64).

- `check-host.sh`: passive inventory of every running JVM on a Linux machine,
  including JVMs in containers. Reads `/proc` only: JDK version and vendor
  from the JDK's `release` file, OpenJ9 detection, effective flags rebuilt
  with the JVM's precedence rules (including `@argfiles` and
  `-XX:VMOptionsFile`), and JVMs still running a JDK that was replaced on disk
  (RESTART_REQUIRED). Starts and attaches to no JVM.
- `check.sh`: the JDK on a machine with the environment's options.
- `check-port.sh <port>` / `--pid <pid>`: the service behind a port. Reads
  effective flags with `jcmd` (run as the process's own user) or rebuilds
  them from `/proc` (see 1.0.1).
- `check-container.sh`: a running Docker container and every JVM in it;
  read-only and shell-less containers are replayed from the same image ID.
- `check-image.sh`: a Docker image, including distroless; detects emulation.
- `report.sh`: one Markdown report from any mix of saved outputs.
- `cloud/aws-sweep.sh`: read-only CPU sweep of an AWS region (EC2 instances
  and EKS node groups) by instance family, using `cloud/instance-cpu-map.csv`:
  candidates, cleared, unknown.
- `cloud/aws-ssm-host-check.sh`: runs `check-host.sh` on the candidates via
  SSM Run Command (dry run by default, `--emit-payload` to review, batches of
  50) and collects every JVM; unreachable instances and incomplete output are
  reported as not checked.
- `AGENTS.md`: a playbook for AI coding agents to run the right checks and
  write the report, with safety rules (no exploit input, change nothing, ask
  before touching other machines, keep results local).
- Single-file release `j4s-check.sh` with subcommands `host`, `port`, `image`,
  `container`, `report`.
- Verdict classes: VULNERABLE (exit 1), RESTART_REQUIRED / PROBABLY_FIXED /
  UNCERTAIN (exit 3), MITIGATED / NOT_VULNERABLE (exit 0); 2 = error.
- Test suite `tests/run.sh` (unit + Docker integration tests); validated on
  real AWS hardware incl. Intel Sapphire Rapids and AMD Zen 4; see TESTING.md.
