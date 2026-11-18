# Testing

## Run the tests

```sh
tests/run.sh          # unit tests + Docker integration tests
tests/run.sh --unit   # unit tests only (no Docker needed)
```

The integration tests run every mode against real JDK images on the local
Docker daemon. The CPU is simulated so the results are the same on any
Docker host, x86-64 or ARM: a Linux `/proc/cpuinfo` with the AVX-512 VBMI
flags is bind-mounted into the containers and `J4S_TEST_ARCH=x86_64` makes
the tool treat the machine as x86-64. Every container the suite starts is
labelled `j4s-test` and removed at the end.

## What the suite covers

**Unit tests** (pass under bash, dash, busybox sh and Amazon Linux sh):

- Version classification: every affected range boundary, Oracle `.0.3`
  builds, the Java 8 `-perf` build, patch-level "probably fixed" builds,
  JDK 18–20, EOL 22–24 and 26, early-access builds, OpenJ9, and
  `Picked up JAVA_TOOL_OPTIONS` lines that must not influence the result.
- Flag parsing: intrinsic off, `UseAVX<=2`, `-Xint`, `TieredStopAtLevel`,
  defaults, unreadable flags.
- CPU evaluation: x86-64 with and without AVX-512 VBMI, ARM, an ARM machine
  whose `/proc/cpuinfo` claims x86 flags (ignored), other architectures.
- The verdict engine for every combination of version, CPU and flags.
- JDK home detection (JDK 8, 9+, OpenJ9), output sanitising, secret
  redaction, and `report.sh` (counting, container de-duplication, escaping
  of Markdown/HTML in fields, rows for instances without a result, empty
  input).
- `cloud/aws-ssm-host-check.sh` end to end against a fake `aws` CLI
  (`tests/fixtures/aws`): paginated status output, result collection, a
  truncated node (reported as incomplete, its complete rows kept), an
  unreachable instance, and a failing instance listing (an error, not
  "unreachable"). Needs python3 or jq.

**Integration tests** (real JDK images: Temurin 17.0.5, 17.0.6 and 21.0.13,
IBM Semeru 21, distroless Java 21):

- `check.sh`: vulnerable, CPU without VBMI, `-XX:-UseBASE64Intrinsics`,
  `-Xint`, JRE images, a version without the code, OpenJ9, and the real CPU
  of the test host.
- `check-port.sh`: default flags, `-` then `+` (not mitigated), `-`
  (mitigated), `_JAVA_OPTIONS` overriding the command line, mitigation via
  `JAVA_TOOL_OPTIONS`, OpenJ9, `jcmd` run as the owner of a non-root JVM,
  and a process that spoofs `argv[0]` to make the checker run a planted
  binary (it never runs).
- `check-host.sh` on one host with ten JVM containers: all of the above
  plus `@argfile`, `--enable-native-access`, tab-separated
  `JAVA_TOOL_OPTIONS`, an environment variable whose value smuggles a fake
  `_JAVA_OPTIONS` line (ignored), a mitigation flag placed after the main
  class in an argument file (ignored, as the JVM does), and a JDK replaced on
  disk under a running JVM (RESTART_REQUIRED).
- `check-container.sh`: a vulnerable container, a read-only container
  (replayed via image mode), a non-root container; the tool's copy is removed
  every time.
- `check-image.sh`: a version without the code, a distroless image.

Also verified by hand while building: the single-file release
(`j4s-check.sh`, all subcommands) on Alpine and busybox with matching
`SHA256SUMS.txt`; `check-image.sh` detecting emulation (amd64 image on an
arm64 Docker host); every flag-source case cross-checked against
`jcmd <pid> VM.flags -all`.

## Real hardware (AWS)

Run on real EC2 instances (test instances, torn down
afterwards), through `cloud/aws-ssm-host-check.sh`:

- **63 JVMs on 4 real nodes**, in containers, covering every verdict class.
  The tool found all of them, and every version, effective flag and verdict
  matched what each JVM reported about itself (`jcmd VM.info` /
  `VM.flags`).
- **AVX-512 VBMI hardware:** Intel Sapphire Rapids (`m7i`, Xeon 8488C) and
  AMD Zen 4 (`c7a`, EPYC 9R14). Both read as able to run the vulnerable
  code, and every VULNERABLE verdict belonged to a JVM whose own CPU feature
  list included `avx512_vbmi` with the intrinsic enabled.
- **Negative controls:** the same JDKs on `c6a` (AMD Zen 3, no AVX-512) and
  `t4g` (ARM) were correctly cleared.
- **CPU map:** one instance of each of 43 instance families. The tool's CPU
  reading matched the raw `/proc/cpuinfo` on all 43; the map matched on 42
  and the 43rd (`unknown`, the safe default) has been corrected since.
- The SSM pipeline (send, run inline on the node, collect, report) end to
  end; two bugs found at fleet size (paginated status output; a hidden
  listing failure) are fixed and covered by the fake-aws tests above.

Not covered: no exploit was ever sent (by design). Instance families that
ship on more than one CPU generation were probed once each; every
generation listed for them in the map predates Ice Lake / Zen 4. GPU,
Inferentia/Trainium and mac families were not probed.

## Static checks

shellcheck (severity warning) is clean on every script.
