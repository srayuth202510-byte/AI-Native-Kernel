# Real eBPF/LSM Prerequisites

Use this before expecting `kernel-companion` to attach real tracepoints or LSM hooks.

## Quick Check

```bash
./scripts/check-ebpf-prereqs.sh
```

## Privileged Attach Validation (fail-closed)

Confirms the companion attaches **real** eBPF/LSM into the kernel with simulation
fallback disabled — not just that the build prerequisites exist. It boots the
daemon with `--no-bpf-fallback`, scrapes the metrics endpoint until both the
syscall tracer and LSM hook report `ank_ebpf_active_mode{mode="real"} 1`, then
shuts down and prints PASS/FAIL.

```bash
sudo ./scripts/validate-ebpf-attach.sh
# options: --metrics-port N   --timeout SECS   --skip-prereqs   --binary PATH
```

Exit code `0` means real attach was validated. On a host without privileges or
kernel prerequisites it exits non-zero — which is correct: with fallback
disabled the daemon must refuse to run enforcement in userspace simulation
(this applies to **both** the tracer and the LSM hook).

For a full privileged validation pass on a host with the required kernel capabilities:

```bash
./scripts/run.sh validate-ebpf
```

Or:

```bash
./scripts/run.sh prereqs
```

## Install on Ubuntu/Debian

```bash
./scripts/install-ebpf-deps.sh
```

Dry run:

```bash
./scripts/install-ebpf-deps.sh --dry-run
```

Or via the project wrapper:

```bash
./scripts/run.sh install-prereqs
```

The script mirrors the checks used by `crates/kernel-companion/build.rs` and also runs a compile smoke test for:

- `crates/kernel-companion/src/ebpf/syscall-tracer.bpf.c`
- `crates/kernel-companion/src/ebpf/lsm-security.bpf.c`

## Required Items

1. Kernel BTF available at `/sys/kernel/btf/vmlinux`
2. `bpf/bpf_helpers.h` from either matching kernel headers or a host package such as `libbpf-dev`
3. `clang` with `--target=bpf` support
4. `bpftool`

## Common Ubuntu/Debian Packages

```bash
./scripts/install-ebpf-deps.sh
```

If you need the manual equivalent, install `clang`, `llvm`, `libclang-dev`, `libbpf-dev`, `libelf-dev`,
matching `linux-headers-$(uname -r)`, and whichever installable package on your distro
provides `bpftool`. On Ubuntu 24.04 this may be a provider such as `linux-tools-common`
rather than a concrete `bpftool` package.

## Runtime Notes

- Real attach often requires `root` or capabilities such as `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_PERFMON`
- LSM attach may still fail if the running kernel does not expose `bpf` in `/sys/kernel/security/lsm`
- If prerequisites are missing, the project falls back to simulation mode by design. The daemon runs **automated pre-flight diagnostics** at startup to determine the recommended mode and prints actionable remediation logs if checks fail.
- When capability security is active, command communication over UDS uses **Zero-Trust Token Authorization**. The client tools (`ank-cli` and `ank-tui`) automatically load session credentials from `$XDG_RUNTIME_DIR/ank/session.token` (or `/tmp/ank-session-{uid}.token` fallback) to complete the cryptographic `auth` handshake.
