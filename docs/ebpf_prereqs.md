# Real eBPF/LSM Prerequisites

Use this before expecting `kernel-companion` to attach real tracepoints or LSM hooks.

## Quick Check

```bash
./scripts/check-ebpf-prereqs.sh
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
2. Matching Linux headers for the running kernel
3. `bpf_helpers.h` under:
   `/usr/src/linux-headers-$(uname -r)/tools/bpf/resolve_btfids/libbpf/include/bpf/bpf_helpers.h`
4. `clang` with `--target=bpf` support
5. `bpftool`

## Common Ubuntu/Debian Packages

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool linux-headers-$(uname -r)
```

## Runtime Notes

- Real attach often requires `root` or capabilities such as `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_PERFMON`
- LSM attach may still fail if the running kernel does not expose `bpf` in `/sys/kernel/security/lsm`
- If prerequisites are missing, the project falls back to simulation mode by design
