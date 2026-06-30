# Host Provisioning for Validation

Use this when the repo is running inside Ubuntu Core or another environment that cannot
install the required host packages directly.

This runbook provisions a host that can run:

- `./scripts/run.sh validate-ebpf`
- `./scripts/run.sh validate-warm-bench`

## Current Constraint

This workspace is currently running on:

```text
Ubuntu Core 24
```

`scripts/install-ebpf-deps.sh` does not install packages on Ubuntu Core because the base
system does not provide `apt-get`.

## Required Host Tools

For full validation, the host must provide:

- `clang`
- `llvm`
- `libclang`
- `bpftool`
- matching `linux-headers-$(uname -r)`
- `/sys/kernel/btf/vmlinux`
- privilege to attach eBPF/LSM programs

## Option 1: Classic Ubuntu/Debian Host

Run these commands on a classic host shell, container, or chroot that has `apt-get`:

```bash
sudo apt-get update
sudo apt-get install -y \
  clang \
  llvm \
  libclang-dev \
  bpftool \
  linux-headers-$(uname -r)
```

Then verify:

```bash
./scripts/check-ebpf-prereqs.sh
./scripts/check-rocksdb-bench-prereqs.sh
```

If both pass, run:

```bash
./scripts/run.sh validate-ebpf
./scripts/run.sh validate-warm-bench
```

## Option 2: Manually Provisioned LLVM Toolchain

If you cannot use `apt-get`, provide a host toolchain manually and export these paths:

```bash
export PATH="/path/to/llvm/bin:/path/to/bpftool/bin:$PATH"
export LIBCLANG_PATH="/path/to/libclang/lib"
```

Minimum checks:

```bash
command -v clang
command -v bpftool
test -e "$LIBCLANG_PATH/libclang.so" || test -e "$LIBCLANG_PATH/libclang.so.1"
```

Then run:

```bash
./scripts/check-ebpf-prereqs.sh
./scripts/check-rocksdb-bench-prereqs.sh
```

## Option 3: Privileged Validation Host

`validate-ebpf` needs more than build tools. The host also needs:

- root, or equivalent `CAP_BPF`, `CAP_SYS_ADMIN`, and `CAP_PERFMON`
- a kernel with BPF LSM support exposed to the running environment
- readable `/sys/kernel/security/lsm` and `/sys/kernel/btf/vmlinux`

The warm benchmark does not need kernel privileges, but it does need `libclang` because
`rocksdb-warm` builds through `bindgen`.

## Expected Success State

`validate-ebpf` is ready when:

- `./scripts/check-ebpf-prereqs.sh` reports no failures
- `./scripts/run.sh validate-ebpf` reaches the attach tests instead of failing at prereqs

`validate-warm-bench` is ready when:

- `./scripts/check-rocksdb-bench-prereqs.sh` reports no failures
- `./scripts/run.sh validate-warm-bench` reaches the benchmark run instead of failing in `bindgen`

## Known Blockers on This Workspace

At the time of writing, this environment is missing:

- `clang`
- `bpftool`
- `libclang`
- privileged eBPF attach capabilities

That means code changes alone will not complete the remaining host validation work from
inside this Ubuntu Core workspace.
