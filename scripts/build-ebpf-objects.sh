#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CRATE_DIR="$PROJECT_ROOT/crates/kernel-companion"
OUT_DIR="$CRATE_DIR/target/bpf"

VMLINUX_BTF="/sys/kernel/btf/vmlinux"
CLANG_BIN="${CLANG_BIN:-clang}"
BPFTOOL_BIN="${BPFTOOL_BIN:-bpftool}"
BPF_INCLUDE_DIR="${BPF_INCLUDE_DIR:-}"

resolve_bpf_include_dir() {
    local kernel_release
    kernel_release="$(uname -r)"
    local candidates=(
        "$BPF_INCLUDE_DIR"
        "/usr/src/linux-headers-${kernel_release}/tools/bpf/resolve_btfids/libbpf/include"
        "/usr/src/linux-headers-${kernel_release}/tools/lib/bpf"
        "/usr/include"
        "/usr/local/include"
        "/opt/homebrew/include"
    )
    local candidate

    for candidate in "${candidates[@]}"; do
        if [[ -z "$candidate" ]]; then
            continue
        fi
        if [[ -f "${candidate}/bpf/bpf_helpers.h" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

# Resolve clang — if missing, fall back to prebuilt objects
if [[ "$CLANG_BIN" == /* ]]; then
    if [[ ! -x "$CLANG_BIN" ]]; then
        echo "clang is not executable: $CLANG_BIN — using prebuilt objects" >&2
        exit 0
    fi
else
    if ! CLANG_BIN="$(command -v "$CLANG_BIN" 2>/dev/null)"; then
        echo "clang not found — using prebuilt objects" >&2
        exit 0
    fi
fi

# Resolve bpftool — if missing, fall back to prebuilt objects
if [[ "$BPFTOOL_BIN" == /* ]]; then
    if [[ ! -x "$BPFTOOL_BIN" ]]; then
        echo "bpftool is not executable: $BPFTOOL_BIN — using prebuilt objects" >&2
        exit 0
    fi
else
    if ! BPFTOOL_BIN="$(command -v "$BPFTOOL_BIN" 2>/dev/null)"; then
        echo "bpftool not found — using prebuilt objects" >&2
        exit 0
    fi
fi

if [[ ! -f "$VMLINUX_BTF" ]]; then
    echo "Missing kernel BTF: $VMLINUX_BTF — using prebuilt objects" >&2
    exit 0
fi

if ! BPF_INCLUDE_DIR="$(resolve_bpf_include_dir)"; then
    echo "Missing BPF helper headers — using prebuilt objects" >&2
    exit 0
fi

mkdir -p "$OUT_DIR"

vmlinux_h="$OUT_DIR/vmlinux.h"
"$BPFTOOL_BIN" btf dump file "$VMLINUX_BTF" format c >"$vmlinux_h"

for src in \
    "$CRATE_DIR/src/ebpf/syscall-tracer.bpf.c" \
    "$CRATE_DIR/src/ebpf/lsm-security.bpf.c"
do
    stem="$(basename "$src" .bpf.c)"
    out_file="$OUT_DIR/${stem}.bpf.o"
    "$CLANG_BIN" -O2 -target bpf -g -I "$OUT_DIR" -I "$BPF_INCLUDE_DIR" -c "$src" -o "$out_file"
done

echo "Built eBPF objects in $OUT_DIR"
