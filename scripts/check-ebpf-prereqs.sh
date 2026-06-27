#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

KERNEL_RELEASE="$(uname -r)"
VMLINUX_BTF="/sys/kernel/btf/vmlinux"
BPF_INCLUDE_DIR="/usr/src/linux-headers-${KERNEL_RELEASE}/tools/bpf/resolve_btfids/libbpf/include"
BPF_HELPERS_H="${BPF_INCLUDE_DIR}/bpf/bpf_helpers.h"
LSM_LIST="/sys/kernel/security/lsm"

BPF_SOURCES=(
    "$PROJECT_ROOT/crates/kernel-companion/src/ebpf/syscall-tracer.bpf.c"
    "$PROJECT_ROOT/crates/kernel-companion/src/ebpf/lsm-security.bpf.c"
)

CLANG_CANDIDATES=(
    clang
    clang-18
    clang-17
    /usr/lib/llvm-18/bin/clang
    /usr/lib/llvm-17/bin/clang
    /usr/lib/llvm-16/bin/clang
    /usr/local/bin/clang
)
if [[ -n "${CLANG_BIN:-}" ]]; then
    CLANG_CANDIDATES=("$CLANG_BIN" "${CLANG_CANDIDATES[@]}")
fi

BPFTOOL_CANDIDATES=(
    bpftool
    /usr/sbin/bpftool
    /usr/local/bin/bpftool
)
if [[ -n "${BPFTOOL_BIN:-}" ]]; then
    BPFTOOL_CANDIDATES=("$BPFTOOL_BIN" "${BPFTOOL_CANDIDATES[@]}")
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TMP_DIR=""
CLANG_BIN=""
BPFTOOL_BIN=""

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '[PASS] %s\n' "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '[FAIL] %s\n' "$1"
}

warn() {
    WARN_COUNT=$((WARN_COUNT + 1))
    printf '[WARN] %s\n' "$1"
}

check_file() {
    local path="$1"
    local label="$2"

    if [[ -f "$path" ]]; then
        pass "$label: $path"
    else
        fail "$label missing: $path"
    fi
}

resolve_command() {
    local -n candidates_ref="$1"
    local candidate

    for candidate in "${candidates_ref[@]}"; do
        if [[ -z "$candidate" ]]; then
            continue
        fi
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s\n' "$candidate"
            return 0
        fi
        if [[ -x "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

check_command() {
    local cmd="$1"
    local label="$2"

    if resolved_path="$(command -v "$cmd" 2>/dev/null)"; then
        pass "$label: $resolved_path"
    else
        fail "$label missing from PATH: $cmd"
    fi
}

check_clang_bpf_target() {
    if [[ -z "$CLANG_BIN" ]]; then
        fail "clang BPF target check skipped because clang is missing"
        return
    fi

    if printf '' | "$CLANG_BIN" --target=bpf -dM -E -x c - >/dev/null 2>&1; then
        pass "$CLANG_BIN supports --target=bpf"
    else
        fail "$CLANG_BIN found but does not support --target=bpf"
    fi
}

check_lsm_state() {
    local lsm_contents=""

    if ! lsm_contents="$(cat "$LSM_LIST" 2>/dev/null)"; then
        warn "cannot read $LSM_LIST to confirm active BPF LSM support"
        return
    fi

    if printf '%s' "$lsm_contents" | grep -Eq '(^|,)bpf(,|$)'; then
        pass "active Linux Security Modules include bpf"
    else
        warn "active Linux Security Modules do not list bpf in $LSM_LIST"
    fi
}

check_privileges() {
    if [[ "$(id -u)" -eq 0 ]]; then
        pass "running as root"
    else
        warn "not running as root; real eBPF attach may require root or CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON"
    fi
}

compile_smoke_test() {
    if [[ ! -f "$VMLINUX_BTF" ]]; then
        fail "compile smoke test skipped because $VMLINUX_BTF is missing"
        return
    fi
    if [[ ! -f "$BPF_HELPERS_H" ]]; then
        fail "compile smoke test skipped because $BPF_HELPERS_H is missing"
        return
    fi
    if [[ -z "$CLANG_BIN" ]]; then
        fail "compile smoke test skipped because clang is missing"
        return
    fi
    if [[ -z "$BPFTOOL_BIN" ]]; then
        fail "compile smoke test skipped because bpftool is missing"
        return
    fi

    TMP_DIR="$(mktemp -d)"
    local vmlinux_h="$TMP_DIR/vmlinux.h"

    if "$BPFTOOL_BIN" btf dump file "$VMLINUX_BTF" format c >"$vmlinux_h" 2>"$TMP_DIR/bpftool.stderr"; then
        pass "$BPFTOOL_BIN generated vmlinux.h"
    else
        fail "bpftool failed to generate vmlinux.h"
        sed 's/^/       /' "$TMP_DIR/bpftool.stderr"
        return
    fi

    local src
    for src in "${BPF_SOURCES[@]}"; do
        local stem
        stem="$(basename "$src" .bpf.c)"
        local out_file="$TMP_DIR/${stem}.bpf.o"
        local stderr_file="$TMP_DIR/${stem}.stderr"

        if "$CLANG_BIN" -O2 -target bpf -g -I "$TMP_DIR" -I "$BPF_INCLUDE_DIR" -c "$src" -o "$out_file" \
            > /dev/null 2>"$stderr_file"; then
            pass "compiled $(basename "$src") with $CLANG_BIN -target bpf"
        else
            fail "failed to compile $(basename "$src") with clang -target bpf"
            sed 's/^/       /' "$stderr_file"
        fi
    done
}

print_help() {
    cat <<EOF
AI-Native Kernel real eBPF prerequisite check

Usage:
  $(basename "$0")

Checks:
  - /sys/kernel/btf/vmlinux
  - linux headers with bpf_helpers.h
  - clang presence and --target=bpf support
  - bpftool presence
  - active LSM state (warn-only)
  - privilege level (warn-only)
  - compile smoke test for kernel-companion BPF sources
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_help
    exit 0
fi

echo "==> Checking real eBPF prerequisites for AI-Native Kernel"
echo "    Kernel release: $KERNEL_RELEASE"

if CLANG_BIN="$(resolve_command CLANG_CANDIDATES)"; then
    pass "clang resolved to: $CLANG_BIN"
else
    fail "clang missing from PATH: ${CLANG_CANDIDATES[*]}"
fi

if BPFTOOL_BIN="$(resolve_command BPFTOOL_CANDIDATES)"; then
    pass "bpftool resolved to: $BPFTOOL_BIN"
else
    fail "bpftool missing from PATH: ${BPFTOOL_CANDIDATES[*]}"
fi

check_file "$VMLINUX_BTF" "kernel BTF"
check_file "$BPF_HELPERS_H" "libbpf helper headers"
check_clang_bpf_target
check_lsm_state
check_privileges

for src in "${BPF_SOURCES[@]}"; do
    check_file "$src" "BPF source"
done

compile_smoke_test

echo
echo "Summary: $PASS_COUNT passed, $WARN_COUNT warnings, $FAIL_COUNT failed"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    cat <<EOF

Real eBPF mode is not ready yet.
Suggested next steps:
  1. Install matching linux headers for: $KERNEL_RELEASE
  2. Install clang/llvm with BPF target support
  3. Install bpftool
  4. Ensure /sys/kernel/btf/vmlinux is available
  5. Re-run: scripts/check-ebpf-prereqs.sh
EOF
    exit 1
fi

if [[ "$WARN_COUNT" -gt 0 ]]; then
    cat <<EOF

Prerequisites passed, but there are warnings that may still block real attach at runtime.
EOF
fi

echo
echo "Real eBPF build prerequisites look ready."
