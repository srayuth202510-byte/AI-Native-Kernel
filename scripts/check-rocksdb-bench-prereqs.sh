#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

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

detect_libclang_path() {
    for candidate in \
        "${LIBCLANG_PATH:-}" \
        /usr/lib/llvm-21/lib \
        /usr/lib/llvm-20/lib \
        /usr/lib/llvm-19/lib \
        /usr/lib/llvm-18/lib \
        /usr/lib/llvm-17/lib \
        /usr/lib/llvm-16/lib \
        /usr/lib/x86_64-linux-gnu \
        /usr/local/opt/llvm/lib \
        /opt/homebrew/opt/llvm/lib
    do
        if [[ -z "$candidate" ]]; then
            continue
        fi
        if [[ -e "$candidate/libclang.so" || -e "$candidate/libclang.so.1" || -e "$candidate/libclang.dylib" || -n "$(find "$candidate" -maxdepth 1 -name "libclang-*.so*" 2>/dev/null)" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

echo "==> Checking RocksDB warm benchmark prerequisites"

if command -v cargo >/dev/null 2>&1; then
    pass "cargo resolved to: $(command -v cargo)"
else
    fail "cargo not found in PATH"
fi

if command -v rustc >/dev/null 2>&1; then
    pass "rustc resolved to: $(command -v rustc)"
else
    fail "rustc not found in PATH"
fi

if libclang_path="$(detect_libclang_path)"; then
    pass "libclang detected at: ${libclang_path}"
else
    fail "libclang not found; set LIBCLANG_PATH or install a host LLVM/libclang toolchain"
fi

if [[ -d "$PROJECT_ROOT/crates/context-memory/benches" ]]; then
    pass "context-memory benchmark directory present"
else
    fail "missing benchmark directory: $PROJECT_ROOT/crates/context-memory/benches"
fi

if [[ -f "$PROJECT_ROOT/crates/context-memory/benches/rocksdb_bench.rs" ]]; then
    pass "rocksdb benchmark source present"
else
    fail "missing benchmark source: $PROJECT_ROOT/crates/context-memory/benches/rocksdb_bench.rs"
fi

echo
echo "Summary: ${PASS_COUNT} passed, ${WARN_COUNT} warnings, ${FAIL_COUNT} failed"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo
    echo "RocksDB warm benchmark is not ready yet."
    echo "Suggested next steps:"
    echo "  1. Provide libclang and export LIBCLANG_PATH if needed"
    echo "  2. Re-run: scripts/check-rocksdb-bench-prereqs.sh"
    echo "  3. Then run: scripts/run-warm-bench.sh"
    exit 1
fi

echo
echo "RocksDB warm benchmark prerequisites look ready."
