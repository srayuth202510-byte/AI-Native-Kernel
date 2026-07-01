#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

INSTALL_DEPS=0

print_help() {
    cat <<EOF
Run the full AI-Native Kernel validation suite on a provisioned host.

Usage:
  $(basename "$0") [--install-deps]

Options:
  --install-deps  Install Debian/Ubuntu eBPF dependencies before validation
  -h, --help      Show this help text

Steps:
  1. Optionally install host dependencies
  2. Detect and export LIBCLANG_PATH if available
  3. Run scripts/run-ci-validations.sh
  4. Run privileged eBPF validation
  5. Run workspace Criterion benches
  6. Run RocksDB warm benchmark validation
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-deps)
            INSTALL_DEPS=1
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_help >&2
            exit 2
            ;;
    esac
    shift
done

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

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

run_step() {
    local description="$1"
    shift

    echo
    echo "==> ${description}"
    "$@"
}

cd "$PROJECT_ROOT"

if [[ "$INSTALL_DEPS" -eq 1 ]]; then
    run_step \
        "Installing host dependencies" \
        bash "$SCRIPT_DIR/install-ebpf-deps.sh" --skip-check
fi

if [[ -z "${LIBCLANG_PATH:-}" ]]; then
    if libclang_path="$(detect_libclang_path)"; then
        export LIBCLANG_PATH="$libclang_path"
        echo
        echo "==> Using LIBCLANG_PATH=${LIBCLANG_PATH}"
    fi
fi

run_step \
    "Running host-side CI validation suite" \
    bash "$SCRIPT_DIR/run-ci-validations.sh"

run_step \
    "Running privileged eBPF validation" \
    bash "$SCRIPT_DIR/run-privileged.sh" bash "$SCRIPT_DIR/run.sh" validate-ebpf

run_step \
    "Running workspace Criterion benches" \
    bash "$SCRIPT_DIR/run-privileged.sh" cargo bench --workspace

run_step \
    "Running RocksDB warm benchmark validation" \
    bash "$SCRIPT_DIR/run.sh" validate-warm-bench

echo
echo "==> Full validation suite completed successfully"
