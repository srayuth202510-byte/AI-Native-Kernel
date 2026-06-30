#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

DRY_RUN=0
RUN_VALIDATIONS=0

print_help() {
    cat <<EOF
Provision a classic Ubuntu/Debian host for AI-Native Kernel validation.

Usage:
  $(basename "$0") [--dry-run] [--run-validations]

Options:
  --dry-run          Print the steps without executing them
  --run-validations  After provisioning, run validate-ebpf and validate-warm-bench
  -h, --help         Show this help text

Default behavior:
  1. Install host packages through scripts/install-ebpf-deps.sh
  2. Detect and export LIBCLANG_PATH for the current shell
  3. Run scripts/check-ebpf-prereqs.sh
  4. Run scripts/check-rocksdb-bench-prereqs.sh
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --run-validations)
            RUN_VALIDATIONS=1
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
        if [[ -e "$candidate/libclang.so" || -e "$candidate/libclang.so.1" || -e "$candidate/libclang.dylib" ]]; then
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

run_validation_step() {
    local description="$1"
    shift

    echo
    echo "==> ${description}"

    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
        return
    fi

    if command -v sudo >/dev/null 2>&1; then
        sudo env "PATH=$PATH" "LIBCLANG_PATH=${LIBCLANG_PATH:-}" "$@"
        return
    fi

    echo "Cannot elevate privileges for: ${description}" >&2
    echo "Re-run as root or install sudo on the validation host." >&2
    exit 1
}

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "==> Dry run: classic Ubuntu/Debian validation host bootstrap"
    echo "  bash scripts/install-ebpf-deps.sh --dry-run --skip-check"
    echo "  bash scripts/check-ebpf-prereqs.sh"
    echo "  bash scripts/check-rocksdb-bench-prereqs.sh"
    if [[ "$RUN_VALIDATIONS" -eq 1 ]]; then
        echo "  sudo env PATH=\"\$PATH\" LIBCLANG_PATH=\"<detected>\" ./scripts/run.sh validate-ebpf"
        echo "  ./scripts/run.sh validate-warm-bench"
    fi
    exit 0
fi

cd "$PROJECT_ROOT"

run_step \
    "Installing host dependencies for eBPF and warm benchmark validation" \
    bash "$SCRIPT_DIR/install-ebpf-deps.sh" --skip-check

if libclang_path="$(detect_libclang_path)"; then
    export LIBCLANG_PATH="$libclang_path"
    echo
    echo "==> Using LIBCLANG_PATH=${LIBCLANG_PATH}"
else
    echo
    echo "==> libclang was not auto-detected after package install" >&2
    echo "Set LIBCLANG_PATH manually before running warm benchmark validation." >&2
fi

run_step \
    "Checking eBPF host prerequisites" \
    bash "$SCRIPT_DIR/check-ebpf-prereqs.sh"

run_step \
    "Checking rocksdb warm benchmark prerequisites" \
    bash "$SCRIPT_DIR/check-rocksdb-bench-prereqs.sh"

if [[ "$RUN_VALIDATIONS" -eq 1 ]]; then
    run_validation_step \
        "Running privileged eBPF validation" \
        "$PROJECT_ROOT/scripts/run.sh" validate-ebpf

    run_step \
        "Running rocksdb warm benchmark validation" \
        "$PROJECT_ROOT/scripts/run.sh" validate-warm-bench
else
    echo
    echo "==> Host bootstrap completed"
    echo "Next steps:"
    echo "  ./scripts/run.sh validate-ebpf"
    echo "  ./scripts/run.sh validate-warm-bench"
fi
