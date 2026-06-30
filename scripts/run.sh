#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

MODE="${1:-companion}"

if command -v rtk >/dev/null 2>&1; then
    RTK=(rtk)
elif [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
    RTK=()
else
    RTK=()
fi

build() {
    echo "==> Building AI-Native Kernel..."
    bash "$SCRIPT_DIR/build-ebpf-objects.sh" || echo "==> eBPF object prebuild failed; continuing with simulation fallback"
    "${RTK[@]}" cargo build --release 2>&1
}

run_companion() {
    echo "==> Starting AI-Native Kernel Companion Daemon..."
    "${RTK[@]}" cargo run --release --bin kernel-companion -- "$@"
}

run_cli() {
    echo "==> Starting ANK CLI..."
    "${RTK[@]}" cargo run --release --bin ank-cli -- "$@"
}

run_tui() {
    echo "==> Starting ANK TUI Dashboard..."
    "${RTK[@]}" cargo run --release --bin ank-tui -- "$@"
}

check_prereqs() {
    echo "==> Checking real eBPF prerequisites..."
    "$SCRIPT_DIR/check-ebpf-prereqs.sh"
}

validate_ebpf() {
    echo "==> Validating privileged eBPF/LSM attach path..."
    "$SCRIPT_DIR/check-ebpf-prereqs.sh"
    "${RTK[@]}" cargo test -p kernel-companion --lib validate_lsm_hooks_attach_to_kernel -- --nocapture
    "${RTK[@]}" cargo test -p kernel-companion --lib validate_tracepoint_attach_to_kernel -- --nocapture
}

install_prereqs() {
    echo "==> Installing real eBPF prerequisites..."
    "$SCRIPT_DIR/install-ebpf-deps.sh" "$@"
}

case "$MODE" in
    companion)
        build
        shift 2>/dev/null || true
        run_companion "$@"
        ;;
    cli)
        build
        shift 2>/dev/null || true
        run_cli "$@"
        ;;
    tui)
        build
        shift 2>/dev/null || true
        run_tui "$@"
        ;;
    build)
        build
        ;;
    prereqs)
        check_prereqs
        ;;
    validate-ebpf)
        validate_ebpf
        ;;
    install-prereqs)
        shift 2>/dev/null || true
        install_prereqs "$@"
        ;;
    *)
        echo "Usage: $0 [companion|cli|tui|build|prereqs|validate-ebpf|install-prereqs] [args...]"
        echo ""
        echo "  companion  (default) Build & run the companion daemon"
        echo "  cli        Build & run the ANK CLI"
        echo "  tui        Build & run the TUI dashboard"
        echo "  build      Build only"
        echo "  prereqs    Check real eBPF/LSM prerequisites"
        echo "  validate-ebpf  Run prereq checks and privileged kernel attach tests"
        echo "  install-prereqs  Install real eBPF/LSM dependencies on Debian/Ubuntu"
        exit 1
        ;;
esac
