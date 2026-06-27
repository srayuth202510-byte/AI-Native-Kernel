#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

MODE="${1:-companion}"

build() {
    echo "==> Building AI-Native Kernel..."
    rtk cargo build --release 2>&1
}

run_companion() {
    echo "==> Starting AI-Native Kernel Companion Daemon..."
    rtk cargo run --release --bin ank-companion -- "$@"
}

run_cli() {
    echo "==> Starting ANK CLI..."
    rtk cargo run --release --bin ank-cli -- "$@"
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
    build)
        build
        ;;
    *)
        echo "Usage: $0 [companion|cli|build] [args...]"
        echo ""
        echo "  companion  (default) Build & run the companion daemon"
        echo "  cli        Build & run the ANK CLI"
        echo "  build      Build only"
        exit 1
        ;;
esac
