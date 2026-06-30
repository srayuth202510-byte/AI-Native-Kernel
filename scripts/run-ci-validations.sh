#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$PROJECT_ROOT"

echo "==> CI validation: formatting"
cargo fmt --all -- --check

echo
echo "==> CI validation: clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo
echo "==> CI validation: workspace + Qdrant-backed tests"
bash "$SCRIPT_DIR/run-all-tests.sh"

echo
echo "==> CI validation: P2P mesh slice"
bash "$SCRIPT_DIR/run-p2p-tests.sh"

echo
echo "==> CI validation: eBPF prerequisite check"
bash "$SCRIPT_DIR/check-ebpf-prereqs.sh"

echo
echo "==> CI validation: rocksdb warm prereq check"
bash "$SCRIPT_DIR/check-rocksdb-bench-prereqs.sh"

echo
echo "==> CI validation: rocksdb warm benchmark compile"
cargo bench -p context-memory --bench rocksdb_bench --features rocksdb-warm --no-run

echo
echo "==> CI validation: release build"
cargo build --release
