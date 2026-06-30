#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$PROJECT_ROOT"

echo "==> Checking RocksDB warm benchmark prerequisites..."
"$SCRIPT_DIR/check-rocksdb-bench-prereqs.sh"

echo
echo "==> Pre-compiling rocksdb warm benchmark..."
cargo bench -p context-memory --bench rocksdb_bench --features rocksdb-warm --no-run

echo
echo "==> Running rocksdb warm benchmark..."
cargo bench -p context-memory --bench rocksdb_bench --features rocksdb-warm
