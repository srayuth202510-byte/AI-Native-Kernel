#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
ZIG="$ROOT/.tools/zig-x86_64-linux-0.16.0/zig"
ZIG_GLOBAL_CACHE_DIR="$ROOT/.zig-global-cache"
ZIG_LOCAL_CACHE_DIR="$ROOT/.zig-cache"

mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
export ZIG_GLOBAL_CACHE_DIR
export ZIG_LOCAL_CACHE_DIR

exec "$ZIG" ar "$@"
