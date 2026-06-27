#!/usr/bin/env bash
set -euo pipefail

ROOT=/home/lokis/Documents/AI-Native-Kernel
ZIG="$ROOT/.tools/zig-x86_64-linux-0.16.0/zig"
ZIG_GLOBAL_CACHE_DIR="$ROOT/.zig-global-cache"
ZIG_LOCAL_CACHE_DIR="$ROOT/.zig-cache"

mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"

exec "$ZIG" ar "$@"
