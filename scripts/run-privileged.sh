#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: $(basename "$0") <command> [args...]" >&2
    exit 2
fi

if [[ "$(id -u)" -eq 0 ]]; then
    exec "$@"
fi

if ! command -v sudo >/dev/null 2>&1; then
    echo "This command requires root or passwordless sudo: $*" >&2
    exit 1
fi

exec sudo env \
    "PATH=$PATH" \
    "HOME=${HOME:-}" \
    "CARGO_HOME=${CARGO_HOME:-}" \
    "RUSTUP_HOME=${RUSTUP_HOME:-}" \
    "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-}" \
    "LIBCLANG_PATH=${LIBCLANG_PATH:-}" \
    "BPF_INCLUDE_DIR=${BPF_INCLUDE_DIR:-}" \
    "CLANG_BIN=${CLANG_BIN:-}" \
    "BPFTOOL_BIN=${BPFTOOL_BIN:-}" \
    "$@"
