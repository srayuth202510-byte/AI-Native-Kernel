#!/bin/sh

ROOT=/home/lokis/Documents/AI-Native-Kernel

export PATH="$ROOT/.tools/rust-1.96.0/bin:$ROOT/.tools/zig-x86_64-linux-0.16.0:$PATH"
export CARGO_HOME="$ROOT/.cargo-home"
export CC="$ROOT/scripts/zig-cc.sh"
export AR="$ROOT/scripts/zig-ar.sh"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$ROOT/scripts/zig-cc.sh"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$ROOT/scripts/zig-ar.sh"
export GIT_EXEC_PATH="/snap/codex/34/usr/lib/git-core"
