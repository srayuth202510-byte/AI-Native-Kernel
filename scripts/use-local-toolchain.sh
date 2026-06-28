#!/bin/sh

ROOT=/home/lokis/Documents/AI-Native-Kernel

export PATH="$ROOT/.tools/rust-1.96.0/bin:$ROOT/.tools/zig-x86_64-linux-0.16.0:$PATH"
export CARGO_HOME="$ROOT/.cargo-home"
export CC="$ROOT/scripts/zig-cc.sh"
export AR="$ROOT/scripts/zig-ar.sh"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$ROOT/scripts/zig-cc.sh"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$ROOT/scripts/zig-ar.sh"
export GIT_EXEC_PATH="/snap/codex/34/usr/lib/git-core"

detect_libclang_path() {
    for candidate in \
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
        if [ -e "$candidate/libclang.so" ] || [ -e "$candidate/libclang.so.1" ] || [ -e "$candidate/libclang.dylib" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

if [ -z "${LIBCLANG_PATH:-}" ]; then
    if libclang_path="$(detect_libclang_path)"; then
        export LIBCLANG_PATH="$libclang_path"
    fi
fi
