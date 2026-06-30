#!/bin/sh

if [ -n "${BASH_SOURCE:-}" ]; then
    TOOLCHAIN_SOURCE="${BASH_SOURCE[0]}"
else
    TOOLCHAIN_SOURCE="$0"
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$TOOLCHAIN_SOURCE")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
ZIG_BUNDLE="$ROOT/.tools/zig-x86_64-linux-0.16.0/zig"

if [ -d "$ROOT/.tools/rust-1.96.0/bin" ]; then
    export PATH="$ROOT/.tools/rust-1.96.0/bin:$PATH"
fi
if [ -x "$ZIG_BUNDLE" ]; then
    export PATH="$ROOT/.tools/zig-x86_64-linux-0.16.0:$PATH"
fi
if [ -d "$ROOT/.cargo-home" ] || mkdir -p "$ROOT/.cargo-home" 2>/dev/null; then
    export CARGO_HOME="$ROOT/.cargo-home"
fi

if [ -x "$ZIG_BUNDLE" ]; then
    export CC="$ROOT/scripts/zig-cc.sh"
    export AR="$ROOT/scripts/zig-ar.sh"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$ROOT/scripts/zig-cc.sh"
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR="$ROOT/scripts/zig-ar.sh"
else
    export CC="${CC:-clang}"
    export AR="${AR:-ar}"
    unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER
    unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_AR
fi

if [ -d "/snap/codex/34/usr/lib/git-core" ]; then
    export GIT_EXEC_PATH="/snap/codex/34/usr/lib/git-core"
fi

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
