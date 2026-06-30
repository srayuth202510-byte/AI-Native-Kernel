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

normalize_target() {
    local target="$1"
    printf '%s\n' "${target/-unknown-/-}"
}

args=()
while (($#)); do
    case "$1" in
        --target=*)
            args+=("-target" "$(normalize_target "${1#--target=}")")
            shift
            ;;
        --target)
            args+=("-target" "$(normalize_target "$2")")
            shift 2
            ;;
        *)
            args+=("$1")
            shift
            ;;
    esac
done

is_cpp=false
final_args=()
for arg in "${args[@]}"; do
    if [[ "$arg" == "-lstdc++" ]]; then
        is_cpp=true
        final_args+=("-lc++")
    elif [[ "$arg" == "-lc++" ]]; then
        is_cpp=true
        final_args+=("$arg")
    elif [[ "$arg" == *.cc || "$arg" == *.cpp || "$arg" == *.cxx || "$arg" == *.C ]]; then
        is_cpp=true
        final_args+=("$arg")
    else
        final_args+=("$arg")
    fi
done

if [[ "$is_cpp" == "true" ]]; then
    exec "$ZIG" c++ "${final_args[@]}"
else
    exec "$ZIG" cc "${args[@]}"
fi


