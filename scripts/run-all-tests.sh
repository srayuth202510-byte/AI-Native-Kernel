#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$PROJECT_ROOT"

DEFAULT_QDRANT_URL="http://localhost:6334"
QDRANT_URL="${QDRANT_URL:-}"

cleanup() {
    if [[ -n "${MOCK_PID:-}" ]]; then
        kill "$MOCK_PID" >/dev/null 2>&1 || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT

_parse_host_port() {
    local url="$1"
    local var_prefix="$2"
    local host_port="${url#http://}"
    host_port="${host_port#https://}"
    host_port="${host_port%%/*}"
    local host="${host_port%:*}"
    local port="${host_port#*:}"
    [[ "$host" == "$port" ]] && port=6334
    [[ "$host" == "$host_port" ]] && port=6334
    printf -v "${var_prefix}_host" "%s" "$host"
    printf -v "${var_prefix}_port" "%s" "$port"
}

_tcp_check() {
    local host="$1" port="$2"
    # bash built-in /dev/tcp (works on most Linux)
    timeout 1 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null && return 0
    # netcat
    command -v nc &>/dev/null && nc -z -w1 "$host" "$port" 2>/dev/null && return 0
    # python3 fallback
    command -v python3 &>/dev/null && python3 -c "
import socket
sock = socket.socket()
sock.settimeout(1)
try:
    sock.connect(('$host', $port))
except:
    exit(1)
finally:
    sock.close()
" 2>/dev/null && return 0
    return 1
}

wait_for_qdrant() {
    local qdrant_url="$1"
    _parse_host_port "$qdrant_url" Q
    _tcp_check "${Q_host}" "${Q_port}"
}

echo "==> Running workspace tests"
cargo test --workspace

if [[ -n "$QDRANT_URL" ]]; then
    echo "==> Using external Qdrant endpoint: ${QDRANT_URL}"
else
    QDRANT_URL="$DEFAULT_QDRANT_URL"
    export QDRANT_URL
    echo "==> QDRANT_URL not set; starting local Qdrant mock at ${QDRANT_URL}"
    cargo run -p context-memory --example qdrant_mock >/tmp/ank-qdrant-mock.log 2>&1 &
    MOCK_PID=$!
fi

export QDRANT_URL

for _ in $(seq 1 30); do
    if [[ -n "${MOCK_PID:-}" ]] && ! kill -0 "$MOCK_PID" 2>/dev/null; then
        echo "Qdrant mock process (PID $MOCK_PID) has exited unexpectedly" >&2
        cat /tmp/ank-qdrant-mock.log 2>/dev/null || true
        exit 1
    fi
    if wait_for_qdrant "$QDRANT_URL"; then
        break
    fi
    sleep 1
done

if ! wait_for_qdrant "$QDRANT_URL"; then
    echo "Qdrant endpoint is not reachable after 30 retries: ${QDRANT_URL}" >&2
    if [[ -n "${MOCK_PID:-}" ]]; then
        echo "Mock PID ${MOCK_PID} is still running but not accepting connections"
    fi
    exit 1
fi

echo "==> Running ignored context-memory tests against ${QDRANT_URL}"
cargo test -p context-memory --lib -- --ignored
