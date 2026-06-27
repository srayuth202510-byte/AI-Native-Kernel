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

wait_for_qdrant() {
    local qdrant_url="$1"
    QDRANT_URL="$qdrant_url" python3 - <<'PY' >/dev/null 2>&1
import os
import socket
from urllib.parse import urlparse

url = os.environ["QDRANT_URL"]
parsed = urlparse(url)
host = parsed.hostname or "localhost"
port = parsed.port or 6334

sock = socket.socket()
try:
    sock.settimeout(0.2)
    sock.connect((host, port))
finally:
    sock.close()
PY
}

if [[ -n "$QDRANT_URL" ]]; then
    echo "==> Using external Qdrant endpoint: ${QDRANT_URL}"
else
    QDRANT_URL="$DEFAULT_QDRANT_URL"
    echo "==> QDRANT_URL not set; starting local Qdrant mock at ${QDRANT_URL}"
    cargo run -p context-memory --example qdrant_mock >/tmp/ank-qdrant-mock.log 2>&1 &
    MOCK_PID=$!
fi

export QDRANT_URL

for _ in $(seq 1 30); do
    if wait_for_qdrant "$QDRANT_URL"; then
        break
    fi
    sleep 1
done

if ! wait_for_qdrant "$QDRANT_URL"; then
    echo "Qdrant endpoint is not reachable: ${QDRANT_URL}" >&2
    exit 1
fi

echo "==> Running context-memory ignored tests against ${QDRANT_URL}"
cargo test -p context-memory --lib -- --ignored
