#!/usr/bin/env bash
#
# validate-ebpf-attach.sh — ยืนยัน "real eBPF privileged attach" แบบ end-to-end
#
# ต่างจาก check-ebpf-prereqs.sh (ตรวจแค่ว่า build/attach *มีโอกาส* สำเร็จ):
# script นี้ boot companion daemon ด้วย --no-bpf-fallback (ปิด simulation)
# แล้ว scrape metrics endpoint เพื่อยืนยันว่า tracer + lsm attach เข้า kernel
# จริง (mode="real") ไม่ใช่ degrade ไป simulation — จากนั้น shutdown สะอาด
# และรายงาน PASS/FAIL พร้อม exit code (0 = attach จริงยืนยันแล้ว)
#
# ต้องรันบน host ที่มีสิทธิ์ (root / CAP_BPF+CAP_SYS_ADMIN+CAP_PERFMON) และ
# kernel prerequisites ครบ — รันใน 環境 ที่ไม่มีสิทธิ์จะ FAIL อย่างถูกต้อง
#
# Usage:
#   sudo scripts/validate-ebpf-attach.sh
#   sudo scripts/validate-ebpf-attach.sh --metrics-port 9099 --timeout 30
#   scripts/validate-ebpf-attach.sh --skip-prereqs        # ข้ามการตรวจ prereq
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

METRICS_PORT=9090
TIMEOUT_SECS=30
SKIP_PREREQS=0
BINARY="${ANK_COMPANION_BIN:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --metrics-port) METRICS_PORT="$2"; shift 2 ;;
        --timeout)      TIMEOUT_SECS="$2"; shift 2 ;;
        --skip-prereqs) SKIP_PREREQS=1; shift ;;
        --binary)       BINARY="$2"; shift 2 ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

METRICS_URL="http://127.0.0.1:${METRICS_PORT}/metrics"
DAEMON_PID=""
LOG_FILE="$(mktemp -t ank-ebpf-validate.XXXXXX.log)"

cleanup() {
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$DAEMON_PID" 2>/dev/null || break
            sleep 0.25
        done
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$LOG_FILE"
}
trap cleanup EXIT

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; }
info() { echo "[INFO] $1"; }

echo "==> eBPF privileged attach validation"
echo "    kernel: $(uname -r)  metrics: ${METRICS_URL}  timeout: ${TIMEOUT_SECS}s"

# 1. Pre-flight: prerequisites -----------------------------------------------
if [[ "$SKIP_PREREQS" -eq 0 ]]; then
    info "running prerequisite check (scripts/check-ebpf-prereqs.sh)"
    if ! "$SCRIPT_DIR/check-ebpf-prereqs.sh"; then
        fail "prerequisites not satisfied — install missing deps or pass --skip-prereqs to bypass"
        exit 1
    fi
fi

# 2. Privilege check ----------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]] && ! capsh --print 2>/dev/null | grep -q 'cap_bpf'; then
    fail "not root and CAP_BPF not present — real attach requires privileges"
    exit 1
fi

# 3. Locate / build the companion binary -------------------------------------
if [[ -z "$BINARY" ]]; then
    BINARY="$PROJECT_ROOT/target/release/kernel-companion"
    if [[ ! -x "$BINARY" ]]; then
        info "release binary not found — building (cargo build --release -p kernel-companion)"
        (cd "$PROJECT_ROOT" && cargo build --release -p kernel-companion)
    fi
fi
[[ -x "$BINARY" ]] || { fail "companion binary not found at: $BINARY"; exit 1; }
info "binary: $BINARY"

# 4. Boot the daemon with simulation fallback DISABLED ------------------------
info "booting companion with --no-bpf-fallback"
"$BINARY" --no-bpf-fallback --metrics-addr "127.0.0.1:${METRICS_PORT}" \
    >"$LOG_FILE" 2>&1 &
DAEMON_PID=$!

# 5. Poll metrics until real mode confirmed, daemon dies, or timeout ---------
tracer_real=0
lsm_real=0
deadline=$(( $(date +%s) + TIMEOUT_SECS ))

while [[ "$(date +%s)" -lt "$deadline" ]]; do
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        fail "daemon exited before confirming real attach (fallback disabled = attach failed)"
        echo "----- daemon log (tail) -----"
        tail -n 20 "$LOG_FILE" || true
        exit 1
    fi

    metrics="$(curl -fs --max-time 2 "$METRICS_URL" 2>/dev/null || true)"
    if [[ -n "$metrics" ]]; then
        # ank_ebpf_active_mode{component="tracer",mode="real"} 1
        if grep -Eq 'ank_ebpf_active_mode\{[^}]*component="tracer"[^}]*mode="real"[^}]*\} 1' <<<"$metrics"; then
            tracer_real=1
        fi
        if grep -Eq 'ank_ebpf_active_mode\{[^}]*component="lsm"[^}]*mode="real"[^}]*\} 1' <<<"$metrics"; then
            lsm_real=1
        fi
        [[ "$tracer_real" -eq 1 && "$lsm_real" -eq 1 ]] && break
    fi
    sleep 1
done

# 6. Report -------------------------------------------------------------------
echo "----- results -----"
[[ "$tracer_real" -eq 1 ]] && pass "syscall tracer attached in REAL mode" \
                           || fail "syscall tracer did NOT reach real mode"
[[ "$lsm_real" -eq 1 ]]    && pass "LSM hook attached in REAL mode" \
                           || fail "LSM hook did NOT reach real mode"

if [[ "$tracer_real" -eq 1 && "$lsm_real" -eq 1 ]]; then
    echo
    echo "==> PASS — real eBPF/LSM attach validated (fallback disabled)"
    exit 0
fi

echo
echo "==> FAIL — real attach not confirmed within ${TIMEOUT_SECS}s"
echo "----- daemon log (tail) -----"
tail -n 20 "$LOG_FILE" || true
exit 1
