#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SUMMARY_PATH="$PROJECT_ROOT/target/ci-validation-summary.md"

if [[ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$PROJECT_ROOT"
mkdir -p "$(dirname "$SUMMARY_PATH")"

declare -a STAGE_NAMES=()
declare -a STAGE_STATUS=()
declare -a STAGE_CODES=()
declare -a STAGE_SECONDS=()

FAIL_COUNT=0
NON_BLOCKING_FAIL_COUNT=0

# Per-stage timeout (seconds). Override per-stage with:
#   CI_STAGE_TIMEOUT_SECS=300 run_stage "name" ...
# Without `timeout(1)` this is a no-op. Prevents a single hung cargo/test
# step from burning the whole 6h GitHub job timeout with zero artifacts.
HAVE_TIMEOUT=0
if command -v timeout >/dev/null 2>&1; then
    HAVE_TIMEOUT=1
fi

run_stage() {
    local stage_name="$1"
    local blocking_mode="${2:-required}"
    if [[ "$blocking_mode" == "required" || "$blocking_mode" == "non-blocking" ]]; then
        shift 2
    else
        blocking_mode="required"
        shift 1
    fi
    local stage_timeout="${CI_STAGE_TIMEOUT_SECS:-1200}"

    echo "==> CI validation: ${stage_name} (timeout ${stage_timeout}s, mode ${blocking_mode})"

    local started_at
    started_at="$(date +%s)"

    set +e
    if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then
        timeout "$stage_timeout" "$@"
    else
        "$@"
    fi
    local exit_code=$?
    set -e

    if [[ "$exit_code" -eq 124 ]]; then
        echo "!! Stage '${stage_name}' timed out after ${stage_timeout}s (timeout exit 124)" >&2
    fi

    local finished_at
    finished_at="$(date +%s)"
    local elapsed=$((finished_at - started_at))

    STAGE_NAMES+=("$stage_name")
    STAGE_CODES+=("$exit_code")
    STAGE_SECONDS+=("$elapsed")

    if [[ "$exit_code" -eq 0 ]]; then
        STAGE_STATUS+=("PASS")
    elif [[ "$blocking_mode" == "non-blocking" ]]; then
        STAGE_STATUS+=("WARN")
        NON_BLOCKING_FAIL_COUNT=$((NON_BLOCKING_FAIL_COUNT + 1))
    else
        STAGE_STATUS+=("FAIL")
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    # Incremental summary: if the job is SIGKILLed later (GitHub timeout),
    # the artifact upload still finds a file with completed stages.
    write_summary_file "$FAIL_COUNT"

    echo
}

write_summary_file() {
    local failed_or_exit="$1"
    local overall_status="PASS (in progress)"

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        overall_status="FAIL (in progress)"
    elif [[ "$NON_BLOCKING_FAIL_COUNT" -gt 0 ]]; then
        overall_status="PASS with warnings (in progress)"
    fi
    # Called with final exit code from finalize(): render terminal state.
    if [[ "${FINALIZING:-0}" -eq 1 ]]; then
        overall_status="PASS"
        if [[ "$FAIL_COUNT" -gt 0 || "$failed_or_exit" -ne 0 ]]; then
            overall_status="FAIL"
        elif [[ "$NON_BLOCKING_FAIL_COUNT" -gt 0 ]]; then
            overall_status="PASS (with warnings)"
        fi
    fi

    {
        echo "# CI Validation Summary"
        echo
        echo "- Overall: ${overall_status}"
        echo "- Failed stages: ${FAIL_COUNT}"
        echo "- Non-blocking stage warnings: ${NON_BLOCKING_FAIL_COUNT}"
        echo
        echo "| Stage | Status | Exit Code | Duration (s) |"
        echo "| --- | --- | ---: | ---: |"

        local i
        for i in "${!STAGE_NAMES[@]}"; do
            echo "| ${STAGE_NAMES[$i]} | ${STAGE_STATUS[$i]} | ${STAGE_CODES[$i]} | ${STAGE_SECONDS[$i]} |"
        done
    } >"$SUMMARY_PATH"
}

write_summary() {
    FINALIZING=1 write_summary_file "$1"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat "$SUMMARY_PATH" >>"$GITHUB_STEP_SUMMARY"
    fi
}

finalize() {
    local overall_exit_code="${1:-0}"
    FINALIZING=1 write_summary_file "$overall_exit_code"
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" && -z "${SUMMARY_PUBLISHED:-}" ]]; then
        cat "$SUMMARY_PATH" >>"$GITHUB_STEP_SUMMARY"
        SUMMARY_PUBLISHED=1
    fi
    echo
    echo "==> CI Validation Summary Table ==>"
    cat "$SUMMARY_PATH"
    echo "==================================="
    echo
}

trap 'status=$?; finalize "$status"; exit "$status"' EXIT

# Placeholder so `target/ci-validation-summary.md` exists even if the first
# stage hangs and the job is cancelled before any stage completes.
write_summary_file 0

CI_STAGE_TIMEOUT_SECS=300 run_stage "formatting" cargo fmt --all -- --check
CI_STAGE_TIMEOUT_SECS=900 run_stage "clippy" cargo clippy --all-targets --all-features -- -D warnings
CI_STAGE_TIMEOUT_SECS=1500 run_stage "workspace + Qdrant-backed tests" bash "$SCRIPT_DIR/run-all-tests.sh"
CI_STAGE_TIMEOUT_SECS=600 run_stage "P2P mesh slice" bash "$SCRIPT_DIR/run-p2p-tests.sh"
CI_STAGE_TIMEOUT_SECS=300 run_stage "eBPF prerequisite check" non-blocking bash "$SCRIPT_DIR/check-ebpf-prereqs.sh"
CI_STAGE_TIMEOUT_SECS=300 run_stage "rocksdb warm prereq check" bash "$SCRIPT_DIR/check-rocksdb-bench-prereqs.sh"
CI_STAGE_TIMEOUT_SECS=1200 run_stage "rocksdb warm benchmark compile" cargo bench -p context-memory --bench rocksdb_bench --features rocksdb-warm --no-run
# งบ latency 2ms ของ data plane วัดได้เฉพาะ release เท่านั้น (ดู ai-gateway/tests/perf_budget.rs)
# ใน debug เทสต์ถูก ignore อยู่แล้ว จึงต้องรันแยกจาก debug test suite ไม่เช่นนั้นไม่มีอะไรถูกตรวจ
# ใช้ non-blocking เพราะ shared runner ไม่นิ่งพอสำหรับ latency assertion —
# ถ้าพังเฉพาะบน runner จะได้ WARN ให้สืบสวนแทนที่จะบล็อกทั้ง pipeline
CI_STAGE_TIMEOUT_SECS=1200 run_stage "data plane latency budget (release)" non-blocking \
    cargo test -p ai-gateway --release --test perf_budget -- --test-threads=1 --nocapture
CI_STAGE_TIMEOUT_SECS=1500 run_stage "release build" cargo build --release

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "CI validation completed with ${FAIL_COUNT} failing stage(s)." >&2
    exit 1
fi

if [[ "$NON_BLOCKING_FAIL_COUNT" -gt 0 ]]; then
    echo "CI validation completed with ${NON_BLOCKING_FAIL_COUNT} non-blocking warning stage(s)."
    exit 0
fi

echo "CI validation completed successfully."
