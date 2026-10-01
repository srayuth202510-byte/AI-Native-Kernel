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

run_stage() {
    local stage_name="$1"
    local blocking_mode="${2:-required}"
    if [[ "$blocking_mode" == "required" || "$blocking_mode" == "non-blocking" ]]; then
        shift 2
    else
        blocking_mode="required"
        shift 1
    fi

    echo "==> CI validation: ${stage_name}"

    local started_at
    started_at="$(date +%s)"

    set +e
    "$@"
    local exit_code=$?
    set -e

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

    echo
}

write_summary() {
    local overall_exit_code="$1"
    local overall_status="PASS"

    if [[ "$FAIL_COUNT" -gt 0 || "$overall_exit_code" -ne 0 ]]; then
        overall_status="FAIL"
    elif [[ "$NON_BLOCKING_FAIL_COUNT" -gt 0 ]]; then
        overall_status="PASS (with warnings)"
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

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        cat "$SUMMARY_PATH" >>"$GITHUB_STEP_SUMMARY"
    fi
}

finalize() {
    local overall_exit_code="${1:-0}"
    write_summary "$overall_exit_code"
    echo
    echo "==> CI Validation Summary Table ==>"
    cat "$SUMMARY_PATH"
    echo "==================================="
    echo
}

trap 'status=$?; finalize "$status"; exit "$status"' EXIT

run_stage "formatting" cargo fmt --all -- --check
run_stage "clippy" cargo clippy --all-targets --all-features -- -D warnings
run_stage "workspace + Qdrant-backed tests" bash "$SCRIPT_DIR/run-all-tests.sh"
run_stage "P2P mesh slice" bash "$SCRIPT_DIR/run-p2p-tests.sh"
run_stage "eBPF prerequisite check" non-blocking bash "$SCRIPT_DIR/check-ebpf-prereqs.sh"
run_stage "rocksdb warm prereq check" bash "$SCRIPT_DIR/check-rocksdb-bench-prereqs.sh"
run_stage "rocksdb warm benchmark compile" cargo bench -p context-memory --bench rocksdb_bench --features rocksdb-warm --no-run
# งบ latency 2ms ของ data plane วัดได้เฉพาะ release เท่านั้น (ดู ai-gateway/tests/perf_budget.rs)
# ใน debug เทสต์ถูก ignore อยู่แล้ว จึงต้องรันแยกจาก debug test suite ไม่เช่นนั้นไม่มีอะไรถูกตรวจ
# ใช้ non-blocking เพราะ shared runner ไม่นิ่งพอสำหรับ latency assertion —
# ถ้าพังเฉพาะบน runner จะได้ WARN ให้สืบสวนแทนที่จะบล็อกทั้ง pipeline
run_stage "data plane latency budget (release)" non-blocking \
    cargo test -p ai-gateway --release --test perf_budget -- --test-threads=1 --nocapture
run_stage "release build" cargo build --release

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo "CI validation completed with ${FAIL_COUNT} failing stage(s)." >&2
    exit 1
fi

if [[ "$NON_BLOCKING_FAIL_COUNT" -gt 0 ]]; then
    echo "CI validation completed with ${NON_BLOCKING_FAIL_COUNT} non-blocking warning stage(s)."
    exit 0
fi

echo "CI validation completed successfully."
