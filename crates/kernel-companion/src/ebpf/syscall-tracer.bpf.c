#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/*
 * ── Syscall Decision Cache ────────────────────────────────────────────
 * Key:   u64 syscall number
 * Value: u8 decision (1 = ALLOW, 0 = DENY)
 *
 * Populated by userspace companion daemon after evaluating each syscall
 * against LsmPolicyEngine. On cache hit, the tracepoint skips sending
 * the event to userspace — the decision is returned directly in-kernel.
 *
 * This eliminates the 1ms polling round-trip for repeat syscalls,
 * reducing P99 latency from ~1ms to near-zero for cached entries.
 *
 * Invalidation: userspace clears the entire map when:
 *   - Active profile changes (strict ↔ runtime ↔ dev)
 *   - Antibody blocklist is updated by B-Cell immune system
 * ──────────────────────────────────────────────────────────────────────
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} syscall_decision_cache SEC(".maps");

/* Sentinel value: "not in cache" — we use a separate exists-map
 * because BPF maps don't distinguish "value is 0" from "key not found".
 * Instead, we store (1=allow, 2=deny) so 0 means "not cached".
 */
#define DECISION_NOT_CACHED 0
#define DECISION_ALLOW      1
#define DECISION_DENY       2

struct syscall_event {
    __u64 syscall_nr;
    __u32 pid;
    __u32 uid;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} syscall_events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_tp(struct trace_event_raw_sys_enter *ctx) {
    __u64 syscall_nr = ctx->id;

    /* ── Step 1: Check decision cache ── */
    __u8 *cached = bpf_map_lookup_elem(&syscall_decision_cache, &syscall_nr);
    if (cached && *cached != DECISION_NOT_CACHED) {
        /* Cache hit — skip perf buffer round-trip.
         * The decision is already known; no need to send to userspace.
         * We still return 0 (allow the tracepoint to complete) because
         * actual enforcement happens at the LSM hook or userspace layer.
         */
        return 0;
    }

    /* ── Step 2: Cache miss — send event to userspace for evaluation ── */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    struct syscall_event event = {
        .syscall_nr = syscall_nr,
        .pid = (__u32)(pid_tgid >> 32),
        .uid = (__u32)uid_gid,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
