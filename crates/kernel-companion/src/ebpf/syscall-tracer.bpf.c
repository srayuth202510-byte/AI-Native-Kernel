#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

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
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    struct syscall_event event = {
        .syscall_nr = ctx->id,
        .pid = (__u32)(pid_tgid >> 32),
        .uid = (__u32)uid_gid,
        .timestamp_ns = bpf_ktime_get_ns(),
    };

    bpf_perf_event_output(ctx, &syscall_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}
