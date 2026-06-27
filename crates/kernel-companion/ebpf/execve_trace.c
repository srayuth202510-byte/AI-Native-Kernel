// execve_trace.c - minimal eBPF program that logs execve syscalls
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct pt_regs *ctx) {
    // Placeholder: just return 0; real implementation would emit an event via perf ring buffer
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
