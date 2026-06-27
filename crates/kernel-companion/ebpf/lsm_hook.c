// lsm_hook.c - minimal LSM hook stub that always allows syscalls
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("lsm.sched_process_exec")
int bpf_lsm_sched_process_exec(struct task_struct *task) {
    // Placeholder: always allow execution (return 0). Real implementation would check capabilities.
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
