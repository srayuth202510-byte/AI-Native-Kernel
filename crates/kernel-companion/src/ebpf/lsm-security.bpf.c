#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "MIT";

/* ── eBPF hash map for process allowlist ──
 * Key:   u32 PID of the process
 * Value: u32 allowed flag (1 = allowed, 0 = denied)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} allowed_pids SEC(".maps");

/* ── eBPF hash map for syscall allowlist ──
 * Key:   u64 syscall number
 * Value: u32 allowed flag (1 = allowed, 0 = denied)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u64);
    __type(value, u32);
} allowed_syscalls SEC(".maps");

/* ── LSM: security_file_open ──
 * Fires on every file open operation. Checks if the calling PID is
 * in the allowed_pids map. Denies access if not found or flagged 0.
 */
SEC("lsm/security_file_open")
int lsm_file_open(struct file *file, const struct cred *cred) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    if (!allowed || *allowed == 0) {
        return -EPERM;
    }
    return 0;
}

/* ── LSM: security_bprm_check ──
 * Fires before execve(2). Checks the calling PID against the allowlist.
 * Blocks execution of new programs for unapproved processes.
 */
SEC("lsm/security_bprm_check")
int lsm_bprm_check(struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    if (!allowed || *allowed == 0) {
        return -EPERM;
    }
    return 0;
}
