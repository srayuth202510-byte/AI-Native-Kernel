#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

/*
 * ── Architecture Overview ──────────────────────────────────────────────
 *
 * These LSM hooks enforce PID-level access control at the kernel boundary.
 * Only processes whose PID is in `allowed_pids` may open files or exec
 * new programs. This is the first layer of Zero-Trust enforcement.
 *
 * Syscall-level policy (which specific syscalls like read/write/socket
 * are allowed or denied) is enforced at the *userspace* level by the
 * companion daemon, which:
 *   1. Receives every syscall event via the `raw_syscalls/sys_enter`
 *      tracepoint (see syscall-tracer.bpf.c).
 *   2. Evaluates each syscall against `LsmPolicyEngine` (allowlist per
 *      profile: strict / runtime / dev).
 *   3. Feeds deny decisions to the Immune System (T-Cell → B-Cell →
 *      antibody rules) for adaptive threat response.
 *
 * The `allowed_syscalls` map is populated by the userspace daemon but
 * is currently unused in-kernel. It is retained for future use when
 * syscall-level filtering is pushed into BPF for lower latency.
 * ──────────────────────────────────────────────────────────────────────
 */

/* ── eBPF hash map for process allowlist ──
 * Key:   u32 PID of the process
 * Value: u32 allowed flag (1 = allowed, 0 = denied)
 *
 * Populated at attach time by the companion daemon (own PID inserted
 * first). Additional PIDs are added as agents are spawned.
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
 *
 * Populated by the companion daemon from LsmPolicyEngine.
 * Reserved for future in-kernel syscall-level enforcement.
 * Currently not read by any hook — syscall policy is evaluated
 * in userspace via the tracepoint channel.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u64);
    __type(value, u32);
} allowed_syscalls SEC(".maps");

/* ── Helper: PID allowlist check ──
 * Returns 1 if the current process is in the allowed_pids map with a
 * non-zero flag. Returns 0 otherwise (caller should deny access).
 *
 * Extracted as a static inline to reduce duplication across hooks
 * and enable future addition of UID-based checks.
 */
static __always_inline int is_pid_allowed(void)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    return (allowed && *allowed != 0) ? 1 : 0;
}

/* ── LSM: security_file_open ──
 * Fires on every file open(2) / openat(2) operation in the kernel.
 * Enforces PID-level access control: only processes on the allowlist
 * may open files. This blocks unauthorized agents from reading or
 * writing resources on the filesystem.
 *
 * Syscall-level policy (e.g., whether `openat` itself is allowed) is
 * evaluated in userspace via the tracepoint channel.
 */
SEC("lsm/file_open")
int lsm_file_open(struct file *file) {
    if (!is_pid_allowed()) {
        return -EPERM;
    }
    return 0;
}

/* ── LSM: security_bprm_check ──
 * Fires before execve(2) completes. Blocks execution of new programs
 * for processes not on the PID allowlist. This prevents unauthorized
 * agents from spawning child processes or escalating via exec.
 *
 * Syscall-level policy (e.g., whether `execve` is allowed) is evaluated
 * in userspace via the tracepoint channel.
 */
SEC("lsm/bprm_check_security")
int lsm_bprm_check(struct linux_binprm *bprm) {
    if (!is_pid_allowed()) {
        return -EPERM;
    }
    return 0;
}

/* ── LSM: security_socket_create ──
 * Fires for socket(2) creation and applies the same PID/token-backed
 * gate as file open and exec. This extends fail-closed enforcement to
 * network-capable agents that have not passed userspace token checks.
 */
SEC("lsm/socket_create")
int lsm_socket_create(int family, int type, int protocol, int kern)
{
    if (!is_pid_allowed()) {
        return -EPERM;
    }
    return 0;
}
