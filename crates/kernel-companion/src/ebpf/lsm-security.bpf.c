#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

/* Emit a "version" section so the loader reads a concrete kernel_version
 * (Some) and never falls back to KernelVersion::current(), which reads
 * /proc/version_signature and can return EPERM on some kernels (aya 0.12
 * unwraps that error and panics). The value is not the ANY sentinel
 * (0xFFFFFFFE) so it is kept; LSM programs ignore kern_version. */
__u32 _version SEC("version") = 0x00070000;

/*
 * ── Architecture Overview ──────────────────────────────────────────────
 *
 * These LSM hooks enforce PID-level access control at the kernel boundary.
 *
 * IMPORTANT — these hooks are GLOBAL: `lsm/file_open`, `lsm/bprm_check_*`
 * and `lsm/socket_create` fire for EVERY process on the machine, not just
 * agents managed by the companion daemon. The kernel gives us no way to
 * scope an LSM hook to "our" PIDs only.
 *
 * Therefore the model here is DEFAULT-ALLOW with a targeted BLOCK-LIST:
 * a PID is denied ONLY if it has been explicitly placed in `blocked_pids`
 * by the daemon (capability revocation/expiry, or an Immune-System
 * quarantine/kill decision). Unknown PIDs — i.e. essentially the whole
 * operating system — pass through untouched.
 *
 * A previous version used an ALLOW-LIST (deny unless the PID was present),
 * which, because the hooks are global, denied file_open/exec/socket for
 * EVERY process the daemon had not explicitly allow-listed — i.e. all of
 * userspace — and locked up the machine the instant the hooks attached.
 * Fail-closed default-DENY is the correct posture for the *userspace*
 * policy engine evaluating a *managed agent's* syscalls; it is catastrophic
 * as the default for a global kernel LSM hook. Do not reintroduce it.
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

/* ── eBPF hash map for process block-list ──
 * Key:   u32 PID of the process
 * Value: u32 blocked flag (1 = blocked, 0/absent = allowed)
 *
 * Empty by default — every PID is allowed until the companion daemon
 * explicitly inserts it here (capability revocation/expiry or an
 * Immune-System quarantine/kill decision).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} blocked_pids SEC(".maps");

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

/* ── Helper: PID block-list check ──
 * Returns 1 if the current process is in the blocked_pids map with a
 * non-zero flag (caller should deny access). Returns 0 otherwise — the
 * default for the overwhelming majority of PIDs on the system, which
 * were never inserted into the map at all.
 *
 * Extracted as a static inline to reduce duplication across hooks
 * and enable future addition of UID-based checks.
 */
static __always_inline int is_pid_blocked(void)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    return (blocked && *blocked != 0) ? 1 : 0;
}

/* ── LSM: security_file_open ──
 * Fires on every file open(2) / openat(2) operation in the kernel, for
 * every process on the system. Denies only PIDs the daemon has placed
 * in the block-list (revoked/expired token or Immune-System action);
 * everything else — i.e. the rest of the OS — passes through.
 *
 * Syscall-level policy (e.g., whether `openat` itself is allowed) is
 * evaluated in userspace via the tracepoint channel.
 */
SEC("lsm/file_open")
int lsm_file_open(struct file *file) {
    if (is_pid_blocked()) {
        return -EPERM;
    }
    return 0;
}

/* ── LSM: security_bprm_check ──
 * Fires before execve(2) completes, for every process on the system.
 * Denies only PIDs on the block-list, preventing a quarantined/revoked
 * agent from spawning child processes or escalating via exec.
 *
 * Syscall-level policy (e.g., whether `execve` is allowed) is evaluated
 * in userspace via the tracepoint channel.
 */
SEC("lsm/bprm_check_security")
int lsm_bprm_check(struct linux_binprm *bprm) {
    if (is_pid_blocked()) {
        return -EPERM;
    }
    return 0;
}

/* ── LSM: security_socket_create ──
 * Fires for socket(2) creation and applies the same block-list gate as
 * file open and exec.
 */
SEC("lsm/socket_create")
int lsm_socket_create(int family, int type, int protocol, int kern)
{
    if (is_pid_blocked()) {
        return -EPERM;
    }
    return 0;
}
