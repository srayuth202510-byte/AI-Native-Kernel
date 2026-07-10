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
 * These LSM hooks enforce cgroup-scoped access control at the kernel
 * boundary (Hardening Backlog H1).
 *
 * IMPORTANT — these hooks are GLOBAL: `lsm/file_open`, `lsm/bprm_check_*`
 * and `lsm/socket_create` fire for EVERY process on the machine, not just
 * agents managed by the companion daemon. The kernel gives us no way to
 * scope an LSM hook attachment to "our" PIDs only — so we scope the
 * DECISION instead, using the caller's cgroup (v2) id:
 *
 *   1. `blocked_pids` (quarantine) is checked first and wins everywhere,
 *      host processes included — capability revocation/expiry or an
 *      Immune-System quarantine/kill decision must always bite.
 *   2. If the caller's cgroup id is NOT registered in `agent_cgroups`,
 *      the caller is part of the host world → pass through untouched.
 *      The host can never be frozen by these hooks.
 *   3. If the caller IS inside a registered agent cgroup, the posture is
 *      fail-closed DEFAULT-DENY: the PID must be explicitly present in
 *      `allowed_pids` (valid capability token) or the operation is denied.
 *
 * History: v1 used a global PID ALLOW-LIST, which denied file_open/exec/
 * socket for all of userspace and locked up the machine the instant the
 * hooks attached. v2 (commit d728095d) inverted to a global BLOCK-LIST,
 * which kept the host alive but made kernel-level enforcement default-
 * ALLOW — contradicting the project's fail-DENY principle. This version
 * restores default-DENY for the agent world only, by scoping it to
 * registered agent cgroups. Do NOT widen default-DENY beyond registered
 * cgroups: an empty `agent_cgroups` map must always mean "host untouched".
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

/* ── eBPF hash map for process block-list (quarantine) ──
 * Key:   u32 PID of the process
 * Value: u32 blocked flag (1 = blocked, 0/absent = not quarantined)
 *
 * Empty by default — checked FIRST and wins everywhere (host included).
 * The companion daemon inserts a PID here on capability revocation/expiry
 * or an Immune-System quarantine/kill decision.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} blocked_pids SEC(".maps");

/* ── eBPF hash map for agent cgroup scope ──
 * Key:   u64 cgroup (v2) id — kernfs inode of the cgroup directory
 * Value: u32 registered flag (1 = agent scope)
 *
 * Registered by the companion daemon for every cgroup that hosts managed
 * agents. Processes whose cgroup id is present here live in the "agent
 * world" and are subject to fail-closed default-DENY. Everything else is
 * the host world and passes through untouched. Empty map = enforcement
 * effectively off (host-safe default).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);
    __type(value, u32);
} agent_cgroups SEC(".maps");

/* ── eBPF hash map for agent PID allow-list ──
 * Key:   u32 PID of a managed agent process
 * Value: u32 allowed flag (1 = holds a valid capability token)
 *
 * Consulted ONLY for processes inside a registered agent cgroup. The
 * companion daemon inserts a PID when `authorize_process_token` validates
 * its capability token, and removes it on revocation/expiry. An agent-
 * cgroup process absent from this map is denied (default-DENY).
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

/* ── Helper: cgroup-scoped access gate ──
 * Shared decision logic for every hook. Returns 0 (allow) or -EPERM:
 *
 *   1. Quarantined PID (blocked_pids)      → deny, wins everywhere.
 *   2. Cgroup not registered (host world)  → allow, host untouched.
 *   3. Agent cgroup + PID allow-listed     → allow (valid token).
 *   4. Agent cgroup otherwise              → deny (fail-closed).
 *
 * Extracted as a static inline to keep all hooks on identical policy.
 */
static __always_inline int lsm_gate(void)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked && *blocked != 0)
        return -EPERM;

    u64 cgid = bpf_get_current_cgroup_id();
    u32 *agent_scope = bpf_map_lookup_elem(&agent_cgroups, &cgid);
    if (!agent_scope || *agent_scope == 0)
        return 0;

    u32 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    return (allowed && *allowed != 0) ? 0 : -EPERM;
}

/* ── LSM: security_file_open ──
 * Fires on every file open(2) / openat(2) operation in the kernel, for
 * every process on the system. Applies the cgroup-scoped gate: host
 * processes pass through; agent-cgroup processes are default-DENIED
 * unless allow-listed; quarantined PIDs are denied everywhere.
 *
 * Syscall-level policy (e.g., whether `openat` itself is allowed) is
 * evaluated in userspace via the tracepoint channel.
 */
SEC("lsm/file_open")
int lsm_file_open(struct file *file) {
    return lsm_gate();
}

/* ── LSM: security_bprm_check ──
 * Fires before execve(2) completes, for every process on the system.
 * The cgroup-scoped gate prevents a non-authorized or quarantined agent
 * from spawning child processes or escalating via exec — including
 * children it forked, which inherit the agent cgroup but are not in the
 * PID allow-list (default-DENY catches the escape).
 *
 * Syscall-level policy (e.g., whether `execve` is allowed) is evaluated
 * in userspace via the tracepoint channel.
 */
SEC("lsm/bprm_check_security")
int lsm_bprm_check(struct linux_binprm *bprm) {
    return lsm_gate();
}

/* ── LSM: security_socket_create ──
 * Fires for socket(2) creation and applies the same cgroup-scoped gate
 * as file open and exec.
 */
SEC("lsm/socket_create")
int lsm_socket_create(int family, int type, int protocol, int kern)
{
    return lsm_gate();
}
