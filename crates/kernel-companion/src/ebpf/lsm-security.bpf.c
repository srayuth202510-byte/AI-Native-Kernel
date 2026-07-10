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
 * Key:   u32 PID (tgid) of a managed agent process
 * Value: u64 expected process start time, in USER_HZ ticks since boot
 *        (the same value userspace reads from /proc/<pid>/stat field 22)
 *
 * Consulted ONLY for processes inside a registered agent cgroup. The
 * companion daemon inserts a PID when `authorize_process_token` validates
 * its capability token, and removes it on revocation/expiry. An agent-
 * cgroup process absent from this map is denied (default-DENY).
 *
 * Hardening H2 — unforgeable identity: the stored start time binds the
 * authorization to the process *instance*, not the bare PID. If the agent
 * dies and the kernel recycles its PID for a new process (in the same
 * cgroup), the new process has a different start time and is denied.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} allowed_pids SEC(".maps");

/* แปลง start_boottime (ns) เป็น USER_HZ ticks ให้ตรงกับ /proc/<pid>/stat
 * field 22: kernel ใช้ nsec_to_clock_t(x) = x / (NSEC_PER_SEC / USER_HZ)
 * โดย USER_HZ ตรึงเป็น 100 ใน userspace ABI → ตัวหาร = 10^7 */
#define START_TIME_TICK_NS 10000000ULL

/* ── Hardening H3: intent-derived scope ──
 * Operation-class bits — must mirror kernel-companion/src/scope.rs. */
#define SCOPE_FILE_OPEN 1u
#define SCOPE_EXEC      2u
#define SCOPE_SOCKET    4u

#define PATH_PREFIX_MAX 128
#define PATH_BUF_MAX    256

/* ── eBPF hash map for per-PID scope flags (H3) ──
 * Key:   u32 PID (tgid) of an allow-listed agent
 * Value: u32 bitmask of permitted operation classes (SCOPE_*)
 *
 * Absent entry = no class restriction (the allow-list alone governs, as
 * before H3). Present entry = the hook's class bit must be set. Entries
 * are written by the daemon from the compiled IntentScope BEFORE the
 * agent starts work, and removed together with the allow-list entry.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pid_scope_flags SEC(".maps");

/* ── eBPF hash map for per-PID file path prefix (H3) ──
 * Key:   u32 PID (tgid) of an allow-listed agent
 * Value: NUL-terminated absolute path prefix (no trailing slash)
 *
 * When present, file_open is permitted only for paths equal to the
 * prefix or strictly under it (next byte '/'). Resolved with bpf_d_path,
 * so the comparison uses the kernel's own view of the path — symlink
 * tricks in userspace cannot dodge it. Absent = no path restriction.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, char[PATH_PREFIX_MAX]);
} pid_path_prefix SEC(".maps");

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
 * Shared decision logic for every hook. Return values:
 *
 *   0      → host world: allow, and NO scoped checks apply (a recycled
 *            PID outside the agent cgroup must never inherit agent
 *            restrictions).
 *   1      → agent world, allowed so far: caller may apply further
 *            scoped checks (e.g. the file path prefix).
 *   -EPERM → deny.
 *
 * Decision order:
 *   1. Quarantined PID (blocked_pids)      → deny, wins everywhere.
 *   2. Cgroup not registered (host world)  → 0, host untouched.
 *   3. PID not allow-listed or start time mismatch (H2, recycled PID)
 *                                          → deny (fail-closed).
 *   4. Scope flags present but hook's operation class not granted (H3)
 *                                          → deny. Absent entry = no
 *                                            class restriction.
 */
static __always_inline int lsm_gate(u32 scope_class)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *blocked = bpf_map_lookup_elem(&blocked_pids, &pid);
    if (blocked && *blocked != 0)
        return -EPERM;

    u64 cgid = bpf_get_current_cgroup_id();
    u32 *agent_scope = bpf_map_lookup_elem(&agent_cgroups, &cgid);
    if (!agent_scope || *agent_scope == 0)
        return 0;

    u64 *expected_start = bpf_map_lookup_elem(&allowed_pids, &pid);
    if (!expected_start)
        return -EPERM;

    /* H2: bind the allow-list entry to the process instance. Use the
     * thread-group leader so every thread of the agent shares one start
     * time — pid here is the tgid, matching /proc/<tgid>/stat. LSM
     * programs are BTF-typed, so direct task_struct dereferences are
     * verifier-checked reads. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    u64 start_ticks = task->group_leader->start_boottime / START_TIME_TICK_NS;
    if (*expected_start != start_ticks)
        return -EPERM;

    /* H3: intent-derived operation-class scope */
    u32 *flags = bpf_map_lookup_elem(&pid_scope_flags, &pid);
    if (flags && (*flags & scope_class) == 0)
        return -EPERM;

    return 1;
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
/* หมายเหตุ: hook ทุกตัวต้องประกาศผ่าน BPF_PROG — ctx ของ LSM program คือ
 * อาร์เรย์ u64 ของ args, การประกาศ `int f(struct file *file)` ตรงๆ จะทำให้
 * compiler มอง ctx pointer เป็น struct pointer แล้วคำนวณ offset ผิดทั้งหมด
 * (verifier ปฏิเสธ: "R1 type=ctx expected=ptr_") */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    int gate = lsm_gate(SCOPE_FILE_OPEN);
    if (gate <= 0)
        return gate;

    /* H3: path-prefix scope — เฉพาะ agent ที่ถูกจำกัด path เท่านั้น
     * (gate == 1 การันตีว่าเป็น agent world; PID ของ host ที่บังเอิญชน
     * key ใน map จะไม่ถึงจุดนี้เพราะ gate คืน 0 ไปก่อนแล้ว) */
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char *prefix = bpf_map_lookup_elem(&pid_path_prefix, &pid);
    if (!prefix)
        return 0;

    /* bpf_d_path ใช้ได้ใน security_file_open (hook นี้อยู่ในชุด sleepable
     * LSM hooks ที่ helper อนุญาต) — ได้ path จากมุมมองของ kernel เอง
     * เลี่ยง symlink trick จาก userspace ทั้งหมด; resolve ไม่ได้ = fail
     * closed. buffer ต้อง zero-init: arg ของ helper เป็น ARG_PTR_TO_MEM
     * ซึ่ง verifier บังคับให้ stack ถูก initialize ก่อนเรียก */
    char path[PATH_BUF_MAX] = {};
    long len = bpf_d_path(&file->f_path, path, sizeof(path));
    if (len < 0)
        return -EPERM;

    int i;
    for (i = 0; i < PATH_PREFIX_MAX; i++) {
        char p = prefix[i];
        if (p == '\0')
            break;
        if (i >= PATH_BUF_MAX - 1 || path[i] != p)
            return -EPERM;
    }
    /* ผ่านเมื่อ path เท่ากับ prefix พอดี หรืออยู่ใต้ prefix เท่านั้น —
     * กัน /tmp/foo ไปจับคู่ /tmp/foobar ด้วยการเช็ค byte ถัดไป */
    if (i < PATH_BUF_MAX && (path[i] == '\0' || path[i] == '/'))
        return 0;
    return -EPERM;
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
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm)
{
    int gate = lsm_gate(SCOPE_EXEC);
    return gate > 0 ? 0 : gate;
}

/* ── LSM: security_socket_create ──
 * Fires for socket(2) creation and applies the same cgroup-scoped gate
 * as file open and exec.
 */
SEC("lsm/socket_create")
int BPF_PROG(lsm_socket_create, int family, int type, int protocol, int kern)
{
    int gate = lsm_gate(SCOPE_SOCKET);
    return gate > 0 ? 0 : gate;
}
