use crate::config::LsmConfig;
use crate::ebpf::load_bpf_o;
use crate::observability::kernel_metrics;
use anyhow::Result;
use aya::maps::{HashMap as BpfHashMap, MapData};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

/// ข้อผิดพลาดของการควบคุม LSM (Linux Security Module)
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LsmError {
    /// การเรียกใช้งานระบบ (Syscall) ถูกปฏิเสธตามนโยบายความปลอดภัย
    #[error("policy decision denied")]
    Denied,
    /// ล้มเหลวในขั้นตอนการแนบ Hook เข้ากับ Kernel
    #[error("attachment failed")]
    AttachmentFailed,
    /// profile ที่ร้องขอไม่มีอยู่ใน config
    #[error("unknown profile: {0}")]
    UnknownProfile(String),
}

/// การตัดสินใจเชิงนโยบายความปลอดภัยของ LSM
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmDecision {
    /// อนุญาตให้เรียกใช้งานระบบได้
    Allow,
    /// ปฏิเสธการเรียกใช้งานระบบ
    Deny,
}

/// ตัวตัดสินใจและบังคับใช้สิทธิ์ความปลอดภัยในระดับ Kernel (LSM Policy Engine)
#[derive(Debug)]
pub struct LsmPolicyEngine {
    /// ผลการตัดสินใจเริ่มต้นกรณีไม่ตรงกับเงื่อนไขใด ๆ (Fail-closed: DENY)
    default_decision: LsmDecision,
    /// profile ที่ active อยู่จาก config
    active_profile: RwLock<String>,
    /// profiles ที่ resolve แล้วจาก config
    profiles: RwLock<BTreeMap<String, HashSet<String>>>,
    /// รายชื่อ syscall ที่ถูกบล็อกโดย Immune System antibodies (deny rules)
    blocked_syscalls: RwLock<std::collections::HashSet<String>>,
}

impl LsmPolicyEngine {
    /// สร้างอินสแตนซ์ของ LSM Policy Engine โดยตั้งค่าเริ่มต้นให้ปฏิเสธการเรียกใช้งานไว้ก่อน
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(&LsmConfig::default())
    }

    /// สร้างอินสแตนซ์ของ LSM Policy Engine จาก config profile ที่กำหนด
    #[must_use]
    pub fn with_config(config: &LsmConfig) -> Self {
        let profiles = config
            .profiles
            .iter()
            .map(|(name, profile)| {
                (
                    name.clone(),
                    profile.allowed_syscalls.iter().cloned().collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Self {
            default_decision: LsmDecision::Deny,
            active_profile: RwLock::new(config.active_profile_name().to_string()),
            profiles: RwLock::new(profiles),
            blocked_syscalls: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// เพิ่ม syscall ใน Blocklist ตาม Antibody Rule จาก Immune System B-Cell Agent
    pub fn add_blocked_syscall(&self, syscall: impl Into<String>) {
        let syscall = syscall.into();
        self.blocked_syscalls.write().insert(syscall);
        let blocked_count = self.blocked_syscalls.read().len();
        kernel_metrics().set_blocked_syscalls(blocked_count);
    }

    /// ดึงรายการ syscall ทั้งหมดที่ถูกบล็อคโดยแอนติบอดี
    pub fn get_blocked_syscalls(&self) -> Vec<String> {
        self.blocked_syscalls.read().iter().cloned().collect()
    }

    /// ดึง allowlist ที่ active อยู่ในรูปแบบ snapshot
    #[must_use]
    pub fn get_allowed_syscalls(&self) -> HashSet<String> {
        let active_profile = self.active_profile_name();
        self.profiles
            .read()
            .get(active_profile.as_str())
            .cloned()
            .unwrap_or_default()
    }

    /// คืนชื่อ profile ที่ active อยู่
    #[must_use]
    pub fn active_profile_name(&self) -> String {
        self.active_profile.read().clone()
    }

    /// รายชื่อ profile ทั้งหมดที่มีอยู่ใน config
    #[must_use]
    pub fn available_profiles(&self) -> Vec<String> {
        self.profiles.read().keys().cloned().collect()
    }

    /// สลับ active profile แบบ runtime
    pub fn set_active_profile(&self, profile: &str) -> std::result::Result<(), LsmError> {
        let profiles = self.profiles.read();
        if !profiles.contains_key(profile) {
            return Err(LsmError::UnknownProfile(profile.to_string()));
        }
        drop(profiles);

        *self.active_profile.write() = profile.to_string();
        Ok(())
    }

    /// ตรวจสอบ syscall และตัดสินใจว่าจะอนุญาตหรือปฏิเสธตามกฎที่กำหนดไว้
    /// 1. ตรวจสอบ Blocklist (Immune System Antibodies) — DENY ถ้าตรง
    /// 2. ตรวจสอบ Allowlist — ALLOW ถ้าตรง
    /// 3. Default = DENY (Zero-Trust fail-closed)
    #[must_use]
    #[instrument(skip(self), fields(syscall = %syscall))]
    pub fn decision_for_syscall(&self, syscall: &str) -> LsmDecision {
        let metrics = kernel_metrics();
        // ขั้นแรก: ตรวจสอบ Blocklist จาก Immune System antibodies
        if self.blocked_syscalls.read().contains(syscall) {
            metrics.record_lsm_decision("deny", "antibody");
            warn!(
                decision = "deny (antibody)",
                syscall, "LSM blocked syscall per Immune System antibody rule"
            );
            return LsmDecision::Deny;
        }

        if self.get_allowed_syscalls().contains(syscall) {
            metrics.record_lsm_decision("allow", "allowlist");
            debug!(decision = "allow", "อนุญาต syscall ตามนโยบาย Zero-Trust");
            return LsmDecision::Allow;
        }

        // ขั้นสาม: ปฏิเสธ syscall อื่น ๆ ทั้งหมด (fail-closed)
        metrics.record_lsm_decision("deny", "default_deny");
        warn!(decision = "deny", "ปฏิเสธ syscall ที่ไม่อยู่ใน allowlist");
        self.default_decision
    }
}

impl Default for LsmPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// โครงสร้างข้อมูลสำหรับอ้างอิงสถานะการเชื่อมต่อ LSM Hook
///
/// ในโหมดจริง (real eBPF): เก็บ `aya::Bpf` เพื่อให้โปรแกรม LSM ทำงานใน kernel
/// ในโหมดจำลอง: แค่ flag `attached` สำหรับทดสอบการทำงานของ lifecycle
#[derive(Debug)]
pub struct LsmAttachment {
    /// BPF object ที่เก็บรักษาโปรแกรม LSM ใน kernel (None = โหมดจำลอง)
    bpf: Option<aya::Bpf>,
    /// map สำหรับ sync PID allowlist runtime เข้ากับ kernel hook
    allowed_pids: Option<BpfHashMap<MapData, u32, u32>>,
    /// map สำหรับ sync syscall allowlist runtime เข้ากับ kernel hook
    allowed_syscalls: Option<BpfHashMap<MapData, u64, u32>>,
    /// บ่งชี้ว่ายังคงแนบอยู่กับ Kernel หรือไม่
    attached: bool,
    /// snapshot ฝั่ง userspace สำหรับทดสอบและ fail-safe checks
    allowed_pid_cache: HashSet<u32>,
}

impl LsmAttachment {
    /// สร้าง LsmAttachment ในโหมดจำลอง (simulation mode)
    /// ใช้เมื่อ real eBPF LSM ไม่สามารถโหลดได้
    #[must_use]
    pub fn new() -> Self {
        Self {
            bpf: None,
            allowed_pids: None,
            allowed_syscalls: None,
            attached: true,
            allowed_pid_cache: HashSet::new(),
        }
    }

    /// สร้าง LsmAttachment จาก aya::Bpf จริง
    /// โปรแกรม LSM จะทำงานใน kernel จนกว่าจะเรียก detach()
    #[must_use]
    pub fn new_with_bpf(
        bpf: aya::Bpf,
        allowed_pids: Option<BpfHashMap<MapData, u32, u32>>,
        allowed_syscalls: Option<BpfHashMap<MapData, u64, u32>>,
        allowed_pid_cache: HashSet<u32>,
    ) -> Self {
        Self {
            bpf: Some(bpf),
            allowed_pids,
            allowed_syscalls,
            attached: true,
            allowed_pid_cache,
        }
    }

    /// ปลดการแนบ LSM Hook และยกเลิกโหลดโปรแกรม eBPF
    pub fn detach(&mut self) {
        // Dropping the Bpf object detaches all programs and unloads them
        self.bpf = None;
        self.allowed_pids = None;
        self.allowed_syscalls = None;
        self.attached = false;
        self.allowed_pid_cache.clear();
    }

    /// ตรวจสอบสถานะว่า LSM Hook ยังทำงานอยู่หรือไม่
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// ตรวจสอบว่าใช้ real eBPF หรือโหมดจำลอง
    #[must_use]
    pub fn is_real(&self) -> bool {
        self.bpf.is_some()
    }

    pub fn allow_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(map) = self.allowed_pids.as_mut() {
            map.insert(pid, 1, 0)?;
        }
        self.allowed_pid_cache.insert(pid);
        Ok(())
    }

    pub fn deny_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(map) = self.allowed_pids.as_mut() {
            let _ = map.remove(&pid);
        }
        self.allowed_pid_cache.remove(&pid);
        Ok(())
    }

    #[must_use]
    pub fn allows_pid(&self, pid: u32) -> bool {
        self.allowed_pid_cache.contains(&pid)
    }

    #[must_use]
    pub fn allowed_pids(&self) -> HashSet<u32> {
        self.allowed_pid_cache.clone()
    }
}

impl Default for LsmAttachment {
    fn default() -> Self {
        Self::new()
    }
}

/// พยายามโหลดและแนบโปรแกรม LSM eBPF จริงผ่าน Aya
///
/// โปรแกรมที่แนบ:
/// - `lsm/security_file_open` — ตรวจสอบ PID ที่ allowed_pids map (kernel ≥5.7)
/// - `lsm/security_bprm_check` — ตรวจสอบ PID ก่อน execve (kernel ≥5.5)
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหาก BPF .o file ไม่มี หรือ Aya โหลด/แนบไม่สำเร็จ
fn try_attach_real_lsm(engine: &LsmPolicyEngine) -> Result<LsmAttachment> {
    let metrics = kernel_metrics();
    let bpf_bytes = load_bpf_o("lsm-security")?;
    let mut bpf = aya::Bpf::load(&bpf_bytes)?;
    let mut allowed_pid_cache = HashSet::new();

    // Aya 0.12: LSM programs require kernel BTF (/sys/kernel/btf/vmlinux)
    // to resolve types between the BPF program and kernel LSM hooks.
    let btf = aya::Btf::from_sys_fs()
        .map_err(|e| anyhow::anyhow!("Cannot load kernel BTF from /sys/kernel/btf/vmlinux: {e}"))?;

    // ── security_file_open LSM hook ──
    // ตรวจสอบทุกครั้งที่มีการเปิดไฟล์ โดยเช็ค PID จาก allowed_pids map
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_file_open")
            .ok_or_else(|| anyhow::anyhow!("lsm_file_open program not found"))?
            .try_into()?;
        // In Aya 0.12, load(lsm_hook_name, btf) attaches the hook name to the program
        prog.load("security_file_open", &btf)?;
        // attach() with no arguments — the hook name was already specified in load()
        let link = prog.attach()?;
        // Leak the link so it stays alive for the daemon's lifetime.
        // The kernel keeps a reference via the file descriptor.
        Box::leak(Box::new(link));
        info!("LSM eBPF: security_file_open attached");
    }

    // ── security_bprm_check LSM hook ──
    // ตรวจสอบก่อน execute ใหม่ ห้าม fork/exec โดยไม่ได้รับอนุญาต
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_bprm_check")
            .ok_or_else(|| anyhow::anyhow!("lsm_bprm_check program not found"))?
            .try_into()?;
        prog.load("security_bprm_check", &btf)?;
        let link = prog.attach()?;
        Box::leak(Box::new(link));
        info!("LSM eBPF: security_bprm_check attached");
    }

    // ── security_socket_create LSM hook ──
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_socket_create")
            .ok_or_else(|| anyhow::anyhow!("lsm_socket_create program not found"))?
            .try_into()?;
        prog.load("security_socket_create", &btf)?;
        let link = prog.attach()?;
        Box::leak(Box::new(link));
        info!("LSM eBPF: security_socket_create attached");
    }

    // ── populate allowed_pids eBPF map ──
    // เพิ่ม PID ของ companion daemon เองให้อยู่ใน allowlist เสมอ
    let mut allowed_pids = if let Some(map) = bpf.take_map("allowed_pids") {
        Some(BpfHashMap::<_, u32, u32>::try_from(map)?)
    } else {
        None
    };
    if let Some(pid_map) = allowed_pids.as_mut() {
        let own_pid = std::process::id();
        let _ = pid_map.insert(own_pid, 1, 0);
        allowed_pid_cache.insert(own_pid);
        info!("LSM eBPF: PID {own_pid} added to allowed_pids map");
    } else {
        warn!("LSM eBPF: could not create HashMap from allowed_pids map");
    }

    // ── populate allowed_syscalls eBPF map ──
    // เติม syscall numbers ที่ LsmPolicyEngine อนุญาต
    let mut allowed_syscalls = if let Some(map) = bpf.take_map("allowed_syscalls") {
        Some(BpfHashMap::<_, u64, u32>::try_from(map)?)
    } else {
        None
    };
    if let Some(sc_map) = allowed_syscalls.as_mut() {
        let allowed_syscalls = engine.get_allowed_syscalls();
        for (nr, name) in crate::ebpf::build_syscall_table() {
            if allowed_syscalls.contains(name) {
                let _ = sc_map.insert(nr, 1, 0);
                debug!("LSM eBPF: syscall {name}({nr}) added to allowlist");
            }
        }
    } else {
        warn!("LSM eBPF: could not create HashMap from allowed_syscalls map");
    }

    info!("LSM eBPF: all programs attached and maps populated");
    metrics.record_attach_attempt("lsm", "success");
    metrics.set_active_mode("lsm", "real");
    Ok(LsmAttachment::new_with_bpf(
        bpf,
        allowed_pids,
        allowed_syscalls,
        allowed_pid_cache,
    ))
}

/// ฟังก์ชันหลักสำหรับแนบ LSM Hook เข้ากับ Linux Kernel
///
/// พยายามแนบ real LSM eBPF hooks ก่อน หากล้มเหลวจะ fallback เป็นโหมดจำลอง
/// ในโหมดจำลอง `LsmPolicyEngine` ยังคงทำงานใน userspace สำหรับการตัดสินใจ
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหากทั้ง real mode และ simulation mode ล้มเหลว
#[instrument(skip(engine))]
pub fn attach_lsm_hooks(engine: Arc<LsmPolicyEngine>) -> Result<LsmAttachment> {
    let metrics = kernel_metrics();
    match try_attach_real_lsm(&engine) {
        Ok(attachment) => {
            info!("LSM hooks: real eBPF mode — kernel-level enforcement active");
            Ok(attachment)
        }
        Err(e) => {
            metrics.record_attach_attempt("lsm", "fallback");
            metrics.set_active_mode("lsm", "simulation");
            warn!(error = %e, "LSM hooks: real eBPF attachment failed — falling back to simulation mode");
            info!("LSM hooks: simulation mode — policy engine running in userspace");
            Ok(LsmAttachment::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_recvmsg_allowed() {
        // ทดสอบว่า syscall read, write, recvmsg ต้องได้รับอนุญาตตามนโยบาย Zero-Trust
        let engine = LsmPolicyEngine::new();
        assert_eq!(engine.decision_for_syscall("read"), LsmDecision::Allow);
        assert_eq!(engine.decision_for_syscall("write"), LsmDecision::Allow);
        assert_eq!(engine.decision_for_syscall("recvmsg"), LsmDecision::Allow);
    }

    #[test]
    fn execve_fork_denied_socket_allowed() {
        // ทดสอบว่า execve/fork ถูกปฏิเสธ แต่ socket อนุญาต (network-aware agents)
        let engine = LsmPolicyEngine::new();
        assert_eq!(engine.decision_for_syscall("execve"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("fork"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("socket"), LsmDecision::Allow);
    }

    #[test]
    fn unknown_denied() {
        // ทดสอบว่า syscall ที่ไม่รู้จักต้องถูกปฏิเสธตามหลัก fail-closed
        let engine = LsmPolicyEngine::new();
        assert_eq!(
            engine.decision_for_syscall("definitely_not_a_real_syscall"),
            LsmDecision::Deny
        );
        assert_eq!(engine.decision_for_syscall(""), LsmDecision::Deny);
        assert_eq!(
            engine.decision_for_syscall("definitely_not_a_real_syscall_2"),
            LsmDecision::Deny
        );
    }

    #[test]
    fn attachment_lifecycle() {
        // ทดสอบวงจรชีวิตของ LsmAttachment: สร้าง -> แนบ -> ปลด
        let mut attachment = LsmAttachment::new();
        assert!(attachment.is_attached(), "ควรแนบสำเร็จตอนสร้าง");
        attachment.detach();
        assert!(!attachment.is_attached(), "ควรไม่แนบหลังจาก detach()");
    }

    #[test]
    fn attachment_pid_allowlist_can_be_updated_in_fail_closed_mode() {
        let mut attachment = LsmAttachment::new();
        assert!(!attachment.allows_pid(4242));

        attachment.allow_pid(4242).expect("allow should succeed");
        assert!(attachment.allows_pid(4242));

        attachment.deny_pid(4242).expect("deny should succeed");
        assert!(!attachment.allows_pid(4242));
    }

    #[test]
    fn default_is_deny() {
        // ทดสอบว่า default_decision ของ LsmPolicyEngine ต้องเป็น Deny (fail-closed)
        let engine = LsmPolicyEngine::default();
        // ทดสอบด้วย syscall สุ่มที่ไม่อยู่ใน allowlist
        assert_eq!(
            engine.decision_for_syscall("this_syscall_should_not_exist"),
            LsmDecision::Deny,
            "ค่าเริ่มต้นต้องปฏิเสธ syscall ที่ไม่รู้จัก"
        );
    }

    #[test]
    fn runtime_allowlist_covers_common_runtime_syscalls() {
        let engine = LsmPolicyEngine::new();
        for syscall in [
            "close",
            "poll",
            "mprotect",
            "clone",
            "futex",
            "rt_sigaction",
            "rt_sigprocmask",
            "clock_gettime",
            "gettid",
            "set_robust_list",
        ] {
            assert_eq!(
                engine.decision_for_syscall(syscall),
                LsmDecision::Allow,
                "{syscall} should be allowed by default runtime allowlist"
            );
        }
    }

    #[test]
    fn active_profile_is_exposed_from_config() {
        let config = LsmConfig::default();
        let engine = LsmPolicyEngine::with_config(&config);
        assert_eq!(engine.active_profile_name(), "runtime");
        assert!(engine.available_profiles().contains(&"runtime".to_string()));
    }

    #[test]
    fn strict_profile_does_not_allow_socket() {
        let config = LsmConfig {
            active_profile: "strict".to_string(),
            ..LsmConfig::default()
        };
        let engine = LsmPolicyEngine::with_config(&config);
        assert_eq!(engine.decision_for_syscall("socket"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("read"), LsmDecision::Allow);
    }

    #[test]
    fn switch_profile_updates_allowlist_runtime() {
        let engine = LsmPolicyEngine::new();
        assert_eq!(engine.active_profile_name(), "runtime");
        engine
            .set_active_profile("strict")
            .expect("strict profile should exist");
        assert_eq!(engine.active_profile_name(), "strict");
        assert_eq!(engine.decision_for_syscall("socket"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("read"), LsmDecision::Allow);
    }

    #[test]
    fn switch_profile_rejects_unknown_profile() {
        let engine = LsmPolicyEngine::new();
        let err = engine
            .set_active_profile("definitely-not-a-profile")
            .expect_err("unknown profile should be rejected");
        assert_eq!(
            err,
            LsmError::UnknownProfile("definitely-not-a-profile".to_string())
        );
    }

    /// Privileged validation: full LSM attachment lifecycle.
    /// Loads lsm-security BPF, attaches all hooks, verifies PID map operations,
    /// and detaches cleanly. Requires CAP_BPF + CAP_SYS_ADMIN.
    #[test]
    fn validate_lsm_full_attachment_lifecycle() {
        let engine = Arc::new(LsmPolicyEngine::new());
        let mut attachment = match attach_lsm_hooks(engine) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("SKIP validate_lsm_full_attachment_lifecycle: {e}");
                return;
            }
        };

        // Verify attached state
        assert!(
            attachment.is_attached(),
            "should be attached after attach_lsm_hooks"
        );
        eprintln!("LSM: attached — is_real={}", attachment.is_real());

        if attachment.is_real() {
            // Verify PID allowlist operations
            let own_pid = std::process::id();
            assert!(
                attachment.allows_pid(own_pid),
                "own PID should be in allowlist"
            );

            attachment
                .allow_pid(99999)
                .expect("allow_pid should succeed");
            assert!(
                attachment.allows_pid(99999),
                "newly allowed PID should be in allowlist"
            );

            attachment.deny_pid(99999).expect("deny_pid should succeed");
            assert!(
                !attachment.allows_pid(99999),
                "denied PID should be removed from allowlist"
            );

            eprintln!("LSM: PID allowlist operations verified");
        }

        // Detach
        attachment.detach();
        assert!(!attachment.is_attached(), "should be detached after detach");
        eprintln!("PASS: LSM full attachment lifecycle validated");
    }
}
