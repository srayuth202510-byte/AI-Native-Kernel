use crate::config::LsmConfig;
use crate::ebpf::load_bpf_o;
use crate::observability::kernel_metrics;
use anyhow::Result;
use aya::maps::{HashMap as BpfHashMap, MapData};
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

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
    /// รายชื่อ syscall ที่ได้รับอนุญาตหลังการผันแปรทางพันธุกรรมแยกราย PID (Polymorphic Agent DNA)
    mutated_pids: RwLock<std::collections::HashMap<u32, HashSet<String>>>,
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
            mutated_pids: RwLock::new(std::collections::HashMap::new()),
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

    /// ลงทะเบียนและสร้าง allowlist กลายพันธุ์ (Polymorphic Agent DNA) สำหรับ PID หนึ่งๆ
    pub fn register_polymorphic_pid(&self, pid: u32, parent_profile: &str, salt: &[u8; 16]) {
        let parent_allowlist = self
            .profiles
            .read()
            .get(parent_profile)
            .cloned()
            .unwrap_or_else(|| self.get_allowed_syscalls());

        let critical = ["read", "write", "rt_sigreturn", "exit", "exit_group"];
        let mut mutated = parent_allowlist.clone();

        for syscall in &parent_allowlist {
            if critical.contains(&syscall.as_str()) {
                continue;
            }
            // คำนวณ Hash แบบง่าย (djb2) เพื่อตัดสินใจแบบ deterministic จากเกลือของเอเจนต์
            let mut hash = 5381u32;
            for byte in syscall.bytes() {
                hash = hash
                    .wrapping_shl(5)
                    .wrapping_add(hash)
                    .wrapping_add(byte as u32);
            }
            let mut salt_mix = 0u32;
            for (idx, byte) in salt.iter().enumerate() {
                salt_mix = salt_mix
                    .wrapping_add(*byte as u32)
                    .wrapping_mul(idx as u32 + 1);
            }
            hash = hash.wrapping_add(salt_mix);
            // มีโอกาส 10% ที่จะถูก Deprivilege (ถอนสิทธิ์ออกสุ่มๆ)
            if hash % 10 == 0 {
                mutated.remove(syscall);
                debug!(
                    "PAD (Polymorphic Agent DNA): Deprivileged syscall {} for PID {}",
                    syscall, pid
                );
            }
        }

        self.mutated_pids.write().insert(pid, mutated);
        info!(
            "PAD (Polymorphic Agent DNA): Registered polymorphic allowlist for PID {}",
            pid
        );
    }

    /// ตรวจสอบ syscall และตัดสินใจว่าจะอนุญาตหรือปฏิเสธตามกฎที่กำหนดไว้
    /// รองรับการแยกแยะราย PID ตามกลไก Polymorphic Agent DNA
    /// 1. ตรวจสอบ Blocklist (Immune System Antibodies) — DENY ถ้าตรง
    /// 2. ตรวจสอบ Polymorphic/Global Allowlist — ALLOW ถ้าตรง
    /// 3. Default = DENY (Fail-closed)
    #[must_use]
    #[instrument(skip(self), fields(syscall = %syscall))]
    pub fn decision_for_syscall(&self, pid: Option<u32>, syscall: &str) -> LsmDecision {
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

        // ขั้นสอง: ตรวจสอบ Allowlist (เลือกเช็คแบบ Polymorphic ราย PID หรือ Global ตามลำดับ)
        let is_allowed = if let Some(p) = pid {
            let mutated_map = self.mutated_pids.read();
            if let Some(mutated_list) = mutated_map.get(&p) {
                mutated_list.contains(syscall)
            } else {
                self.get_allowed_syscalls().contains(syscall)
            }
        } else {
            self.get_allowed_syscalls().contains(syscall)
        };

        if is_allowed {
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
///
/// หมายเหตุด้านความปลอดภัย: hook เหล่านี้เป็น **global** — ทำงานกับทุก process
/// บนเครื่อง ไม่ใช่แค่ agent ที่ daemon จัดการ โมเดลจึงเป็น **cgroup-scoped
/// allow-list** (Hardening H1):
/// - `blocked_pids` (quarantine) ตรวจก่อนและชนะทุกกรณี รวมถึง host
/// - process ที่ cgroup ไม่ได้ลงทะเบียนใน `agent_cgroups` = โลกของ host →
///   ปล่อยผ่านเสมอ (host ไม่มีทางค้าง)
/// - process ใน agent cgroup ที่ลงทะเบียนแล้ว = **default-DENY** เว้นแต่
///   PID อยู่ใน `allowed_pids` (ถือ capability token ที่ valid)
#[derive(Debug)]
pub struct LsmAttachment {
    /// BPF object ที่เก็บรักษาโปรแกรม LSM ใน kernel (None = โหมดจำลอง)
    bpf: Option<aya::Bpf>,
    /// map สำหรับ sync PID block-list (quarantine) เข้ากับ kernel hook
    blocked_pids: Option<BpfHashMap<MapData, u32, u32>>,
    /// map สำหรับ sync cgroup id ของ agent scope เข้ากับ kernel hook
    agent_cgroups: Option<BpfHashMap<MapData, u64, u32>>,
    /// map สำหรับ sync PID allow-list เข้ากับ kernel hook — ค่าคือ start
    /// time (USER_HZ ticks) ของ process ที่ผูก authorization ไว้ (H2:
    /// กัน PID reuse — PID เดิมแต่ start time ไม่ตรง = โดน DENY)
    allowed_pids: Option<BpfHashMap<MapData, u32, u64>>,
    /// map สำหรับ sync scope flags ราย PID (H3: operation-class scope)
    pid_scope_flags: Option<BpfHashMap<MapData, u32, u32>>,
    /// map สำหรับ sync ชุด path prefix ราย PID (H3 v2: จำกัด file_open ใต้
    /// prefix ตัวใดตัวหนึ่งในชุด)
    pid_path_prefixes: Option<BpfHashMap<MapData, u32, [u8; crate::scope::PATH_SET_LEN]>>,
    /// map สำหรับ sync syscall allowlist runtime เข้ากับ kernel hook
    allowed_syscalls: Option<BpfHashMap<MapData, u64, u32>>,
    /// บ่งชี้ว่ายังคงแนบอยู่กับ Kernel หรือไม่
    attached: bool,
    /// snapshot ฝั่ง userspace สำหรับทดสอบและ fail-safe checks
    blocked_pid_cache: HashSet<u32>,
    /// snapshot ฝั่ง userspace ของ cgroup id ที่ลงทะเบียนเป็น agent scope
    agent_cgroup_cache: HashSet<u64>,
    /// snapshot ฝั่ง userspace ของ PID → start ticks ที่อยู่ใน allow-list
    allowed_pid_cache: std::collections::HashMap<u32, u64>,
    /// snapshot ฝั่ง userspace ของ PID → scope ที่ compile จาก intent (H3)
    pid_scope_cache: std::collections::HashMap<u32, crate::scope::IntentScope>,
}

impl LsmAttachment {
    /// สร้าง LsmAttachment ในโหมดจำลอง (simulation mode)
    /// ใช้เมื่อ real eBPF LSM ไม่สามารถโหลดได้
    #[must_use]
    pub fn new() -> Self {
        Self {
            bpf: None,
            blocked_pids: None,
            agent_cgroups: None,
            allowed_pids: None,
            pid_scope_flags: None,
            pid_path_prefixes: None,
            allowed_syscalls: None,
            attached: true,
            blocked_pid_cache: HashSet::new(),
            agent_cgroup_cache: HashSet::new(),
            allowed_pid_cache: std::collections::HashMap::new(),
            pid_scope_cache: std::collections::HashMap::new(),
        }
    }

    /// สร้าง LsmAttachment จาก aya::Bpf จริง
    /// โปรแกรม LSM จะทำงานใน kernel จนกว่าจะเรียก detach()
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_bpf(
        bpf: aya::Bpf,
        blocked_pids: Option<BpfHashMap<MapData, u32, u32>>,
        agent_cgroups: Option<BpfHashMap<MapData, u64, u32>>,
        allowed_pids: Option<BpfHashMap<MapData, u32, u64>>,
        pid_scope_flags: Option<BpfHashMap<MapData, u32, u32>>,
        pid_path_prefixes: Option<BpfHashMap<MapData, u32, [u8; crate::scope::PATH_SET_LEN]>>,
        allowed_syscalls: Option<BpfHashMap<MapData, u64, u32>>,
        blocked_pid_cache: HashSet<u32>,
    ) -> Self {
        Self {
            bpf: Some(bpf),
            blocked_pids,
            agent_cgroups,
            allowed_pids,
            pid_scope_flags,
            pid_path_prefixes,
            allowed_syscalls,
            attached: true,
            blocked_pid_cache,
            agent_cgroup_cache: HashSet::new(),
            allowed_pid_cache: std::collections::HashMap::new(),
            pid_scope_cache: std::collections::HashMap::new(),
        }
    }

    /// ปลดการแนบ LSM Hook และยกเลิกโหลดโปรแกรม eBPF
    pub fn detach(&mut self) {
        // Dropping the Bpf object detaches all programs and unloads them
        self.bpf = None;
        self.blocked_pids = None;
        self.agent_cgroups = None;
        self.allowed_pids = None;
        self.pid_scope_flags = None;
        self.pid_path_prefixes = None;
        self.allowed_syscalls = None;
        self.attached = false;
        self.blocked_pid_cache.clear();
        self.agent_cgroup_cache.clear();
        self.allowed_pid_cache.clear();
        self.pid_scope_cache.clear();
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

    /// อนุญาต PID นี้: ลบออกจาก block-list และเพิ่มเข้า PID allow-list
    /// สำหรับ agent ใน cgroup ที่ลงทะเบียนแล้ว การอยู่ใน allow-list คือ
    /// เงื่อนไขเดียวที่ทำให้ syscall ผ่าน (default-DENY ในโลกของ agent)
    ///
    /// H2: authorization ผูกกับ `(PID, start_time)` — อ่าน start time จาก
    /// `/proc/<pid>/stat` ณ ตอนอนุญาต ถ้า PID ถูกแจกใหม่ให้ process อื่น
    /// start time จะไม่ตรงและ kernel hook จะ DENY เอง
    ///
    /// # Errors
    ///
    /// โหมด real eBPF: ส่งคืนข้อผิดพลาดหากอ่าน `/proc/<pid>/stat` ไม่ได้
    /// (ระบุตัว process ไม่ได้ = fail closed ห้ามอนุญาต) หรือเขียน BPF map
    /// ไม่สำเร็จ
    pub fn allow_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(map) = self.blocked_pids.as_mut() {
            let _ = map.remove(&pid);
        }
        self.blocked_pid_cache.remove(&pid);

        // โหมด real ต้องระบุ process instance ได้จริง (fail closed) —
        // โหมดจำลองไม่มี kernel enforcement จึงยอมรับ PID สมมุติในเทสต์ได้
        let start_ticks = if self.allowed_pids.is_some() {
            crate::proc_identity::process_start_ticks(pid)?
        } else {
            crate::proc_identity::process_start_ticks(pid).unwrap_or(0)
        };
        if let Some(map) = self.allowed_pids.as_mut() {
            map.insert(pid, start_ticks, 0)?;
        }
        self.allowed_pid_cache.insert(pid, start_ticks);
        Ok(())
    }

    /// บล็อก PID นี้ (เพิ่มเข้า block-list และถอนออกจาก allow-list) —
    /// ใช้เมื่อ token ถูกเพิกถอน/หมดอายุ หรือ Immune System สั่งกักกัน/kill agent
    pub fn deny_pid(&mut self, pid: u32) -> Result<()> {
        if let Some(map) = self.blocked_pids.as_mut() {
            map.insert(pid, 1, 0)?;
        }
        self.blocked_pid_cache.insert(pid);
        if let Some(map) = self.allowed_pids.as_mut() {
            let _ = map.remove(&pid);
        }
        self.allowed_pid_cache.remove(&pid);
        self.clear_pid_scope(pid);
        Ok(())
    }

    #[must_use]
    /// คืนค่า `true` หาก PID นี้ยังคงถูกอนุญาต (ไม่อยู่ใน block-list)
    /// หมายเหตุ: สำหรับ PID ใน agent cgroup ต้องดู `is_pid_allow_listed`
    /// ประกอบ เพราะโลกของ agent เป็น default-DENY
    pub fn allows_pid(&self, pid: u32) -> bool {
        !self.blocked_pid_cache.contains(&pid)
    }

    #[must_use]
    /// คืนค่า `true` หาก PID นี้อยู่ใน allow-list (ถือ token ที่ valid) —
    /// เงื่อนไขจำเป็นสำหรับ process ใน agent cgroup ที่ลงทะเบียนแล้ว
    pub fn is_pid_allow_listed(&self, pid: u32) -> bool {
        self.allowed_pid_cache.contains_key(&pid)
    }

    /// ถอน PID ออกจาก allow-list โดยไม่เพิ่มเข้า block-list — ใช้ rollback
    /// เมื่อ authorize สำเร็จแต่ย้าย PID เข้า agent cgroup ไม่ได้ (PID กลับ
    /// สู่สถานะเดิมก่อน authorize แทนที่จะโดน quarantine ทั้งที่ไม่ได้ทำผิด)
    pub fn withdraw_pid(&mut self, pid: u32) {
        if let Some(map) = self.allowed_pids.as_mut() {
            let _ = map.remove(&pid);
        }
        self.allowed_pid_cache.remove(&pid);
        self.clear_pid_scope(pid);
    }

    /// ผูก scope ที่ compile จาก intent เข้ากับ PID (H3) — ต้องเรียกหลัง
    /// `allow_pid` และก่อนปล่อย agent เริ่มงาน จึงจะไม่มีหน้าต่างที่ agent
    /// วิ่งแบบไร้ขอบเขต
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากเขียน BPF map ไม่สำเร็จ
    pub fn set_pid_scope(&mut self, pid: u32, scope: &crate::scope::IntentScope) -> Result<()> {
        if let Some(map) = self.pid_scope_flags.as_mut() {
            map.insert(pid, scope.class_flags, 0)?;
        }
        if let Some(set) = scope.path_set_bytes() {
            if let Some(map) = self.pid_path_prefixes.as_mut() {
                map.insert(pid, set, 0)?;
            }
        } else if let Some(map) = self.pid_path_prefixes.as_mut() {
            let _ = map.remove(&pid);
        }
        self.pid_scope_cache.insert(pid, scope.clone());
        Ok(())
    }

    /// ถอน scope ของ PID ออกจากทั้ง BPF maps และ cache — เรียกอัตโนมัติ
    /// จาก `deny_pid`/`withdraw_pid` เพื่อไม่ให้ scope ตกค้างไปจำกัด PID
    /// ที่ถูกแจกใหม่ให้ process อื่น
    pub fn clear_pid_scope(&mut self, pid: u32) {
        if let Some(map) = self.pid_scope_flags.as_mut() {
            let _ = map.remove(&pid);
        }
        if let Some(map) = self.pid_path_prefixes.as_mut() {
            let _ = map.remove(&pid);
        }
        self.pid_scope_cache.remove(&pid);
    }

    #[must_use]
    /// คืนค่า scope ที่ผูกกับ PID นี้อยู่ (`None` = ไม่มีการจำกัดจาก intent)
    pub fn pid_scope(&self, pid: u32) -> Option<crate::scope::IntentScope> {
        self.pid_scope_cache.get(&pid).cloned()
    }

    #[must_use]
    /// คืนค่า snapshot ของ PID ทั้งหมดที่ถูกบล็อกอยู่ในปัจจุบัน
    pub fn blocked_pids(&self) -> HashSet<u32> {
        self.blocked_pid_cache.clone()
    }

    /// ลงทะเบียน cgroup id เป็น agent scope — ทุก process ใน cgroup นี้จะ
    /// ตกอยู่ใต้ default-DENY ทันที (ต้องมี PID ใน allow-list จึงผ่าน)
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากเขียน BPF map ไม่สำเร็จ
    pub fn register_agent_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        if let Some(map) = self.agent_cgroups.as_mut() {
            map.insert(cgroup_id, 1, 0)?;
        }
        self.agent_cgroup_cache.insert(cgroup_id);
        info!(
            cgroup_id,
            "LSM: agent cgroup registered — default-DENY scope active"
        );
        Ok(())
    }

    /// ถอนการลงทะเบียน cgroup id ออกจาก agent scope — process ใน cgroup นี้
    /// จะกลับไปเป็นโลกของ host (ปล่อยผ่าน ยกเว้น PID ที่ถูก quarantine)
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากเขียน BPF map ไม่สำเร็จ
    pub fn unregister_agent_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
        if let Some(map) = self.agent_cgroups.as_mut() {
            let _ = map.remove(&cgroup_id);
        }
        self.agent_cgroup_cache.remove(&cgroup_id);
        Ok(())
    }

    #[must_use]
    /// คืนค่า `true` หาก cgroup id นี้ลงทะเบียนเป็น agent scope อยู่
    pub fn is_agent_cgroup(&self, cgroup_id: u64) -> bool {
        self.agent_cgroup_cache.contains(&cgroup_id)
    }

    #[must_use]
    /// คืนค่า snapshot ของ cgroup id ทั้งหมดที่ลงทะเบียนเป็น agent scope
    pub fn agent_cgroups(&self) -> HashSet<u64> {
        self.agent_cgroup_cache.clone()
    }
}

impl Default for LsmAttachment {
    fn default() -> Self {
        Self::new()
    }
}

/// พยายามโหลดและแนบโปรแกรม LSM eBPF จริงผ่าน Aya
///
/// โปรแกรมที่แนบ (ชื่อ LSM hook ต้องตรงกับ kernel BTF trampoline `bpf_lsm_<hook>`),
/// ทุกตัวใช้ cgroup-scoped gate: host ปล่อยผ่าน, agent cgroup ที่ลงทะเบียน
/// เป็น default-DENY เว้นแต่ PID อยู่ใน `allowed_pids`, และ `blocked_pids`
/// (quarantine) ชนะทุกกรณี:
/// - `file_open` (kernel ≥5.7)
/// - `bprm_check_security` (kernel ≥5.5)
/// - `socket_create`
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหาก BPF .o file ไม่มี หรือ Aya โหลด/แนบไม่สำเร็จ
fn try_attach_real_lsm(engine: &LsmPolicyEngine) -> Result<LsmAttachment> {
    let metrics = kernel_metrics();
    let bpf_bytes = load_bpf_o("lsm-security")?;
    let mut bpf = aya::Bpf::load(&bpf_bytes)?;
    let blocked_pid_cache = HashSet::new();

    // Aya 0.12: LSM programs require kernel BTF (/sys/kernel/btf/vmlinux)
    // to resolve types between the BPF program and kernel LSM hooks.
    let btf = aya::Btf::from_sys_fs()
        .map_err(|e| anyhow::anyhow!("Cannot load kernel BTF from /sys/kernel/btf/vmlinux: {e}"))?;

    // ── file_open LSM hook ──
    // ตรวจสอบทุกครั้งที่มีการเปิดไฟล์ โดยเช็ค PID จาก blocked_pids map
    // หมายเหตุ: program_mut ใช้ชื่อฟังก์ชัน C ("lsm_file_open"); load ใช้ชื่อ LSM
    // hook ("file_open") ที่ Aya จะ resolve เป็น BTF trampoline `bpf_lsm_file_open`
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_file_open")
            .ok_or_else(|| anyhow::anyhow!("lsm_file_open program not found"))?
            .try_into()?;
        prog.load("file_open", &btf)?;
        // attach() with no arguments — the hook name was already specified in load()
        let link = prog.attach()?;
        // Leak the link so it stays alive for the daemon's lifetime.
        // The kernel keeps a reference via the file descriptor.
        Box::leak(Box::new(link));
        info!("LSM eBPF: file_open attached");
    }

    // ── bprm_check_security LSM hook ──
    // ตรวจสอบก่อน execute ใหม่ ห้าม fork/exec โดยไม่ได้รับอนุญาต
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_bprm_check")
            .ok_or_else(|| anyhow::anyhow!("lsm_bprm_check program not found"))?
            .try_into()?;
        prog.load("bprm_check_security", &btf)?;
        let link = prog.attach()?;
        Box::leak(Box::new(link));
        info!("LSM eBPF: bprm_check_security attached");
    }

    // ── socket_create LSM hook ──
    {
        let prog: &mut aya::programs::Lsm = bpf
            .program_mut("lsm_socket_create")
            .ok_or_else(|| anyhow::anyhow!("lsm_socket_create program not found"))?
            .try_into()?;
        prog.load("socket_create", &btf)?;
        let link = prog.attach()?;
        Box::leak(Box::new(link));
        info!("LSM eBPF: socket_create attached");
    }

    // ── populate blocked_pids eBPF map ──
    // ว่างเปล่าโดยดีฟอลต์ — ทุก PID (รวมถึง daemon เอง) ได้รับอนุญาตจนกว่าจะถูก
    // เพิ่มเข้า block-list อย่างชัดเจน (token ถูกเพิกถอน/หมดอายุ หรือ Immune
    // System สั่งกักกัน) ไม่ต้องเติมอะไรตอน attach
    let blocked_pids = if let Some(map) = bpf.take_map("blocked_pids") {
        Some(BpfHashMap::<_, u32, u32>::try_from(map)?)
    } else {
        warn!("LSM eBPF: could not create HashMap from blocked_pids map");
        None
    };

    // ── agent_cgroups eBPF map ──
    // ว่างเปล่าตอน attach = ไม่มี agent scope = ทั้งระบบคือโลกของ host
    // (ปล่อยผ่าน) — daemon จะลงทะเบียน cgroup id ผ่าน register_agent_cgroup
    // หลัง boot เมื่อ config กำหนด agent_cgroup_path ไว้
    let agent_cgroups = if let Some(map) = bpf.take_map("agent_cgroups") {
        Some(BpfHashMap::<_, u64, u32>::try_from(map)?)
    } else {
        warn!("LSM eBPF: could not create HashMap from agent_cgroups map");
        None
    };

    // ── allowed_pids eBPF map ──
    // ว่างเปล่าตอน attach — PID จะถูกเพิ่มเมื่อ authorize_process_token
    // ตรวจ capability token ผ่าน และถูกถอนเมื่อ token หมดอายุ/ถูกเพิกถอน
    // ค่าใน map คือ start ticks ของ process instance (H2)
    let allowed_pids = if let Some(map) = bpf.take_map("allowed_pids") {
        Some(BpfHashMap::<_, u32, u64>::try_from(map)?)
    } else {
        warn!("LSM eBPF: could not create HashMap from allowed_pids map");
        None
    };

    // ── H3 scope maps ──
    // ว่างเปล่าตอน attach — daemon เขียน scope ที่ compile จาก intent
    // ผ่าน set_pid_scope ก่อนปล่อย agent เริ่มงาน
    let pid_scope_flags = if let Some(map) = bpf.take_map("pid_scope_flags") {
        Some(BpfHashMap::<_, u32, u32>::try_from(map)?)
    } else {
        warn!("LSM eBPF: could not create HashMap from pid_scope_flags map");
        None
    };
    let pid_path_prefixes = if let Some(map) = bpf.take_map("pid_path_prefixes") {
        Some(BpfHashMap::<_, u32, [u8; crate::scope::PATH_SET_LEN]>::try_from(map)?)
    } else {
        warn!("LSM eBPF: could not create HashMap from pid_path_prefixes map");
        None
    };

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
        blocked_pids,
        agent_cgroups,
        allowed_pids,
        pid_scope_flags,
        pid_path_prefixes,
        allowed_syscalls,
        blocked_pid_cache,
    ))
}

/// ฟังก์ชันหลักสำหรับแนบ LSM Hook เข้ากับ Linux Kernel
///
/// พยายามแนบ real LSM eBPF hooks ก่อน หากล้มเหลว:
/// - `enable_fallback == true`  → fallback เป็นโหมดจำลอง (userspace policy engine)
/// - `enable_fallback == false` → fail closed (คืน error) เพื่อไม่ให้ production ที่สั่ง
///   `--no-bpf-fallback` แอบรัน enforcement ใน userspace โดยไม่รู้ตัว
///   (ต้องสอดคล้องกับ tracer path ที่เคารพ flag เดียวกัน)
///
/// # Errors
///
/// ส่งคืน `LsmError::AttachmentFailed` หาก real attach ล้มเหลวและ `enable_fallback == false`
#[instrument(skip(engine))]
pub fn attach_lsm_hooks(
    engine: Arc<LsmPolicyEngine>,
    enable_fallback: bool,
) -> Result<LsmAttachment> {
    let metrics = kernel_metrics();
    match try_attach_real_lsm(&engine) {
        Ok(attachment) => {
            info!("LSM hooks: real eBPF mode — kernel-level enforcement active");
            Ok(attachment)
        }
        Err(e) if !enable_fallback => {
            metrics.record_attach_attempt("lsm", "failed");
            error!(
                error = %e,
                "LSM real eBPF attachment failed and fallback is disabled — refusing to run in userspace simulation"
            );
            // พ่วง LsmError ไว้บนสุด (ให้ downcast ได้) โดยคง source chain
            // ของ aya ไว้ — verifier log อยู่ในนั้น ถ้าตัดทิ้งจะ debug ไม่ได้
            Err(e.context(LsmError::AttachmentFailed))
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
        assert_eq!(
            engine.decision_for_syscall(None, "read"),
            LsmDecision::Allow
        );
        assert_eq!(
            engine.decision_for_syscall(None, "write"),
            LsmDecision::Allow
        );
        assert_eq!(
            engine.decision_for_syscall(None, "recvmsg"),
            LsmDecision::Allow
        );
    }

    #[test]
    fn execve_fork_denied_socket_allowed() {
        // ทดสอบว่า execve/fork ถูกปฏิเสธ แต่ socket อนุญาต (network-aware agents)
        let engine = LsmPolicyEngine::new();
        assert_eq!(
            engine.decision_for_syscall(None, "execve"),
            LsmDecision::Deny
        );
        assert_eq!(engine.decision_for_syscall(None, "fork"), LsmDecision::Deny);
        assert_eq!(
            engine.decision_for_syscall(None, "socket"),
            LsmDecision::Allow
        );
    }

    #[test]
    fn unknown_denied() {
        // ทดสอบว่า syscall ที่ไม่รู้จักต้องถูกปฏิเสธตามหลัก fail-closed
        let engine = LsmPolicyEngine::new();
        assert_eq!(
            engine.decision_for_syscall(None, "definitely_not_a_real_syscall"),
            LsmDecision::Deny
        );
        assert_eq!(engine.decision_for_syscall(None, ""), LsmDecision::Deny);
        assert_eq!(
            engine.decision_for_syscall(None, "definitely_not_a_real_syscall_2"),
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
    fn attach_fails_closed_when_fallback_disabled_without_privileges() {
        // ในสภาพแวดล้อมทดสอบ (ไม่มี CAP_BPF) real attach จะล้มเหลวเสมอ
        // enable_fallback = false ต้องคืน error ไม่ใช่แอบ degrade เป็น simulation
        // (ถ้ารันบน host ที่ attach จริงได้ จะได้ Ok(real) ซึ่งก็ถูกต้องเช่นกัน)
        let engine = Arc::new(LsmPolicyEngine::new());
        match attach_lsm_hooks(engine, false) {
            Err(e) => {
                // fail-closed ตามคาดในเครื่องไม่มีสิทธิ์ — ต้องเป็น AttachmentFailed
                assert!(
                    matches!(
                        e.downcast_ref::<LsmError>(),
                        Some(LsmError::AttachmentFailed)
                    ),
                    "expected LsmError::AttachmentFailed, got: {e}"
                );
            }
            Ok(attachment) => assert!(
                attachment.is_real(),
                "with fallback disabled, a returned attachment must be REAL, never simulation"
            ),
        }
    }

    #[test]
    fn attach_falls_back_to_simulation_when_enabled() {
        // enable_fallback = true → บนเครื่องไม่มีสิทธิ์ต้องได้ simulation attachment (Ok)
        let engine = Arc::new(LsmPolicyEngine::new());
        let attachment =
            attach_lsm_hooks(engine, true).expect("fallback enabled must never error out");
        assert!(attachment.is_attached());
    }

    #[test]
    fn attachment_pid_block_list_can_be_updated() {
        let mut attachment = LsmAttachment::new();
        // Host world: an unknown PID is not quarantined until explicitly blocked.
        assert!(attachment.allows_pid(4242));

        attachment.deny_pid(4242).expect("deny should succeed");
        assert!(!attachment.allows_pid(4242));

        attachment.allow_pid(4242).expect("allow should succeed");
        assert!(attachment.allows_pid(4242));
    }

    #[test]
    fn attachment_agent_cgroup_registration_lifecycle() {
        // H1: ลงทะเบียน/ถอน cgroup scope ต้องสะท้อนใน snapshot ทันที
        let mut attachment = LsmAttachment::new();
        assert!(!attachment.is_agent_cgroup(42));

        attachment
            .register_agent_cgroup(42)
            .expect("register should succeed");
        assert!(attachment.is_agent_cgroup(42));
        assert!(attachment.agent_cgroups().contains(&42));

        attachment
            .unregister_agent_cgroup(42)
            .expect("unregister should succeed");
        assert!(!attachment.is_agent_cgroup(42));
        assert!(attachment.agent_cgroups().is_empty());
    }

    #[test]
    fn allow_pid_populates_allow_list_and_deny_pid_withdraws_it() {
        // H1: allow_pid ต้องใส่ PID เข้า allow-list (เงื่อนไขผ่าน default-DENY
        // ใน agent cgroup) และ deny_pid ต้องถอนออกพร้อม quarantine
        let mut attachment = LsmAttachment::new();
        assert!(!attachment.is_pid_allow_listed(7));

        attachment.allow_pid(7).expect("allow should succeed");
        assert!(attachment.is_pid_allow_listed(7));

        attachment.deny_pid(7).expect("deny should succeed");
        assert!(!attachment.is_pid_allow_listed(7));
        assert!(!attachment.allows_pid(7));
    }

    #[test]
    fn withdraw_pid_removes_allow_list_without_quarantine() {
        // rollback path: ถอน allow-list โดยไม่ block — PID กลับสู่สถานะ
        // ก่อน authorize (โลกของ host) ไม่ใช่โดนลงโทษ
        let mut attachment = LsmAttachment::new();
        attachment.allow_pid(9).expect("allow should succeed");
        assert!(attachment.is_pid_allow_listed(9));

        attachment.withdraw_pid(9);
        assert!(!attachment.is_pid_allow_listed(9));
        assert!(attachment.allows_pid(9), "withdraw must not quarantine");
    }

    #[test]
    fn intent_scope_binds_and_clears_with_pid() {
        // H3: scope ต้องถูกถอนพร้อม authorization เสมอ — ไม่งั้น PID ที่ถูก
        // แจกใหม่จะโดนขอบเขตของ agent เก่าจำกัดอย่างไม่ตั้งใจ
        let mut attachment = LsmAttachment::new();
        let scope = crate::scope::IntentScope {
            class_flags: crate::scope::SCOPE_FILE_OPEN,
            path_prefixes: vec!["/data".to_string()],
        };

        attachment.allow_pid(77).expect("allow should succeed");
        attachment
            .set_pid_scope(77, &scope)
            .expect("set scope should succeed");
        assert_eq!(attachment.pid_scope(77), Some(scope));

        attachment.withdraw_pid(77);
        assert!(
            attachment.pid_scope(77).is_none(),
            "withdraw must clear the scope too"
        );

        attachment.allow_pid(78).expect("allow should succeed");
        attachment
            .set_pid_scope(
                78,
                &crate::scope::IntentScope {
                    class_flags: 0,
                    path_prefixes: Vec::new(),
                },
            )
            .expect("set scope should succeed");
        attachment.deny_pid(78).expect("deny should succeed");
        assert!(
            attachment.pid_scope(78).is_none(),
            "deny must clear the scope too"
        );
    }

    #[test]
    fn detach_clears_cgroup_scope_state() {
        let mut attachment = LsmAttachment::new();
        attachment
            .register_agent_cgroup(1234)
            .expect("register should succeed");
        attachment.allow_pid(55).expect("allow should succeed");

        attachment.detach();
        assert!(!attachment.is_agent_cgroup(1234));
        assert!(!attachment.is_pid_allow_listed(55));
    }

    #[test]
    fn default_is_deny() {
        // ทดสอบว่า default_decision ของ LsmPolicyEngine ต้องเป็น Deny (fail-closed)
        let engine = LsmPolicyEngine::default();
        // ทดสอบด้วย syscall สุ่มที่ไม่อยู่ใน allowlist
        assert_eq!(
            engine.decision_for_syscall(None, "this_syscall_should_not_exist"),
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
                engine.decision_for_syscall(None, syscall),
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
        assert_eq!(
            engine.decision_for_syscall(None, "socket"),
            LsmDecision::Deny
        );
        assert_eq!(
            engine.decision_for_syscall(None, "read"),
            LsmDecision::Allow
        );
    }

    #[test]
    fn switch_profile_updates_allowlist_runtime() {
        let engine = LsmPolicyEngine::new();
        assert_eq!(engine.active_profile_name(), "runtime");
        engine
            .set_active_profile("strict")
            .expect("strict profile should exist");
        assert_eq!(engine.active_profile_name(), "strict");
        assert_eq!(
            engine.decision_for_syscall(None, "socket"),
            LsmDecision::Deny
        );
        assert_eq!(
            engine.decision_for_syscall(None, "read"),
            LsmDecision::Allow
        );
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
        // enable_fallback = true → บนเครื่องไม่มีสิทธิ์จะได้ simulation attachment (ไม่ error)
        let mut attachment = match attach_lsm_hooks(engine, true) {
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
            // Verify PID block-list operations. Default-allow: own PID is
            // never inserted into blocked_pids at attach time, so it must
            // already be allowed.
            let own_pid = std::process::id();
            assert!(
                attachment.allows_pid(own_pid),
                "own PID should be allowed by default (not in block-list)"
            );

            attachment.deny_pid(99999).expect("deny_pid should succeed");
            assert!(
                !attachment.allows_pid(99999),
                "denied PID should be in block-list"
            );

            // H2: real mode ต้อง fail closed เมื่อระบุ process instance
            // ไม่ได้ — PID 99999 ไม่มี /proc entry จึงห้ามอนุญาต
            assert!(
                attachment.allow_pid(99999).is_err(),
                "allow_pid must fail closed for a PID without /proc identity"
            );

            // ขา allow ปกติ: ใช้ PID ตัวเองซึ่งมี /proc/<pid>/stat จริง
            attachment
                .allow_pid(own_pid)
                .expect("allow_pid should succeed for a live process");
            assert!(
                attachment.is_pid_allow_listed(own_pid),
                "live PID should be allow-listed with its start time"
            );

            eprintln!("LSM: PID block-list + identity-bound allow-list verified");
        }

        // Detach
        attachment.detach();
        assert!(!attachment.is_attached(), "should be detached after detach");
        eprintln!("PASS: LSM full attachment lifecycle validated");
    }

    #[test]
    fn test_polymorphic_agent_dna_mutation() {
        let engine = LsmPolicyEngine::new();
        let pid1 = 12345u32;
        let pid2 = 54321u32;

        let salt1 = [0u8; 16];
        let salt2 = [255u8; 16];

        engine.register_polymorphic_pid(pid1, "runtime", &salt1);
        engine.register_polymorphic_pid(pid2, "runtime", &salt2);

        // Verify that critical syscalls like read and write are still allowed for both
        assert_eq!(
            engine.decision_for_syscall(Some(pid1), "read"),
            LsmDecision::Allow
        );
        assert_eq!(
            engine.decision_for_syscall(Some(pid2), "read"),
            LsmDecision::Allow
        );
        assert_eq!(
            engine.decision_for_syscall(Some(pid1), "write"),
            LsmDecision::Allow
        );
        assert_eq!(
            engine.decision_for_syscall(Some(pid2), "write"),
            LsmDecision::Allow
        );

        // Verify that non-critical syscalls have different allow status (polymorphic diversity)
        // We will scan all non-critical allowed syscalls of the runtime profile to find if there is diversity.
        let allowed_global = engine.get_allowed_syscalls();
        let mut diff_found = false;

        for syscall in &allowed_global {
            let dec1 = engine.decision_for_syscall(Some(pid1), syscall);
            let dec2 = engine.decision_for_syscall(Some(pid2), syscall);
            if dec1 != dec2 {
                diff_found = true;
                break;
            }
        }

        assert!(
            diff_found,
            "PAD: Spawning agents with different salts should produce diverse allowlists!"
        );
    }
}
