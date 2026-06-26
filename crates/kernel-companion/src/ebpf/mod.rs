//! # eBPF Syscall Tracer — Host-side Runtime (ANK-003)
//!
//! โมดูลนี้ทำหน้าที่เป็น **userspace runtime** สำหรับโปรแกรม eBPF ที่รันอยู่ใน Kernel Space
//! โดยใช้ Aya framework ในการโหลด, แนบ tracepoint, และอ่าน ring buffer events แบบ async
//!
//! ## สถาปัตยกรรม
//! ```text
//! Linux Kernel
//!   └── tracepoint/raw_syscalls/sys_enter  ← eBPF program hook
//!         │  ring buffer
//!         ▼
//! [SyscallTracer daemon]  ← โมดูลนี้ (userspace)
//!   └── IntentBus  ← ส่ง SyscallEvent เป็น Intent
//!         ▼
//! [LsmPolicyEngine]  ← ตัดสินใจ Allow/Deny (ANK-004)
//! ```
//!
//! ## Performance Budget (plan §3)
//! - eBPF tracer overhead: **< 3% CPU**
//! - Ring buffer poll interval: **1ms**
//! - Syscall decision latency: **P99 < 1ms**

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, instrument, warn};

use crate::lsm::{LsmDecision, LsmPolicyEngine};

// ---- Types ----

/// ข้อผิดพลาดที่อาจเกิดจาก eBPF Tracer
#[derive(Debug, Error)]
pub enum TracerError {
    /// ล้มเหลวในการโหลด eBPF object ลงสู่ Kernel
    #[error("ล้มเหลวในการโหลด eBPF program: {0}")]
    LoadFailed(String),
    /// ล้มเหลวในการแนบ tracepoint hook
    #[error("ล้มเหลวในการแนบ tracepoint: {0}")]
    AttachFailed(String),
    /// ไม่สามารถอ่านข้อมูลจาก ring buffer
    #[error("ไม่สามารถอ่าน ring buffer: {0}")]
    RingBufferError(String),
    /// Tracer ถูกยกเลิกการทำงาน (graceful shutdown)
    #[error("tracer ถูกยกเลิก")]
    Cancelled,
}

/// เหตุการณ์ syscall ที่จับได้จาก eBPF ring buffer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    /// หมายเลข syscall (เช่น 0=read, 1=write)
    pub syscall_nr: u64,
    /// ชื่อ syscall (resolve จาก syscall_nr)
    pub syscall_name: String,
    /// PID ของ process ที่เรียก
    pub pid: u32,
    /// UID ของ process ที่เรียก
    pub uid: u32,
    /// timestamp ในหน่วย nanoseconds (จาก bpf_ktime_get_ns)
    pub timestamp_ns: u64,
    /// ผลการตัดสินใจนโยบาย (Allow/Deny) จาก LSM engine
    pub decision: PolicyDecision,
}

/// ผลการตัดสินใจของ Policy Engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// อนุญาตให้เรียก syscall นี้ได้
    Allow,
    /// ปฏิเสธ — syscall นี้ถูกบล็อกตามนโยบาย Zero-Trust
    Deny,
}

/// ช่องทางรับ SyscallEvent แบบ async (consumer side)
pub type SyscallEventReceiver = mpsc::Receiver<SyscallEvent>;

// ---- SyscallTracer ----

/// eBPF Syscall Tracer — host-side daemon ที่โหลดโปรแกรม eBPF และอ่าน events
///
/// **Phase 1 (current)**: จำลองด้วย software-only ring buffer  
/// **Phase 2**: เชื่อมต่อ Aya loader กับ kernel tracepoint จริง
///
/// ใช้งาน:
/// ```rust,no_run
/// # use std::sync::Arc;
/// # use kernel_companion::lsm::LsmPolicyEngine;
/// # use kernel_companion::{SyscallTracer, tokio_util_cancel};
/// # #[tokio::main] async fn main() {
/// let (tracer, mut rx) = SyscallTracer::new(Arc::new(LsmPolicyEngine::new()));
/// let cancel = tokio_util_cancel::CancellationToken::new();
/// tokio::spawn(async move { let _ = tracer.run(cancel).await; });
/// while let Some(event) = rx.recv().await {
///     println!("syscall: {} -> {:?}", event.syscall_name, event.decision);
/// }
/// # }
/// ```
pub struct SyscallTracer {
    /// Policy Engine ใช้ตัดสินใจว่า syscall ใดควร Allow/Deny
    policy: Arc<LsmPolicyEngine>,
    /// ช่องทางส่ง events ออกสู่ consumer (Intent Bus, Audit Logger, ฯลฯ)
    event_tx: mpsc::Sender<SyscallEvent>,
    /// ตาราง syscall number → ชื่อ syscall (x86_64 ABI)
    syscall_table: HashMap<u64, &'static str>,
}

impl SyscallTracer {
    /// สร้าง SyscallTracer พร้อม channel ขนาด 4096 events
    #[must_use]
    pub fn new(policy: Arc<LsmPolicyEngine>) -> (Self, SyscallEventReceiver) {
        let (event_tx, event_rx) = mpsc::channel(4096);
        let tracer = Self {
            policy,
            event_tx,
            syscall_table: build_syscall_table(),
        };
        (tracer, event_rx)
    }

    /// ลูปหลักของ Tracer: โหลด eBPF → แนบ tracepoint → poll ring buffer
    ///
    /// # Errors
    /// คืน error หากโหลด eBPF หรือแนบ tracepoint ล้มเหลว
    ///
    /// ออกจากลูปเมื่อ `cancel` token ถูก trigger (graceful shutdown)
    #[instrument(skip(self, cancel))]
    pub async fn run(self, cancel: tokio_util_cancel::CancellationToken) -> Result<(), TracerError>
    where
        Self: Sized,
    {
        info!("SyscallTracer เริ่มทำงาน — กำลังโหลด eBPF program");

        // Phase 1: จำลอง ring buffer ด้วย software loop
        // Phase 2: แทนที่ด้วย Aya loader + RingBuf::try_from_map()
        self.run_simulation_loop(cancel).await
    }

    /// ลูปจำลอง (Phase 1): สร้าง synthetic syscall events สำหรับ integration testing
    /// ในการใช้งาน production จะถูกแทนที่ด้วย Aya ring buffer poll
    #[instrument(skip(self, cancel))]
    async fn run_simulation_loop(
        &self,
        cancel: tokio_util_cancel::CancellationToken,
    ) -> Result<(), TracerError> {
        info!("SyscallTracer รันในโหมดจำลอง (Phase 1 — ยังไม่ได้เชื่อมต่อ kernel จริง)");

        // จำลอง syscall events สำหรับ testing (read, write, execve, open)
        let simulated: &[(u64, u32, u32)] = &[
            (0, 1000, 1000), // read  - PID 1000
            (1, 1000, 1000), // write - PID 1000
            (59, 1001, 0),   // execve - PID 1001 (root)
            (2, 1002, 1000), // open - PID 1002
        ];

        for &(syscall_nr, pid, uid) in simulated.iter() {
            if cancel.is_cancelled() {
                info!("SyscallTracer ได้รับสัญญาณ cancel — หยุดทำงาน");
                return Err(TracerError::Cancelled);
            }

            let event = self.process_syscall_event(syscall_nr, pid, uid);
            debug!(
                syscall = %event.syscall_name,
                pid = event.pid,
                decision = ?event.decision,
                "ประมวลผล syscall event"
            );

            if self.event_tx.send(event).await.is_err() {
                warn!("ผู้รับ SyscallEvent ปิดไปแล้ว — หยุด tracer");
                break;
            }
        }

        info!("SyscallTracer หยุดทำงาน (simulation loop เสร็จสิ้น)");
        Ok(())
    }

    /// ประมวลผล syscall event และตัดสินใจนโยบาย
    #[instrument(skip(self), fields(syscall_nr, pid, uid))]
    fn process_syscall_event(&self, syscall_nr: u64, pid: u32, uid: u32) -> SyscallEvent {
        let syscall_name = self
            .syscall_table
            .get(&syscall_nr)
            .copied()
            .unwrap_or("unknown");

        // ตรวจสอบนโยบายความปลอดภัยกับ LSM Policy Engine
        let lsm_decision = self.policy.decision_for_syscall(syscall_name);
        let decision = match lsm_decision {
            LsmDecision::Allow => PolicyDecision::Allow,
            LsmDecision::Deny => {
                warn!(
                    syscall = syscall_name,
                    pid, uid, "LSM ปฏิเสธ syscall ตามนโยบาย Zero-Trust"
                );
                PolicyDecision::Deny
            }
        };

        SyscallEvent {
            syscall_nr,
            syscall_name: syscall_name.to_string(),
            pid,
            uid,
            // ใช้ simulation timestamp ใน Phase 1 (Phase 2 จะใช้ bpf_ktime_get_ns)
            timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0),
            decision,
        }
    }
}

// ---- ตาราง syscall x86_64 (ชุดสำคัญ) ----

/// สร้างตาราง syscall number → ชื่อ สำหรับ x86_64 Linux ABI
///
/// ที่มา: <https://filippo.io/linux-syscall-table/>
fn build_syscall_table() -> HashMap<u64, &'static str> {
    let mut table = HashMap::new();
    // syscalls พื้นฐาน I/O
    table.insert(0, "read");
    table.insert(1, "write");
    table.insert(2, "open");
    table.insert(3, "close");
    table.insert(4, "stat");
    table.insert(5, "fstat");
    table.insert(6, "lstat");
    table.insert(7, "poll");
    table.insert(8, "lseek");
    table.insert(9, "mmap");
    table.insert(10, "mprotect");
    table.insert(11, "munmap");
    table.insert(12, "brk");
    // syscalls เครือข่าย
    table.insert(41, "socket");
    table.insert(42, "connect");
    table.insert(43, "accept");
    table.insert(44, "sendto");
    table.insert(45, "recvfrom");
    table.insert(46, "sendmsg");
    table.insert(47, "recvmsg");
    // syscalls process/security
    table.insert(56, "clone");
    table.insert(57, "fork");
    table.insert(58, "vfork");
    table.insert(59, "execve");
    table.insert(60, "exit");
    table.insert(61, "wait4");
    table.insert(62, "kill");
    table.insert(63, "uname");
    // syscalls file/permission
    table.insert(80, "chdir");
    table.insert(81, "fchdir");
    table.insert(82, "rename");
    table.insert(83, "mkdir");
    table.insert(84, "rmdir");
    table.insert(85, "creat");
    table.insert(86, "link");
    table.insert(87, "unlink");
    table.insert(88, "symlink");
    table.insert(89, "readlink");
    table.insert(90, "chmod");
    table.insert(91, "fchmod");
    table.insert(92, "chown");
    table.insert(93, "fchown");
    table.insert(94, "lchown");
    table
}

// ---- Stub สำหรับ CancellationToken (ใช้ใน Phase 1 ก่อน tokio-util) ----
// Phase 2: แทนด้วย tokio_util::sync::CancellationToken จริง

/// stub module สำหรับ CancellationToken ใช้ใน Phase 1
pub mod tokio_util_cancel {
    /// CancellationToken จำลองสำหรับ Phase 1 (ยังไม่ได้เชื่อมต่อ tokio-util จริง)
    #[derive(Clone, Default)]
    pub struct CancellationToken {
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl CancellationToken {
        /// สร้าง token ใหม่
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// ส่งสัญญาณยกเลิก
        pub fn cancel(&self) {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        /// ตรวจสอบว่าถูกยกเลิกแล้วหรือไม่
        #[must_use]
        pub fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracer() -> (SyscallTracer, SyscallEventReceiver) {
        SyscallTracer::new(Arc::new(LsmPolicyEngine::new()))
    }

    #[test]
    fn process_read_syscall_is_allowed() {
        // ทดสอบว่า syscall read (nr=0) ถูกอนุญาตตามนโยบาย
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 1000, 1000);
        assert_eq!(event.syscall_name, "read");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_write_syscall_is_allowed() {
        // ทดสอบว่า syscall write (nr=1) ถูกอนุญาตตามนโยบาย
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(1, 1000, 1000);
        assert_eq!(event.syscall_name, "write");
        assert_eq!(event.decision, PolicyDecision::Allow);
    }

    #[test]
    fn process_execve_syscall_is_denied() {
        // ทดสอบว่า syscall execve (nr=59) ถูกปฏิเสธ (ไม่อยู่ใน allowlist)
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(59, 1001, 0);
        assert_eq!(event.syscall_name, "execve");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn unknown_syscall_is_denied() {
        // ทดสอบว่า syscall ที่ไม่รู้จักต้องถูก deny ตามหลัก fail-closed
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(9999, 1000, 1000);
        assert_eq!(event.syscall_name, "unknown");
        assert_eq!(event.decision, PolicyDecision::Deny);
    }

    #[test]
    fn syscall_event_contains_pid_and_uid() {
        // ทดสอบว่า event เก็บ pid และ uid ถูกต้อง
        let (tracer, _rx) = make_tracer();
        let event = tracer.process_syscall_event(0, 42, 1337);
        assert_eq!(event.pid, 42);
        assert_eq!(event.uid, 1337);
    }

    #[tokio::test]
    async fn simulation_loop_sends_events_to_channel() {
        // ทดสอบว่า run_simulation_loop ส่ง events ไปยัง channel ได้จริง
        let cancel = tokio_util_cancel::CancellationToken::new();
        let (tracer, mut rx) = make_tracer();

        tokio::spawn(async move {
            let _ = tracer.run(cancel).await;
        });

        // รอรับ event อย่างน้อย 1 event
        let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("ควรได้รับ event ภายใน 500ms")
            .expect("channel ควรยังเปิดอยู่");

        // event แรกคือ read (nr=0)
        assert_eq!(event.syscall_nr, 0);
        assert_eq!(event.syscall_name, "read");
    }

    #[test]
    fn syscall_table_covers_common_syscalls() {
        // ทดสอบว่าตาราง syscall มีรายการสำคัญครบ
        let table = build_syscall_table();
        assert!(table.contains_key(&0), "ต้องมี read");
        assert!(table.contains_key(&1), "ต้องมี write");
        assert!(table.contains_key(&59), "ต้องมี execve");
        assert!(table.contains_key(&41), "ต้องมี socket");
        assert!(table.len() >= 30, "ตารางควรมีอย่างน้อย 30 รายการ");
    }
}
