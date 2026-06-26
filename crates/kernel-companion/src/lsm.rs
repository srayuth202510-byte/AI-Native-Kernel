use anyhow::Result;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, instrument, warn};

/// ข้อผิดพลาดของการควบคุม LSM (Linux Security Module)
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LsmError {
    /// การเรียกใช้งานระบบ (Syscall) ถูกปฏิเสธตามนโยบายความปลอดภัย
    #[error("policy decision denied")]
    Denied,
    /// ล้มเหลวในขั้นตอนการแนบ Hook เข้ากับ Kernel
    #[error("attachment failed")]
    AttachmentFailed,
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
#[derive(Debug, Clone)]
pub struct LsmPolicyEngine {
    /// ผลการตัดสินใจเริ่มต้นกรณีไม่ตรงกับเงื่อนไขใด ๆ (Fail-closed: DENY)
    default_decision: LsmDecision,
}

impl LsmPolicyEngine {
    /// สร้างอินสแตนซ์ของ LSM Policy Engine โดยตั้งค่าเริ่มต้นให้ปฏิเสธการเรียกใช้งานไว้ก่อน
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_decision: LsmDecision::Deny,
        }
    }

    /// ตรวจสอบ syscall และตัดสินใจว่าจะยอมรับหรือปฏิเสธตามกฎที่กำหนดไว้
    #[must_use]
    #[instrument(skip(self), fields(syscall = %syscall))]
    pub fn decision_for_syscall(&self, syscall: &str) -> LsmDecision {
        match syscall {
            // อนุญาตเฉพาะ syscall พื้นฐานที่จำเป็นสำหรับ agent ทั่วไป
            "read" | "write" | "recvmsg" => {
                debug!(decision = "allow", "อนุญาต syscall ตามนโยบาย Zero-Trust");
                LsmDecision::Allow
            }
            // ปฏิเสธ syscall อื่น ๆ ทั้งหมดเพื่อความปลอดภัยแบบ Zero-Trust
            _ => {
                warn!(decision = "deny", "ปฏิเสธ syscall ที่ไม่อยู่ใน allowlist");
                self.default_decision
            }
        }
    }
}

impl Default for LsmPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// โครงสร้างข้อมูลสำหรับอ้างอิงสถานะการเชื่อมต่อ LSM Hook
#[derive(Debug)]
pub struct LsmAttachment {
    /// บ่งชี้ว่ายังคงแนบอยู่กับ Kernel หรือไม่
    attached: bool,
}

impl LsmAttachment {
    /// สร้างอินสแตนซ์ของ LsmAttachment เพื่อจำลองการแนบสำเร็จ
    #[must_use]
    pub fn new() -> Self {
        Self { attached: true }
    }

    /// ปลดการแนบ LSM Hook
    pub fn detach(&mut self) {
        self.attached = false;
    }

    /// ตรวจสอบสถานะว่า LSM Hook ยังทำงานอยู่หรือไม่
    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attached
    }
}

impl Default for LsmAttachment {
    fn default() -> Self {
        Self::new()
    }
}

/// ฟังก์ชันช่วยในการแนบ LSM Hook เข้ากับ Linux Kernel
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหากตัวกรองความปลอดภัยแนบไม่สำเร็จ
pub fn attach_lsm_hooks(_engine: Arc<LsmPolicyEngine>) -> Result<LsmAttachment> {
    Ok(LsmAttachment::new())
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
    fn execve_fork_socket_denied() {
        // ทดสอบว่า syscall อันตราย เช่น execve, fork, socket ต้องถูกปฏิเสธ
        let engine = LsmPolicyEngine::new();
        assert_eq!(engine.decision_for_syscall("execve"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("fork"), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("socket"), LsmDecision::Deny);
    }

    #[test]
    fn unknown_denied() {
        // ทดสอบว่า syscall ที่ไม่รู้จักต้องถูกปฏิเสธตามหลัก fail-closed
        let engine = LsmPolicyEngine::new();
        assert_eq!(
            engine.decision_for_syscall("unknown_syscall"),
            LsmDecision::Deny
        );
        assert_eq!(engine.decision_for_syscall(""), LsmDecision::Deny);
        assert_eq!(engine.decision_for_syscall("mmap"), LsmDecision::Deny);
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
    fn default_is_deny() {
        // ทดสอบว่า default_decision ของ LsmPolicyEngine ต้องเป็น Deny (fail-closed)
        let engine = LsmPolicyEngine::default();
        // ทดสอบด้วย syscall สุ่มที่ไม่อยู่ใน allowlist
        assert_eq!(
            engine.decision_for_syscall("getpid"),
            LsmDecision::Deny,
            "ค่าเริ่มต้นต้องปฏิเสธ syscall ที่ไม่รู้จัก"
        );
    }
}
