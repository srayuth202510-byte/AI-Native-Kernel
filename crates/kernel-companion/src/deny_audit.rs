//! ตัวจำกัดอัตรา audit สำหรับ syscall ที่ถูก deny ถี่ ๆ
//!
//! ปัญหา: `syscall_denied` ต้องถูกบันทึกทุกคำตัดสิน (กฎบ้าน) แต่ tight loop ที่ถูก
//! deny จะสร้าง entry ถี่ตาม — หมื่นบรรทัดต่อวินาทีลงดิสก์คือ DoS ตัวเองผ่าน audit
//! วิธีแก้ตรงนี้: token-bucket ต่อ `(pid, syscall)` งบ `cap_per_sec` ต่อวินาที
//!
//! - ในงบ → [`DenyAuditAction::Audit`] บันทึกเดี่ยวเหมือนเดิม
//! - เกินงบ → [`DenyAuditAction::Suppress`] ข้ามการเขียน แต่**นับไว้**
//! - ขึ้นวินาทีใหม่และมีการข้าม → [`DenyAuditAction::Rollover`] ให้ผู้เรียกบันทึก
//!   summary หนึ่ง entry (จำนวนครั้งที่ถูกกลืนใน `reason`) **และ** บันทึก event
//!   ปัจจุบันเดี่ยวตามปกติ — ทุก decision จึงยังถูก "นับรวมใน audit" ไม่มีหายเงียบ
//!
//! โครงนี้เป็น pure logic (รับ `now` เป็นพารามิเตอร์) เพื่อให้เทสต์กำหนดเวลาเองได้
//! ไม่ต้องพึ่ง sleep จริง
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// เพดาน entry เดี่ยวต่อ (pid, syscall) ต่อวินาที — เกินกว่านี้รวมเป็น summary
pub const DENY_AUDIT_BURST_PER_SEC: u32 = 10;

/// ขนาด map สูงสุดก่อนล้าง (กันหน่วยความจำบวมเมื่อ PID หมุนเวียนเร็ว)
pub const DENY_AUDIT_MAX_TRACKED: usize = 4096;

/// ผลการตัดสินใจของ limiter สำหรับ deny หนึ่งครั้ง
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAuditAction {
    /// บันทึก entry เดี่ยว
    Audit,
    /// ข้ามการเขียน (นับไว้ใน `suppressed` ของหน้าต่างปัจจุบัน)
    Suppress,
    /// ขึ้นหน้าต่างใหม่: บันทึก summary ของหน้าต่างเก่า (จำนวนครั้งใน `suppressed`)
    /// **แล้ว** บันทึก event ปัจจุบันเดี่ยวตามปกติ
    Rollover { suppressed: u32 },
}

struct DenyWindow {
    started: Instant,
    audited: u32,
    suppressed: u32,
}

/// ตัวจำกัดอัตรา audit ของ denied syscall — เก็บ state ต่อ (pid, syscall)
pub struct DenyAuditLimiter {
    windows: HashMap<(u32, String), DenyWindow>,
    cap_per_sec: u32,
}

impl DenyAuditLimiter {
    /// สร้าง limiter ด้วยงบต่อวินาที
    #[must_use]
    pub fn new(cap_per_sec: u32) -> Self {
        Self {
            windows: HashMap::new(),
            cap_per_sec: cap_per_sec.max(1),
        }
    }

    /// งบดีฟอลต์สำหรับ production
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DENY_AUDIT_BURST_PER_SEC)
    }

    /// ตัดสินใจว่า deny ครั้งนี้ควรบันทึกอย่างไร (`now` รับจากผู้เรียกเพื่อให้เทสต์ได้)
    pub fn decide(&mut self, pid: u32, syscall: &str, now: Instant) -> DenyAuditAction {
        if self.windows.len() >= DENY_AUDIT_MAX_TRACKED {
            // กันบวม: PID หมุนเวียนเร็ว (fork bomb) จะเติม map ไม่รู้จบ
            // ล้างทั้งหมดดีกว่าปล่อยบวม — นับใหม่เริ่มที่ event นี้ (fail-open ของ
            // limiter ไม่ใช่ของ policy: การ deny ยังเกิดเหมือนเดิม แค่ audit
            // อาจบันทึกเดี่ยวเกินงบในวินาทีที่ล้าง)
            self.windows.clear();
        }
        let window = self
            .windows
            .entry((pid, syscall.to_string()))
            .or_insert(DenyWindow {
                started: now,
                audited: 0,
                suppressed: 0,
            });

        if now.duration_since(window.started) >= Duration::from_secs(1) {
            let suppressed = window.suppressed;
            window.started = now;
            window.audited = 1;
            window.suppressed = 0;
            if suppressed > 0 {
                return DenyAuditAction::Rollover { suppressed };
            }
            return DenyAuditAction::Audit;
        }

        if window.audited < self.cap_per_sec {
            window.audited += 1;
            DenyAuditAction::Audit
        } else {
            window.suppressed += 1;
            DenyAuditAction::Suppress
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN: u32 = 10;

    #[test]
    fn first_burst_is_audited_individually() {
        let mut limiter = DenyAuditLimiter::new(TEN);
        let now = Instant::now();
        for _ in 0..TEN {
            assert_eq!(limiter.decide(100, "execve", now), DenyAuditAction::Audit);
        }
    }

    #[test]
    fn beyond_cap_is_suppressed_and_counted() {
        let mut limiter = DenyAuditLimiter::new(3);
        let now = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.decide(100, "execve", now), DenyAuditAction::Audit);
        }
        assert_eq!(
            limiter.decide(100, "execve", now),
            DenyAuditAction::Suppress
        );
        assert_eq!(
            limiter.decide(100, "execve", now),
            DenyAuditAction::Suppress
        );
    }

    #[test]
    fn rollover_reports_suppressed_count() {
        let mut limiter = DenyAuditLimiter::new(2);
        let t0 = Instant::now();
        assert_eq!(limiter.decide(100, "execve", t0), DenyAuditAction::Audit);
        assert_eq!(limiter.decide(100, "execve", t0), DenyAuditAction::Audit);
        assert_eq!(limiter.decide(100, "execve", t0), DenyAuditAction::Suppress);
        assert_eq!(limiter.decide(100, "execve", t0), DenyAuditAction::Suppress);

        let t1 = t0 + Duration::from_millis(1100);
        assert_eq!(
            limiter.decide(100, "execve", t1),
            DenyAuditAction::Rollover { suppressed: 2 },
            "new window must report the 2 suppressed of the old window"
        );
        // event ถัดไปในหน้าต่างใหม่บันทึกเดี่ยวตามปกติ
        assert_eq!(limiter.decide(100, "execve", t1), DenyAuditAction::Audit);
    }

    #[test]
    fn quiet_window_rolls_over_silently() {
        let mut limiter = DenyAuditLimiter::new(2);
        let t0 = Instant::now();
        assert_eq!(limiter.decide(100, "execve", t0), DenyAuditAction::Audit);
        let t1 = t0 + Duration::from_millis(1100);
        assert_eq!(
            limiter.decide(100, "execve", t1),
            DenyAuditAction::Audit,
            "no suppression happened, so no summary needed"
        );
    }

    #[test]
    fn different_pid_and_syscall_tracked_separately() {
        let mut limiter = DenyAuditLimiter::new(1);
        let now = Instant::now();
        assert_eq!(limiter.decide(100, "execve", now), DenyAuditAction::Audit);
        // pid อื่นไม่โดนงบของ pid แรก
        assert_eq!(limiter.decide(200, "execve", now), DenyAuditAction::Audit);
        // syscall อื่นของ pid เดิมก็ไม่โดน
        assert_eq!(limiter.decide(100, "open", now), DenyAuditAction::Audit);
        // แต่ซ้ำคู่เดิมเกินงบต้อง suppress
        assert_eq!(
            limiter.decide(100, "execve", now),
            DenyAuditAction::Suppress
        );
    }
}
