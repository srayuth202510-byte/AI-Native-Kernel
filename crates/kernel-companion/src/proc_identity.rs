//! อัตลักษณ์ process ที่ปลอมไม่ได้ (Hardening H2)
//!
//! PID เปล่าๆ ใช้ระบุตัว agent ไม่ได้ เพราะ kernel นำ PID กลับมาแจกใหม่ได้
//! (PID reuse): agent ตายแล้ว process อื่นเกิดมาสวม PID เดิม สิทธิ์ที่ผูกกับ
//! PID จะรั่วไปถึง process แปลกหน้าโดยอัตโนมัติ
//!
//! ทางแก้: ผูก allow-list กับ tuple `(PID, start_time)` — start time ของ
//! process (หน่วย USER_HZ ticks นับจาก boot) อ่านได้จาก `/proc/<pid>/stat`
//! field 22 และฝั่ง kernel LSM hook คำนวณค่าเดียวกันจาก
//! `task->group_leader->start_boottime / (NSEC_PER_SEC / USER_HZ)`
//! PID ที่ถูกแจกใหม่จะมี start time ต่างจากเดิมเสมอ จึงถูก default-DENY ทันที

use anyhow::{Context, Result, bail};

/// อ่าน start time ของ process (USER_HZ ticks นับจาก boot) จาก
/// `/proc/<pid>/stat` field 22 — ค่านี้คงที่ตลอดชีวิตของ process และ
/// เปลี่ยนเสมอเมื่อ PID ถูกนำกลับมาแจกใหม่
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหาก process ไม่มีอยู่ หรือ parse `/proc/<pid>/stat`
/// ไม่สำเร็จ — ผู้เรียกต้อง fail closed: ระบุตัว process ไม่ได้ = ห้ามอนุญาต
pub fn process_start_ticks(pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("cannot read /proc/{pid}/stat — process gone?"))?;
    parse_start_ticks(&stat).with_context(|| format!("cannot parse /proc/{pid}/stat"))
}

/// แยกค่า field 22 (starttime) ออกจากเนื้อหา `/proc/<pid>/stat`
///
/// ชื่อ process (field 2, `comm`) อยู่ในวงเล็บและมี space/วงเล็บซ้อนได้
/// จึงต้อง parse จากวงเล็บปิดตัวสุดท้าย: หลัง `)` field 3 (state) คือ
/// token แรก ดังนั้น starttime = token ลำดับ 20 หลังวงเล็บปิด
fn parse_start_ticks(stat: &str) -> Result<u64> {
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest).unwrap_or(stat);
    let Some(field) = after_comm.split_whitespace().nth(19) else {
        bail!("stat line has fewer than 22 fields");
    };
    field
        .parse::<u64>()
        .with_context(|| format!("starttime field is not a number: {field:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_start_ticks_is_readable_and_stable() {
        let pid = std::process::id();
        let first = process_start_ticks(pid).expect("own /proc stat must parse");
        let second = process_start_ticks(pid).expect("own /proc stat must parse");
        assert!(first > 0, "start ticks must be positive after boot");
        assert_eq!(first, second, "start time must be stable for one instance");
    }

    #[test]
    fn nonexistent_pid_fails_closed() {
        // PID ใกล้เพดาน pid_max ที่แทบเป็นไปไม่ได้ว่ามีจริงในเครื่องทดสอบ
        let err = process_start_ticks(4_194_000).expect_err("missing PID must error");
        assert!(err.to_string().contains("/proc/4194000/stat"));
    }

    #[test]
    fn parse_handles_comm_with_spaces_and_parens() {
        // comm ปลอมชื่อ "a) b (c" — parser ต้องยึดวงเล็บปิดตัวสุดท้าย
        // ไม่ใช่ตัวแรก มิฉะนั้น field ทั้งหมดเลื่อนและได้ค่าผิด
        let stat = "1234 (a) b (c) S 1 1234 1234 0 -1 4194560 100 0 0 0 \
                    5 3 0 0 20 0 1 0 987654321 1000000 200";
        assert_eq!(parse_start_ticks(stat).expect("must parse"), 987_654_321);
    }

    #[test]
    fn parse_rejects_truncated_stat() {
        assert!(parse_start_ticks("1234 (comm) S 1 2 3").is_err());
        assert!(parse_start_ticks("").is_err());
    }
}
