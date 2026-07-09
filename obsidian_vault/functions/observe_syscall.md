---
tags: [function, hot-path, immune-system, security]
crate: immune-system
file: crates/immune-system/src/tcell.rs
updated: 2026-07-09
---

# TCellAgent::observe_syscall

```rust
pub async fn observe_syscall(&self, pid: u32, syscall_name: &str, denied: bool) -> ThreatDecision
```

## หน้าที่
Hot path ของระบบภูมิคุ้มกัน — ถูกเรียก**ทุก syscall event** เพื่อตรวจจับพฤติกรรมผิดปกติ:
1. คำนวณ threshold แบบไดนามิก (Immunological Jitter ±15% + per-PID sensitivity factor)
2. อัปเดตสถิติราย PID ภายใต้ **DashMap shard lock** (rate, deny count, syscall history 5 รายการล่าสุด)
3. คำนวณ Anomaly Score: rate contribution + deny contribution (capped) + suspicious sequence (+8.0)
4. ตัดสินระดับภัยคุกคาม → `Safe` / `Warn` / `Quarantine` / `Kill`

## Suspicious Sequences ที่ตรวจจับ
- Privilege escalation: `setuid/setgid → execve`
- Process injection: `ptrace → memfd_create/process_vm_writev`
- Reverse shell: `socket/connect → dup2/dup3 → execve`

## ความสัมพันธ์
- **เรียกโดย:** kernel-companion tcell task (ต่อจาก eBPF SyscallTracer event loop)
- **ผลลัพธ์ไหลไปยัง:** [[audit-record]] (บันทึก Kill/Quarantine), [[intent-publish]] (Cytokine signal → B-Cell learning)
- **Exempt list:** system processes (systemd, sshd, ฯลฯ) ถูก downgrade Kill → Warn

## Performance (วัดจริง 2026-07-09)
- Sequential: **~136 ns/event** | Concurrent 8 tasks: **~71 ns/event** (~14M events/s)
- Design: DashMap แทน global `RwLock<HashMap>` — PID ต่างกันไม่ block กัน, 1 allocation/event ผ่าน `Arc<str>`
- **ข้อควรระวัง:** ห้ามถือ DashMap entry guard ข้าม `.await` (exempt check เป็น async — ต้อง extract ค่าออกก่อน)

## Related
[[00-Function-Map]] · [[policy-decision]] · [[audit-record]]
