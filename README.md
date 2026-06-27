# AI-Native Kernel (Rust)

> ระบบปฏิบัติการแบบ **Hybrid-Companion** สำหรับยุค AI ที่ทำงานควบคู่กับ Linux Kernel โดยใช้ **eBPF** และ **LSM Hooks** ในการควบคุมพฤติกรรมและการสืบค้นสิทธิ์ความปลอดภัยผ่าน AI Agents ภายใต้แนวคิด **Zero-Trust**

---

## 1. โครงสร้างสถาปัตยกรรม (System Architecture)

ระบบประกอบด้วยโมดูลหลัก (Crates) 7 ส่วนที่ทำงานเชื่อมต่อกันเป็นวงปิด:

```
User / AI Application
    │  Intent (NL or structured)
    ▼
Intent Bus (tokio::sync::broadcast)
    │
    ▼
Agent Scheduler (tokio::runtime) ── Capability & Security Manager (LSM Policy Engine)
    │                                  │
    ├── Context Memory Manager ─────────┤  (Hot/Warm/Cold paging)
    │                                  │
    ▼                                  ▼
Compute Scheduler (CPU/GPU/NPU)    Audit Logger (WORM)
    │
    ▼
Linux Kernel (eBPF/LSM Hooks via Aya)
```

### คำอธิบายโมดูล:
1. **[kernel-companion](crates/kernel-companion/)**: ตัวประสานงานหลัก (Composition Root) โหลด LSM eBPF hooks และเปิด Unix Domain Socket รับ Intent จากภายนอก
2. **[agent-scheduler](crates/agent-scheduler/)**: ควบคุมวงจรชีวิตของ Agent (Agent Lifecycle) และคอยดูแลความผิดพลาดด้วย Supervisor
3. **[context-memory](crates/context-memory/)**: ระบบจัดการหน่วยความจำบริบทแบบลำดับชั้น (Hot (RAM) / Warm (RocksDB) / Cold (Disk))
4. **[capability-security](crates/capability-security/)**: ตรวจสอบและบริหารสิทธิ์ความปลอดภัยแบบ Zero-Trust (Default = DENY) พร้อมเขียนรายงานแบบลบไม่ได้ (WORM Audit Log)
5. **[compute-scheduler](crates/compute-scheduler/)**: จัดสรรอุปกรณ์ประมวลผล (Placement) ตาม Latency, Power, และ Cost
6. **[intent-bus](crates/intent-bus/)**: บัสรับส่งข่าวสารเหตุการณ์และคำสั่งแบบ asynchronous
7. **[immune-system](crates/immune-system/)**: ระบบรักษาความปลอดภัยเลียนแบบระบบภูมิคุ้มกัน (Macrophage, T-Cell, B-Cell, Cytokine)

---

## 2. ระบบภูมิคุ้มกันวงปิด (Closed-loop Immune System)

ระบบสามารถตรวจจับและตอบสนองต่อภัยคุกคามโดยอัตโนมัติ:
1. **T-Cell Agent** ตรวจพบความผิดปกติของ syscall (เช่น พฤติกรรมเสี่ยง, เรียกถี่เกินเกณฑ์) จะกักกัน (Quarantine) PID และยิง Event เข้าบัส
2. **B-Cell Agent** ดักฟังบัสแล้วอ่านข้อมูลประวัติ syscall ล่าสุดของ PID นั้นมาเรียนรู้ Attack Pattern
3. B-Cell ผลิต Antibody ส่งไปบล็อก syscall ที่พฤติกรรมเสี่ยงบน **LSM Policy Engine** ทันทีในระดับ Kernel
4. **Macrophage Agent** จะเคลียร์ context ที่หมดอายุและทำการคลายสถานะ Quarantine ของ process ที่พ้นโทษอย่างเป็นระบบ

---

## 3. การควบคุมผ่านเครื่องมือ CLI (`ank-cli`)

ตัวจัดการระบบมีเครื่องมืออำนวยความสะดวกแบบสองทิศทาง (Bidirectional CLI) สำหรับดึงสถานะวิเคราะห์ภัยคุกคาม:

```bash
# พิมพ์บอกวิธีใช้งานคำสั่ง
ank-cli

# สั่งให้ระบบสปอว์น AI Agent ตัวใหม่
ank-cli spawn-agent '{"agent_name": "research-companion"}'

# ตรวจสอบสถานะการทำงาน, จำนวนเอเจนต์, รายชื่อกระบวนการที่โดนบล็อก/กักกัน
ank-cli status

# ตรวจสอบรายการ PID ที่ถูกจำกัดสิทธิ์ชั่วคราว
ank-cli list-quarantine

# ตั้งค่าเกณฑ์ความปลอดภัยของ T-Cell (Syscall Rate limit, Deny count limit) แบบไดนามิกทันที
ank-cli set-threshold <rate_limit> <deny_limit>
```

---

## 4. คำสั่งสำหรับพัฒนาและตรวจสอบคุณภาพ (Build & Quality Commands)

ในการรันคำสั่ง กรุณาขึ้นต้นด้วย `rtk` (Rust Token Killer) เสมอเพื่อรักษาเสถียรภาพการใช้โทเค็น:

```bash
# คอมไพล์โปรเจคแบบ Release
rtk cargo build --release

# รันชุดการทดสอบทั้งหมดของระบบ (Unit + Integration Tests)
rtk cargo test

# ตรวจสอบโค้ดและกฎระเบียบความปลอดภัยแบบไม่มีคำเตือน (Zero Warnings Allowed)
rtk cargo clippy --all-targets --all-features -- -D warnings

# จัดระเบียบฟอร์แมตโค้ดในทั้งโครงการ
rtk cargo fmt
```

---
> **ระดับความปลอดภัย**: Zero-Trust | โค้ดทั้งหมดใช้ **Rust 2024 Edition** ร่วมกับ **Tokio Async Runtime** ปลอดจาก Unsafe blocks และไม่มีการใช้งาน `.unwrap()` ในโค้ดการรันงานหลัก
