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
3. **[context-memory](crates/context-memory/)**: ระบบจัดการหน่วยความจำบริบทแบบลำดับชั้น (Hot (RAM) / Warm (in-memory by default, RocksDB via feature flag) / Cold (Disk))
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

# เปิดใช้ Warm tier แบบ RocksDB (compile-time feature)
rtk cargo build --release --features context-memory/rocksdb-warm

# รันชุดการทดสอบทั้งหมดของระบบ (Unit + Integration Tests)
rtk cargo test

# ตรวจสอบโค้ดและกฎระเบียบความปลอดภัยแบบไม่มีคำเตือน (Zero Warnings Allowed)
rtk cargo clippy --all-targets --all-features -- -D warnings

# จัดระเบียบฟอร์แมตโค้ดในทั้งโครงการ
rtk cargo fmt
```

ถ้าจะรัน `clippy --all-features` ด้วย `context-memory/rocksdb-warm`, ต้องมี `libclang` ให้ `bindgen` หาเจอ
ผ่าน `LIBCLANG_PATH` หรือผ่าน `scripts/use-local-toolchain.sh` ที่จะพยายามตั้งค่าให้เองจาก LLVM ที่ติดตั้งไว้
และ `scripts/install-ebpf-deps.sh` จะติดตั้ง `libclang-dev` เพิ่มให้ในชุด dependency ของ eBPF

หมายเหตุ: backend ของ Warm tier ไม่ได้สลับผ่าน `config/default.toml` ตอน runtime
แต่เลือกตอน build ด้วย feature `context-memory/rocksdb-warm`

## 5. ตรวจความพร้อมสำหรับ Real eBPF/LSM

ก่อนคาดหวังให้ `kernel-companion` attach tracepoint และ LSM hook จริงกับ kernel ให้เช็ก environment ก่อน:

```bash
# ตรวจ prerequisite แบบตรงกับ build.rs
./scripts/check-ebpf-prereqs.sh

# ติดตั้ง dependency สำหรับ Debian/Ubuntu
./scripts/install-ebpf-deps.sh

# หรือเรียกผ่าน wrapper เดิมของโปรเจกต์
./scripts/run.sh prereqs

# ติดตั้งผ่าน wrapper
./scripts/run.sh install-prereqs
```

สคริปต์จะตรวจ:
1. `/sys/kernel/btf/vmlinux`
2. linux headers ที่มี `bpf/bpf_helpers.h`
3. `clang` และ `--target=bpf`
4. `bpftool`
5. compile smoke test ของ `syscall-tracer.bpf.c` และ `lsm-security.bpf.c`

ถ้ายังไม่ผ่าน ระบบจะ fallback ไป simulation mode ตาม behavior ของ `crates/kernel-companion/build.rs`

รายละเอียด remediation เพิ่มเติมดู [docs/ebpf_prereqs.md](docs/ebpf_prereqs.md)

## 6. รัน Qdrant Integration Tests

ชุด `ignored` ของ `context-memory` รองรับ Qdrant จริงแล้วผ่าน environment variables:

```bash
QDRANT_URL=http://127.0.0.1:6334 ./scripts/run-qdrant-tests.sh
```

ถ้าไม่ได้ตั้ง `QDRANT_URL` script จะยก local Qdrant mock ขึ้นให้ชั่วคราวเอง

หรือกำหนดปลายทางเองผ่านตัว test โดยตรง:

```bash
QDRANT_URL=http://qdrant.internal:6334 rtk cargo test -p context-memory --lib -- --ignored
```

ตัวแปรที่รองรับ:
1. `QDRANT_URL`
2. `QDRANT_HOST`
3. `QDRANT_PORT`

ถ้ากำหนด `QDRANT_URL` จะถูกใช้ก่อน `QDRANT_HOST`/`QDRANT_PORT`

## 7. รัน Test ทั้งหมดคำสั่งเดียว

มี script รวมสำหรับรัน workspace tests ทั้งหมด และตามด้วย ignored Qdrant tests:

```bash
./scripts/run-all-tests.sh
```

script นี้จะ:
1. รัน `cargo test --workspace`
2. ใช้ `QDRANT_URL` จริงถ้ากำหนดไว้
3. ถ้าไม่ได้กำหนด `QDRANT_URL` จะยก local Qdrant mock ขึ้นชั่วคราว
4. รัน `cargo test -p context-memory --lib -- --ignored`

ตัวอย่างใช้ Qdrant จริง:

```bash
QDRANT_URL=http://qdrant.internal:6334 ./scripts/run-all-tests.sh
```

---
> **ระดับความปลอดภัย**: Zero-Trust | โค้ดทั้งหมดใช้ **Rust 2024 Edition** ร่วมกับ **Tokio Async Runtime** ปลอดจาก Unsafe blocks และไม่มีการใช้งาน `.unwrap()` ในโค้ดการรันงานหลัก
