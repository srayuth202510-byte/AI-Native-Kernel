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
3. **[context-memory](crates/context-memory/)**: ระบบจัดการหน่วยความจำบริบทแบบลำดับชั้น (VRAM (GPU/NPU) / Hot (RAM) / Warm (in-memory by default, RocksDB via feature flag) / Cold (Disk))
4. **[capability-security](crates/capability-security/)**: ตรวจสอบและบริหารสิทธิ์ความปลอดภัยแบบ Zero-Trust (Default = DENY) พร้อมเขียนรายงานแบบลบไม่ได้ (WORM Audit Log)
5. **[compute-scheduler](crates/compute-scheduler/)**: จัดสรรอุปกรณ์ประมวลผล (Placement) ตาม Latency, Power, และ Cost พร้อมสนับสนุนการเลือกรันไทม์ประมวลผล (llama.cpp, ONNX Runtime, TensorRT-LLM)
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

ถ้าต้องการใช้ toolchain ที่ pin ไว้ใน repo โดยตรง:

```bash
source scripts/use-local-toolchain.sh
```

สถานะที่ยืนยันล่าสุดใน workspace นี้ ณ วันที่ `2026-06-29`:
1. `cargo fmt --all -- --check` ผ่าน
2. `cargo check --workspace` ผ่าน
3. `cargo clippy --workspace -- -D warnings` ผ่าน
4. `cargo test --workspace` ผ่าน

หมายเหตุ:
1. ชุด test ปกติของ workspace ยังเหลือ Qdrant-backed `#[ignore]` integration tests อีก 4 รายการ ซึ่งรันผ่าน `./scripts/run-qdrant-tests.sh`
2. ยังไม่ได้ re-validate privileged eBPF/LSM attach path ในรอบนี้บน host ที่มี kernel prerequisites ครบ; ใช้ `./scripts/run.sh validate-ebpf` สำหรับ host validation
3. ~~ยังไม่ได้รัน lint path แบบเดียวกับ CI คือ `cargo clippy --all-targets --all-features -- -D warnings`~~ ✅ ผ่านแล้ว (ANK-039)

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

ถ้ายังไม่ผ่าน tracer จะ fallback ไป simulation mode ตาม runtime config `ebpf.enable_fallback = true`
ถ้าต้องการบังคับ fail-closed path ให้รัน companion ด้วย `--no-bpf-fallback`

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

## 8. ฟีเจอร์ขั้นสูงเพิ่มเติม (Advanced Features)

### 8.1 ระบบถอนสิทธิ์ความปลอดภัยลงสู่ Kernel LSM ทันที (Automatic Revoke/Expiry Propagation)
- เมื่อ `CapabilityToken` ถูกสั่งยกเลิก (Revoke) หรือหมดอายุการใช้งาน (Expired) ในชั้น `capability-security` ระบบประสานงานหลัก `kernel-companion` จะรับรู้ผ่านกลไกการจดทะเบียน callback ทันที
- ระบบจะดึงรายชื่อ PIDs ทั้งหมดที่เชื่อมโยงกับโทเค็นดังกล่าว และทำการสั่งลบออกจาก `allowed_pids` ในชั้น Kernel LSM hook (Aya) ทันที รวมถึงมี background thread คอยตรวจสอบความปลอดภัยซ้ำทุกๆ 500ms เพื่อให้สอดคล้องกับมาตรการ Zero-Trust แบบ fail-safe

### 8.2 RocksDB Warm Store แบบจัดเก็บถาวร (Persistent RocksDB Warm Store)
เมื่อคอมไพล์โปรเจกต์ด้วย `--features context-memory/rocksdb-warm` ระบบจัดเก็บข้อมูล RocksDB บน NVMe จะทำงานแบบจัดเก็บถาวร (Persistent):
- **การตั้งค่าพาธ**: สามารถกำหนดตำแหน่งโฟลเดอร์ของฐานข้อมูลได้ผ่านฟิลด์ `warm_store_path` ใน `config/default.toml` หรือส่งผ่านตัวแปรสิ่งแวดล้อม `ANK_WARM_STORE_PATH`
- **การกู้คืนสถานะช่วง Startup**: ทุกครั้งที่มีการเปิดระบบขึ้นมาใหม่ Warm Store จะทำการสแกนตรวจสอบข้อมูล (Key Iterator) ที่คงเหลืออยู่จริงบน RocksDB อัตโนมัติ เพื่อสร้างค่าตัวนับรายการ (`count`) และจัดลำดับอายุข้อมูล FIFO (`order` queue) ในแรมใหม่ทั้งหมด ทำให้มั่นใจได้ว่าข้อมูลจะไม่ทับซ้อนและไม่สูญหายข้ามการปิดเปิดระบบ
- **การรันเทสที่เสถียร**: ในสภาพแวดล้อมการทดสอบ (`cargo test`) ระบบจะสร้างฐานข้อมูลแบบแยก UUID ของแต่ละ thread อัตโนมัติ เพื่อหลีกเลี่ยงข้อจำกัดการล๊อคไฟล์ของ RocksDB (Lock conflict) ระหว่างการประมวลผลการทดสอบแบบขนาน

### 8.3 P2P Gossip Mesh พร้อมโมเดลความน่าเชื่อถือและการขจัดความขัดแย้ง (Trust + Conflict Model)
ระบบแชร์ความจำบริบทข้ามเครื่อง (Cross-Machine Memory Plane) ได้รับการยกระดับความปลอดภัยและความทนทาน:
- **Zero-Trust Connection**: แต่ละ Node จะรักษาคะแนนความน่าเชื่อถือ (`trust_score` ตั้งแต่ 0–100) ของเพื่อนบ้าน โดยหาก Node ใดมีคะแนนต่ำกว่า `50` คะแนน ระบบจะปฏิเสธการเชื่อมต่อ TCP Handshake หรือทำการตัดการเชื่อมต่อ (Sever connection) ทันที รวมถึงละทิ้ง (Drop) ทุกข้อความที่ส่งมาจาก Node นั้นๆ
- **ระบบจัดลำดับและแก้ปัญหาข้อมูลชนกัน (Conflict Resolution)**: เมื่อได้รับข้อความซิงก์รายการซ้อนทับกัน ระบบจะคัดกรองตามลำดับความสำคัญ:
  1. เปรียบเทียบ **Trust Score** ของ Node ผู้เขียน (Node ที่มีค่าความน่าเชื่อถือสูงกว่าจะทับข้อมูล Node ที่น่าเชื่อถือน้อยกว่าได้เสมอ)
  2. หากมีระดับความน่าเชื่อถือเท่ากัน จะเปรียบเทียบ **Version** ของข้อมูล (เวอร์ชันล่าสุดที่มี timestamp มากกว่าเป็นฝ่ายชนะ)
  3. หากเท่ากันทุกอย่าง จะตัดสินอย่างเด็ดขาดและแน่นอน (Deterministic) ด้วยการคัดเลือก Node ID ตามลำดับตัวอักษร (Lexicographically smaller Node ID wins)

---
> **ระดับความปลอดภัย**: Zero-Trust | โค้ดทั้งหมดใช้ **Rust 2024 Edition** ร่วมกับ **Tokio Async Runtime** ปลอดจาก Unsafe blocks และไม่มีการใช้งาน `.unwrap()` ในโค้ดการรันงานหลัก
