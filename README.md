# AI-Native Kernel (Rust)

> ระบบปฏิบัติการแบบ **Hybrid-Companion** สำหรับยุค AI ที่ทำงานควบคู่กับ Linux Kernel โดยใช้ **eBPF** และ **LSM Hooks** ในการควบคุมพฤติกรรมและการสืบค้นสิทธิ์ความปลอดภัยผ่าน AI Agents ภายใต้แนวคิด **Zero-Trust**
>
> **Pivot (2026-09)**: เพิ่ม **AI Infrastructure Security Data Plane** — `ai-gateway` (OpenAI-compatible reverse proxy), `semantic-guard` (prompt injection/PII), `extraction-det` (model-extraction detection) — ใช้เป็น Data Plane บนต้นไปของโมเดล ในขณะที่ Host Plane (eBPF/LSM) คงควบคุม Kernel-level enforcement

---

## 1. โครงสร้างสถาปัตยกรรม (System Architecture)

ระบบประกอบด้วยโมดูลหลัก (Crates) 10 ส่วน แบ่งเป็น **Host Plane** (eBPF/LSM enforcement) และ **Data Plane** (API security):

```
User / AI Application
    │  Intent (NL or structured)
    ▼
Intent Bus (tokio::sync::broadcast)
    │
    ├──────────────────┬──────────────────┐
    ▼                  ▼                  ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Data Plane  │  │ Agent Plane │  │ Host Plane  │
├─────────────┤  ├─────────────┤  ├─────────────┤
│ ai-gateway  │  │ agent-scheduler │ kernel-companion │
│ semantic-guard│  │ context-memory│  immune-system   │
│ extraction-det│  │ compute-scheduler│ capability-security│
│             │  │ intent-bus   │               │
└─────────────┘  └─────────────┘  └─────────────┘
       │              │                  │
       └──────────────┴──────────────────┘
                          │
                          ▼
              Linux Kernel (eBPF/LSM Hooks via Aya)
```

### Host Plane (eBPF/LSM Enforcement)
1. **[kernel-companion](crates/kernel-companion/)**: Composition Root — โหลด LSM eBPF hooks, UDS สำหรับ Intent
2. **[capability-security](crates/capability-security/)**: Zero-Trust Capability Tokens, Policy Engine (default=DENY), WORM Audit Log
3. **[immune-system](crates/immune-system/)**: ระบบภูมิคุ้มกันเลียนแบบ (T-Cell, B-Cell, Macrophage) รวม quarantine/kill ผ่าน LSM

### Agent Plane (Agent Runtime)
4. **[agent-scheduler](crates/agent-scheduler/)**: Agent Lifecycle, Supervisor, Priority Queue
5. **[context-memory](crates/context-memory/)**: Hot/Warm/Cold Paging (RAM → RocksDB → Disk)
6. **[compute-scheduler](crates/compute-scheduler/)**: Placement (CPU/GPU/NPU) llama.cpp / ONNX / TensorRT-LLM
7. **[intent-bus](crates/intent-bus/)**: Async Event Bus

### Data Plane (AI Infrastructure Security) — **NEW**
8. **[ai-gateway](crates/ai-gateway/)**: OpenAI-compatible Reverse Proxy — Bearer/ApiKey auth, tenant policy, streaming SSE, per-tenant audit
9. **[semantic-guard](crates/semantic-guard/)**: Unicode normalization, PII redaction (email/card/SSN/API key), 13 prompt-injection signatures, 2ms budget
10. **[extraction-det](crates/extraction-det/)**: Model-extraction detection — sliding window, MinHash/Jaccard, LSH, per-tenant signals

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

# ตรวจสอบความถูกต้องของ hash chain ใน audit log ของ Host Plane
ank-cli verify-audit /var/lib/ank/audit/audit.jsonl
```

---

## 4. คำสั่งสำหรับพัฒนาและตรวจสอบคุณภาพ (Build & Quality Commands)

ในการรันคำสั่ง กรุณาขึ้นต้นด้วย `rtk` (Rust Token Killer) เสมอเพื่อรักษาเสถียรภาพการใช้โทเค็น:

```bash
# คอมไพล์โปรเจคแบบ Release (รวม Data Plane crates)
rtk cargo build --release

# เปิดใช้ Warm tier แบบ RocksDB (compile-time feature)
rtk cargo build --release --features context-memory/rocksdb-warm

# รันชุดการทดสอบทั้งหมดของระบบ (Unit + Integration Tests)
rtk cargo test

# รันเทส Data Plane แยกต่างหาก
rtk cargo test -p ai-gateway -p semantic-guard -p extraction-det

# ตรวจสอบโค้ดและกฎระเบียบความปลอดภัยแบบไม่มีคำเตือน (Zero Warnings Allowed)
rtk cargo clippy --workspace --all-targets --all-features -- -D warnings

# จัดระเบียบฟอร์แมตโค้ดในทั้งโครงการ
rtk cargo fmt

# Security audit
cargo audit
```

ถ้าต้องการใช้ toolchain ที่ pin ไว้ใน repo โดยตรง:

```bash
source scripts/use-local-toolchain.sh
```

สถานะที่ยืนยันล่าสุดใน workspace นี้ ณ วันที่ `2026-09-27`:
1. `cargo fmt --all -- --check` ผ่าน
2. `cargo check --workspace` ผ่าน
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings` ผ่าน
4. `cargo test --workspace` — 697 tests passed (รวม Qdrant-backed ignored tests ผ่าน mock และ P2P mesh tests)
5. `cargo audit` — 0 vulnerabilities (h2 0.4.19, rustls 0.23.45)
6. Criterion Benchmarks (`cargo bench` ทุกโมดูล) คอมไพล์และรันผ่านเกณฑ์ Latency

หมายเหตุ:
1. การทดสอบแบบ privileged eBPF/LSM attach จริงยังคงต้องทำการตรวจสอบบน host ที่มีสิทธิ์ root/capabilities ครบถ้วน (หากไม่มีจะ fallback เป็น simulation mode โดยอัตโนมัติ)

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

### 8.1 Generic Hash Chain — `ChainedLog<E>` (ANK-060)

ระบบ Audit Log แบบ Hash Chain ถูกแยกเป็นโมดูลเจนริก `ChainedLog<E>` ใน `capability-security/chained_log.rs` เพื่อใช้ร่วมกันระหว่าง **Host Plane** (`AuditEntry`) และ **Data Plane** (`ApiAuditEntry`):

```rust
pub trait ChainEntry: Serialize + DeserializeOwned + Send + Sync + 'static {
    fn compute_hash(&self, prev_hash: &str) -> String;
    fn set_hash(&mut self, hash: String);
    fn hash(&self) -> Option<String>;
    fn set_chain_id(&mut self, _chain_id: &str) {} // optional
}
```

- `AuditLogger` (Host Plane) ใช้ `ChainedLog<AuditEntry>` — กำจัด global mutex bottleneck
- `ApiAuditChain` (Data Plane) = `type ApiAuditChain = ChainedLog<ApiAuditEntry>` — per-tenant sharded chains
- รองรับ: crash-safe append, newline repair, resume across restarts, tamper detection

---

### 8.2 API Gateway CLI (Data Plane)

```bash
# Run reverse proxy
ai-gateway serve --listen 127.0.0.1:8890 --upstream http://127.0.0.1:8000 \
  --audit-dir /var/lib/ai-gateway/audit --policy-file /etc/ai-gateway/policy.json

# Same, but terminating TLS in-process (TLS 1.3 only; cert/key must be given as a pair —
# half a pair refuses to start rather than silently falling back to plaintext)
ai-gateway serve --listen 0.0.0.0:8443 --tls-cert /etc/ai-gateway/tls.crt \
  --tls-key /etc/ai-gateway/tls.key --upstream http://127.0.0.1:8000

# Verify audit hash chains
ai-gateway verify-audit --dir /var/lib/ai-gateway/audit
```

Policy file example (`/etc/ai-gateway/policy.json`):
```json
{
  "tenants": [
    {
      "id": "acme",
      "key": "sk-demo-123456",
      "allowed_endpoints": ["chat_completions", "embeddings"],
      "allowed_models": ["demo-model"],
      "max_concurrent": 10,
      "suspended": false
    }
  ]
}
```

Environment variables: `ANK_GATEWAY_LISTEN`, `ANK_GATEWAY_UPSTREAM`, `ANK_GATEWAY_AUDIT_DIR`, `ANK_GATEWAY_POLICY_FILE`, `ANK_GATEWAY_GUARD`, `ANK_GATEWAY_EXTRACTION`, `ANK_GATEWAY_TLS_CERT`, `ANK_GATEWAY_TLS_KEY`, `ANK_LOG`.

> ⚠️ `max_concurrent` ใน policy file ถูกอ่านแล้วแต่ **ยังไม่ถูกบังคับใช้** (ดู ANK-069) — ผู้เช่าหนึ่งยิงพร้อมกันได้ไม่จำกัดในตอนนี้

---

### 8.3 ระบบถอนสิทธิ์ความปลอดภัยลงสู่ Kernel LSM ทันที (Automatic Revoke/Expiry Propagation)
- เมื่อ `CapabilityToken` ถูกสั่งยกเลิก (Revoke) หรือหมดอายุการใช้งาน (Expired) ในชั้น `capability-security` ระบบประสานงานหลัก `kernel-companion` จะรับรู้ผ่านกลไกการจดทะเบียน callback ทันที
- ระบบจะดึงรายชื่อ PIDs ทั้งหมดที่เชื่อมโยงกับโทเค็นดังกล่าว และสั่งเพิ่มเข้า `blocked_pids` ในชั้น Kernel LSM hook (Aya) ทันที รวมถึงมี background thread ตรวจซ้ำทุกๆ 500ms แบบ fail-safe
- **โมเดล enforcement (Hardening H1):** LSM hook เป็น global hook แต่ **scope การตัดสินด้วย cgroup v2 id**: process ของ host ปล่อยผ่าน (host ไม่มีทางค้าง) ส่วน process ใน agent cgroup ที่ลงทะเบียนแล้วเป็น **default-DENY** เว้นแต่ PID อยู่ใน allow-list — คืนหลัก fail-DENY ให้โลกของ agent โดยไม่กระทบ host (เปิดผ่าน `lsm.agent_cgroup_path`, daemon fail-closed ตอน boot ถ้าตั้ง path แล้วสร้าง cgroup ไม่ได้)
- **การตัดสิทธิ์แบบทันที (Hardening H4):** เมื่อ Immune System (T-Cell) สั่ง quarantine/kill ระบบจะเขียน `blocked_pids` map ที่ระดับ kernel **ก่อน** audit/broadcast ปิดหน้าต่างที่ agent ยิง syscall ต่อได้ระหว่างรอ token หมดอายุ

### 8.4 RocksDB Warm Store แบบจัดเก็บถาวร (Persistent RocksDB Warm Store)
เมื่อคอมไพล์โปรเจกต์ด้วย `--features context-memory/rocksdb-warm` ระบบจัดเก็บข้อมูล RocksDB บน NVMe จะทำงานแบบจัดเก็บถาวร (Persistent):
- **การตั้งค่าพาธ**: สามารถกำหนดตำแหน่งโฟลเดอร์ของฐานข้อมูลได้ผ่านฟิลด์ `warm_store_path` ใน `config/default.toml` หรือส่งผ่านตัวแปรสิ่งแวดล้อม `ANK_WARM_STORE_PATH`
- **การกู้คืนสถานะช่วง Startup**: ทุกครั้งที่มีการเปิดระบบขึ้นมาใหม่ Warm Store จะทำการสแกนตรวจสอบข้อมูล (Key Iterator) ที่คงเหลืออยู่จริงบน RocksDB อัตโนมัติ เพื่อสร้างค่าตัวนับรายการ (`count`) และจัดลำดับอายุข้อมูล FIFO (`order` queue) ในแรมใหม่ทั้งหมด ทำให้มั่นใจได้ว่าข้อมูลจะไม่ทับซ้อนและไม่สูญหายข้ามการปิดเปิดระบบ
- **การรันเทสที่เสถียร**: ในสภาพแวดล้อมการทดสอบ (`cargo test`) ระบบจะสร้างฐานข้อมูลแบบแยก UUID ของแต่ละ thread อัตโนมัติ เพื่อหลีกเลี่ยงข้อจำกัดการล๊อคไฟล์ของ RocksDB (Lock conflict) ระหว่างการประมวลผลการทดสอบแบบขนาน

### 8.5 P2P Gossip Mesh พร้อมโมเดลความน่าเชื่อถือและการขจัดความขัดแย้ง (Trust + Conflict Model)
ระบบแชร์ความจำบริบทข้ามเครื่อง (Cross-Machine Memory Plane) ได้รับการยกระดับความปลอดภัยและความทนทาน:
- **Mutual Authentication + Integrity (Hardening H6)**: ทุกข้อความใน mesh ถูกเซ็นด้วย **HMAC-SHA256** จาก pre-shared key ต่อ mesh — ผู้รับตรวจ tag ก่อนประมวลผล ปฏิเสธข้อความปลอม/ถูกแก้ และกัน replay (timestamp window + nonce dedup) ทำให้ `trust_score` มีความหมายจริงเพราะ identity ปลอมไม่ได้ (ต้องถือ key จึงเซ็นในนาม node ได้) ตั้ง key ผ่าน `context_memory.p2p_mesh_key_hex` และ daemon จะ **fail-closed** ตอน boot ถ้าเปิด mesh โดยไม่ตั้ง key
- **Confidentiality via mTLS (Hardening H7)**: เข้ารหัสสายด้วย **TLS 1.3** โดยไม่ต้องมี PKI — derive cert/key แบบ deterministic จาก PSK เดียวกับ H6 แล้ว pin peer cert ให้ตรง identity นั้น กัน active MITM ดักอ่าน context data; peer ที่ไม่ถือ PSK จะ handshake TLS ไม่ผ่าน (ถูกปฏิเสธก่อนถึงชั้น HMAC) โดย operator ยังจัดการ secret เดียวเหมือนเดิม
- **Zero-Trust Connection**: แต่ละ Node จะรักษาคะแนนความน่าเชื่อถือ (`trust_score` ตั้งแต่ 0–100) ของเพื่อนบ้าน โดยหาก Node ใดมีคะแนนต่ำกว่า `50` คะแนน ระบบจะปฏิเสธการเชื่อมต่อ TCP Handshake หรือทำการตัดการเชื่อมต่อ (Sever connection) ทันที รวมถึงละทิ้ง (Drop) ทุกข้อความที่ส่งมาจาก Node นั้นๆ
- **ระบบจัดลำดับและแก้ปัญหาข้อมูลชนกัน (Conflict Resolution)**: เมื่อได้รับข้อความซิงก์รายการซ้อนทับกัน ระบบจะคัดกรองตามลำดับความสำคัญ:
  1. เปรียบเทียบ **Trust Score** ของ Node ผู้เขียน (Node ที่มีค่าความน่าเชื่อถือสูงกว่าจะทับข้อมูล Node ที่น่าเชื่อถือน้อยกว่าได้เสมอ)
  2. หากมีระดับความน่าเชื่อถือเท่ากัน จะเปรียบเทียบ **Version** ของข้อมูล (เวอร์ชันล่าสุดที่มี timestamp มากกว่าเป็นฝ่ายชนะ)
  3. หากเท่ากันทุกอย่าง จะตัดสินอย่างเด็ดขาดและแน่นอน (Deterministic) ด้วยการคัดเลือก Node ID ตามลำดับตัวอักษร (Lexicographically smaller Node ID wins)

### 8.6 Security Hardening Backlog (H1–H8)

ย้าย trust boundary ลงชั้นที่ปลอมไม่ได้จริง ครบทั้ง host และ network (แผนเต็ม: `docs/ai_native_kernel_plan_v2.html` §9.1):

| # | สิ่งที่ปิด | สถานะ |
|---|-----------|-------|
| **H1** | cgroup-scoped default-DENY สำหรับโลกของ agent (แก้ default-ALLOW gap) | ✅ validated บน kernel จริง |
| **H2** | ผูก authorization กับ `(PID, start_time)` กัน PID reuse | ✅ validated บน kernel จริง |
| **H3** | intent → scope compiler (path prefix + operation-class ผ่าน `bpf_d_path`) | ✅ validated บน kernel จริง |
| **H4** | ตัดสิทธิ์ที่ kernel ทันทีเมื่อ immune system สั่ง quarantine | ✅ unit-tested (รอ syscall load จริง) |
| **H5** | VRAM tier migration ไม่ทำข้อมูลหาย (DtoH/HtoD จริง) | ✅ simulation (รอ GPU จริง) |
| **H6** | P2P mesh mutual auth + integrity (HMAC + replay guard) | ✅ validated (E2E loopback) |
| **H7** | P2P mesh confidentiality — mTLS (PSK-derived cert, ไม่ต้องมี PKI) | ✅ validated (E2E loopback) |
| **H8** | capability-scoped skill manifests (specialization = kernel-enforced least-privilege) | ✅ validated บน kernel จริง |

Privileged validation: `sudo scripts/validate-ebpf-attach.sh` (H1) และ `scripts/run-privileged.sh cargo test -p kernel-companion --test privileged_h1_h2` (H2/H3).
---

## 9. Task Tracking (ANK-060..069)

| ID | Title | Module | Status |
|---|-------|--------|--------|
| ANK-060 | Extract ChainedLog<E> & Rebase AuditLogger | capability-security | ✅ done (`chained_log.rs`) |
| ANK-061 | Model-Extraction Detector (extraction-det) | extraction-det | ✅ done (48 tests) |
| ANK-062 | Semantic Guard: Prompt Injection & PII Redaction | semantic-guard | ✅ done (77 tests) |
| ANK-063 | AI Gateway Pass-Through Proxy | ai-gateway | ✅ done (104 tests) |
| ANK-064 | Wire Guard / Extraction / Audit Enforcement | ai-gateway | ✅ done |
| ANK-065 | Multi-tenant Keys for Immune Tcell | immune-system | ✅ done |
| ANK-066 | `verify-audit` & Audit Export | capability-security | ✅ done — JSON export ทั้งสอง plane + golden-shape test |
| ANK-067 | Reposition Docs & README for AI Security Pivot | infra | ✅ done |
| ANK-068 | TLS termination + P99 under concurrent tenants | ai-gateway | ✅ done — TLS 1.3 in-process + 8-tenant P99 ~111 µs / same-tenant chain P99 ~706 µs |
| ANK-069 | Enforce per-tenant `max_concurrent` | ai-gateway | 🔲 todo — ค่าถูกอ่านจาก policy แต่ยังไม่มีตัวนับ |

งาน Phase 1 ครบทั้ง 8 ขั้นตอนแล้ว (บวกขั้นที่ 9 = TLS + concurrency proof) — ดู `docs/pivot_ai_infra_security.md` §7 สำหรับรายละเอียด

---

> **ระดับความปลอดภัย**: Zero-Trust | โค้ดทั้งหมดใช้ **Rust 2024 Edition** ร่วมกับ **Tokio Async Runtime** ปลอดจาก Unsafe blocks และไม่มีการใช้งาน `.unwrap()` ในโค้ดการรันงานหลัก
