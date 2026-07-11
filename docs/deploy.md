# Deploy to another machine + connect to Claude

คู่มือเอาโปรเจกต์ไปรันบนเครื่องอื่น (ที่มี hardware ครบกว่า เช่น GPU/NPU/iGPU),
สแกน hardware, แล้วเชื่อมกับ Claude เพื่อช่วยตัดสินใจ/generate code ต่อ hardware
ตัวนั้น

## ทิศทางการเชื่อมต่อ (สำคัญ)

Claude เป็นโมเดลบน server — **ไม่ได้ต่อเข้ามาหาเครื่องเอง** เครื่องต้องเป็นฝ่าย
เรียก Claude และ hardware scan ต้องรัน**บนเครื่องนั้น** (prober อ่าน `/dev`, NVML
ในเครื่อง)

## 1. เตรียมเครื่อง (target host)

```bash
# toolchain (Rust) — ดู scripts/bootstrap-validation-host.sh สำหรับ full setup
git clone <repo> && cd ai-native-kernel
cargo build --release

# สำหรับ real kernel enforcement (H1–H8) ต้องมี:
#   - root / CAP_BPF
#   - kernel BTF: /sys/kernel/btf/vmlinux
#   - cgroup v2 mounted ที่ /sys/fs/cgroup
# ตรวจด้วย: bash scripts/check-ebpf-prereqs.sh
```

## 2. สแกน hardware

```bash
./target/release/ank-hwscan > hw.json
```

- สรุปอ่านง่ายออกทาง **stderr**, JSON report ออกทาง **stdout** (เก็บใน `hw.json`)
- รายงานครอบ: kernel, cpu cores, RAM, `/dev/dri` render nodes (iGPU/GPU hint),
  `/dev/accel` nodes (NPU hint), NVIDIA, และ compute targets ที่ prober เจอจริง
- ไม่ต้องบูต daemon — รันได้ทันทีบนเครื่องใหม่

> หมายเหตุ: ถ้ามี `/dev/dri/renderD*` แต่ `has_gpu_target: false` แปลว่าเครื่องมี
> iGPU/GPU ที่ compute scheduler **ยังมองไม่เห็น** (ตอนนี้ prober เจอเฉพาะ NVIDIA
> ผ่าน NVML) — เป็นงาน edge/Vulkan backend ที่ยังไม่ทำ

## 3. เชื่อมกับ Claude

### Path A — รัน Claude Code บนเครื่องนั้น (ง่ายสุด, ไม่ต้องเขียนโค้ด)

รัน Claude Code บน target host แล้วให้มันอ่าน `hw.json` (หรือรัน `ank-hwscan` เอง) —
Claude (โมเดลที่ขับ Claude Code) จะเห็น hardware จริง แล้ว generate config/backend
code ที่เหมาะกับเครื่องนั้น รวมถึงรัน validation ที่ค้างเพราะไม่มี hardware:

```bash
# บน target host, ใน session ของ Claude Code:
./target/release/ank-hwscan            # Claude เห็นผลสแกน
sudo bash scripts/validate-ebpf-attach.sh   # ปิด H1 validation บน host จริง
sudo ./run-privileged.sh cargo test -p kernel-companion --test privileged_h1_h2
```

Claude Code **คือ connection อยู่แล้ว** — ไม่ต้องเขียนอะไรเพิ่ม

### Path B — daemon เรียก Claude API เอง (programmatic, ยังไม่ได้ทำ)

ให้ตัว daemon เอา `hw.json` → format เป็น prompt → เรียก Claude API (`/v1/messages`
ผ่าน reqwest ที่มีใน workspace แล้ว) → ได้ placement decision กลับมาเติมให้
`CognitiveControlPlane` (advisory slot ที่ว่างอยู่)

ข้อควรระวัง:
- **API key** เป็น secret — ใช้ `secrecy`/`zeroize` (มีใน workspace) ห้าม log
- **การเรียก API เป็น network action** — ควร capability-scope เอง (H1–H8): agent
  "hardware-advisor" ได้ net scope เฉพาะ endpoint ของ Anthropic (dogfood ระบบ)

## 4. รัน agent ใต้ skill (หลัง scan)

```bash
# ตัวอย่าง: รัน agent ใต้ skill ที่ไม่มี network
sudo ./target/release/ank-run --skill skills/no-network.md \
    --cgroup /sys/fs/cgroup/ank-agents --no-fallback -- <command>

# ตัวอย่าง: skill ที่จำกัด path (scope_paths ใน manifest) — kernel บังคับ file_open
sudo ./target/release/ank-run --skill skills/file-reader.md --no-fallback \
    -- cat /srv/ank-demo/hello.txt     # ผ่าน (ใต้ scope)
sudo ./target/release/ank-run --skill skills/file-reader.md --no-fallback \
    -- cat /etc/shadow                 # Operation not permitted
```

skill ที่ประกาศ `scope_paths` จะถูกจำกัดที่ระดับ kernel ให้เปิดไฟล์ได้เฉพาะใต้
prefix ที่ประกาศ (สูงสุด 8 รายการ) — ank-run เติม prefix ระบบ read-only
(`/usr`, `/lib`, `/lib64`, `/etc/ld.so.cache`) ให้อัตโนมัติเพื่อให้ binary/lib
โหลดได้ (ปิดด้วย `--no-system-paths`)

ดู `crates/kernel-companion/src/bin/ank-run.rs` และ manifest format ใน
`crates/kernel-companion/src/skill.rs`
