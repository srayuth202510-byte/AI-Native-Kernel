//! ตัวช่วยจัดการ cgroup (v2) สำหรับ agent scope (Hardening H1)
//!
//! LSM hook ใน kernel ใช้ cgroup id เป็นตัวกำหนดขอบเขต enforcement:
//! process ใน cgroup ที่ลงทะเบียนเป็น agent scope จะตกอยู่ใต้ default-DENY
//! ส่วน process อื่นทั้งหมด (โลกของ host) ปล่อยผ่าน โมดูลนี้จัดการฝั่ง
//! filesystem: สร้าง cgroup directory, หา cgroup id (kernfs inode) และ
//! ย้าย PID ของ agent เข้า cgroup
//!
//! หมายเหตุ: การเขียน cgroupfs เป็น kernel call ขนาดเล็กที่จบทันที
//! (ไม่ใช่ block I/O จริง) จึงใช้ `std::fs` แบบ synchronous ได้

use anyhow::{Context, Result, bail};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tracing::info;

/// คืนค่า cgroup (v2) id ของ directory ที่กำหนด
///
/// cgroup v2 id ที่ `bpf_get_current_cgroup_id()` เห็นใน kernel คือ
/// kernfs inode number ของ cgroup directory ซึ่ง userspace อ่านได้จาก
/// `stat()` ของ directory นั้นบน cgroupfs โดยตรง
///
/// # Errors
///
/// ส่งคืนข้อผิดพลาดหาก path ไม่มีอยู่หรือไม่ใช่ directory
pub fn cgroup_id_of(path: &Path) -> Result<u64> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("cannot stat cgroup path {}", path.display()))?;
    if !meta.is_dir() {
        bail!("cgroup path {} is not a directory", path.display());
    }
    Ok(meta.ino())
}

/// ตัวแทน cgroup (v2) directory ที่ใช้เป็น agent scope
///
/// สร้างผ่าน [`AgentCgroup::ensure`] แล้วนำ [`AgentCgroup::id`] ไป
/// ลงทะเบียนกับ `LsmAttachment::register_agent_cgroup` จากนั้นทุก PID
/// ที่ authorize ผ่านจะถูกย้ายเข้า cgroup นี้ด้วย [`AgentCgroup::add_pid`]
#[derive(Debug, Clone)]
pub struct AgentCgroup {
    /// path ของ cgroup directory บน cgroupfs
    path: PathBuf,
    /// cgroup (v2) id — kernfs inode ที่ kernel hook ใช้เทียบ
    id: u64,
}

impl AgentCgroup {
    /// เปิดหรือสร้าง cgroup directory ที่ path ที่กำหนด แล้วอ่าน cgroup id
    ///
    /// ตรวจสอบว่า directory เป็น cgroup v2 จริง (ต้องมีไฟล์ `cgroup.procs`
    /// ที่ kernel สร้างให้อัตโนมัติ) เพื่อกัน config ชี้ path ผิดที่ —
    /// ถ้าลงทะเบียน inode ของ directory ธรรมดา enforcement จะไม่เกิดจริง
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากสร้าง directory ไม่ได้ หรือ path ไม่ใช่ cgroup v2
    pub fn ensure(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("cannot create cgroup {}", path.display()))?;
        }
        if !path.join("cgroup.procs").is_file() {
            bail!(
                "{} is not a cgroup v2 directory (no cgroup.procs) — \
                 check lsm.agent_cgroup_path points inside /sys/fs/cgroup",
                path.display()
            );
        }
        let id = cgroup_id_of(&path)?;
        info!(cgroup = %path.display(), cgroup_id = id, "agent cgroup ready");
        Ok(Self { path, id })
    }

    /// คืนค่า cgroup (v2) id สำหรับลงทะเบียนกับ LSM attachment
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// คืนค่า path ของ cgroup directory
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// ย้าย process เข้า cgroup นี้ — จากจุดนี้ไป PID จะตกอยู่ใต้
    /// default-DENY ของ kernel hook (ต้องอยู่ใน allow-list จึงผ่าน)
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากเขียน `cgroup.procs` ไม่สำเร็จ (เช่น ไม่มีสิทธิ์
    /// หรือ PID ไม่มีอยู่แล้ว) — ผู้เรียกต้อง fail closed: อย่าถือว่า PID
    /// อยู่ใต้ enforcement หากการย้ายล้มเหลว
    pub fn add_pid(&self, pid: u32) -> Result<()> {
        let procs = self.path.join("cgroup.procs");
        std::fs::write(&procs, pid.to_string()).with_context(|| {
            format!("cannot move PID {pid} into cgroup {}", self.path.display())
        })?;
        Ok(())
    }

    /// ตรวจสอบว่า PID อยู่ใน cgroup นี้หรือไม่ (อ่านจาก `cgroup.procs`)
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากอ่าน `cgroup.procs` ไม่สำเร็จ
    pub fn contains_pid(&self, pid: u32) -> Result<bool> {
        let procs = std::fs::read_to_string(self.path.join("cgroup.procs"))
            .with_context(|| format!("cannot read cgroup.procs of {}", self.path.display()))?;
        Ok(procs.lines().any(|line| line.trim() == pid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_id_of_missing_path_fails() {
        assert!(cgroup_id_of(Path::new("/definitely/not/a/cgroup")).is_err());
    }

    #[test]
    fn ensure_rejects_non_cgroup_directory() {
        // directory ธรรมดาไม่มี cgroup.procs — ต้องถูกปฏิเสธ ไม่ใช่ลงทะเบียน
        // inode มั่วๆ ที่ทำให้ enforcement ไม่เกิดจริงแบบเงียบๆ
        let tmp = std::env::temp_dir().join("ank-not-a-cgroup-test");
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let err = AgentCgroup::ensure(&tmp).expect_err("plain dir must be rejected");
        assert!(err.to_string().contains("not a cgroup v2 directory"));
        let _ = std::fs::remove_dir(&tmp);
    }

    #[test]
    fn cgroup_root_has_stable_id() {
        // /sys/fs/cgroup (root ของ cgroup v2) ต้อง stat ได้บนทุกเครื่อง
        // ที่ mount cgroup2 — id ของ root คือ inode 1 เสมอบน kernfs
        let root = Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.procs").is_file() {
            eprintln!("SKIP cgroup_root_has_stable_id: cgroup v2 not mounted");
            return;
        }
        let id = cgroup_id_of(root).expect("cgroup root must stat");
        assert!(id > 0, "cgroup id must be non-zero");
    }

    /// Privileged validation: สร้าง cgroup จริงใต้ /sys/fs/cgroup
    /// ต้องรันด้วยสิทธิ์ root — เครื่องอื่น skip
    #[test]
    fn validate_ensure_creates_real_cgroup() {
        let path = Path::new("/sys/fs/cgroup/ank-test-cgroup");
        let cg = match AgentCgroup::ensure(path) {
            Ok(cg) => cg,
            Err(e) => {
                eprintln!("SKIP validate_ensure_creates_real_cgroup: {e}");
                return;
            }
        };
        assert!(cg.id() > 0);
        assert_eq!(cg.path(), path);
        // cgroup ว่าง — PID ของเราต้องยังไม่อยู่ในนั้น
        let own_pid = std::process::id();
        assert!(!cg.contains_pid(own_pid).expect("read cgroup.procs"));
        let _ = std::fs::remove_dir(path);
        eprintln!("PASS: real cgroup created and inspected");
    }
}
