//! Intent → Scope compiler (Hardening H3)
//!
//! ปิด semantic gap ระหว่าง Intent (ประกาศเจตนา) กับ syscall (สิ่งที่ kernel
//! เห็น): แปลง intent เป็น scope ที่ **ตรวจได้เชิงกลไก** แล้ว push ลง BPF map
//! ก่อน agent เริ่มงาน — kernel hook บังคับใช้เองโดยไม่ต้องเดาเจตนา
//!
//! กติกาการ compile (deterministic ล้วน ไม่มี LLM ในเส้นทางตัดสินใจ):
//!
//! 1. **Grant จาก token**: capability strings ของ `CapabilityToken` กำหนด
//!    operation class ที่เปิดได้ (`read`/`write` → file_open, `exec`/`spawn`
//!    → exec, `net`/`socket` → socket)
//! 2. **Narrow จาก intent**: metadata ของ Intent บีบ scope ให้แคบลงได้
//!    เท่านั้น — **ห้ามขยาย** เกินที่ token ให้ (zero-trust composition):
//!    - `scope_path`   = จำกัด file_open ใต้ path เหล่านี้ (absolute, ไม่มี
//!      `..`) — หลาย path คั่นด้วย newline ได้สูงสุด [`MAX_PATH_PREFIXES`]
//!      ตัว (H3 v2: ชุด prefix ทำให้ launcher เติม system paths ที่จำเป็น
//!      ต่อการโหลด binary/lib ควบคู่กับ data path ของ skill ได้)
//!    - `scope_no_exec`, `scope_no_net`, `scope_no_file` = ปิด class นั้นๆ
//!
//! ผลลัพธ์ผูกกับ PID ผ่าน `LsmAttachment::set_pid_scope` ซึ่งเขียนลง
//! `pid_scope_flags` / `pid_path_prefixes` maps ให้ `lsm_gate()` ใช้ตัดสิน

use intent_bus::Intent;
use thiserror::Error;

/// bit ของ operation class — ต้องตรงกับ `SCOPE_*` ใน lsm-security.bpf.c
pub const SCOPE_FILE_OPEN: u32 = 1;
/// bit อนุญาต execve / spawn process ลูก
pub const SCOPE_EXEC: u32 = 2;
/// bit อนุญาตสร้าง socket
pub const SCOPE_SOCKET: u32 = 4;

/// ความยาวสูงสุดของ path prefix (รวม NUL) — ต้องตรงกับ `PATH_PREFIX_MAX`
/// ใน lsm-security.bpf.c
pub const PATH_PREFIX_MAX: usize = 128;

/// จำนวน path prefix สูงสุดต่อ scope — ต้องตรงกับ `MAX_PATH_PREFIXES`
/// ใน lsm-security.bpf.c (H3 v2)
pub const MAX_PATH_PREFIXES: usize = 8;

/// ขนาด buffer ของชุด prefix ทั้งชุดใน BPF map slot — ต้องตรงกับ
/// `struct path_prefix_set` ใน lsm-security.bpf.c
pub const PATH_SET_LEN: usize = MAX_PATH_PREFIXES * PATH_PREFIX_MAX;

/// ข้อผิดพลาดจากการ compile intent เป็น scope
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// path ที่ประกาศใน intent ไม่ผ่านการตรวจเชิงกลไก
    #[error("invalid scope path: {0}")]
    InvalidPath(String),
    /// ประกาศ path prefix เกินจำนวน slot ใน BPF map
    #[error("too many scope paths: {count} declared, max {MAX_PATH_PREFIXES}")]
    TooManyPaths {
        /// จำนวน prefix ที่ประกาศมา
        count: usize,
    },
}

/// Scope ที่ตรวจได้เชิงกลไก — ผลลัพธ์ของการ compile intent + token caps
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentScope {
    /// bitmask ของ operation class ที่อนุญาต (`SCOPE_*`)
    pub class_flags: u32,
    /// จำกัด file_open เฉพาะ path เหล่านี้และใต้มัน — เปิดไฟล์ได้เมื่อ path
    /// อยู่ใต้ prefix **ตัวใดตัวหนึ่ง** ในชุด (ว่าง = ไม่จำกัด path)
    pub path_prefixes: Vec<String>,
}

impl IntentScope {
    /// compile capability strings ของ token + intent metadata เป็น scope
    ///
    /// ขั้นแรก grant class ตาม capabilities แล้วให้ intent **บีบแคบลง**
    /// เท่านั้น — metadata ที่พยายามเปิด class ที่ token ไม่ได้ให้จะไม่มีผล
    /// โดยโครงสร้าง (ไม่มีทาง set bit เพิ่ม มีแต่ clear)
    ///
    /// # Errors
    ///
    /// ส่งคืน [`ScopeError::InvalidPath`] เมื่อ path ใดใน `scope_path`
    /// (คั่นด้วย newline) ไม่ absolute, มี `..`, มี NUL, หรือยาวเกิน
    /// [`PATH_PREFIX_MAX`] และ [`ScopeError::TooManyPaths`] เมื่อประกาศ
    /// เกิน [`MAX_PATH_PREFIXES`] ตัว
    pub fn compile<S: AsRef<str>>(
        capabilities: &[S],
        intent: Option<&Intent>,
    ) -> Result<Self, ScopeError> {
        // 1. grant จาก token capabilities
        let mut class_flags = 0u32;
        for cap in capabilities {
            match cap.as_ref() {
                "read" | "write" => class_flags |= SCOPE_FILE_OPEN,
                "exec" | "spawn" => class_flags |= SCOPE_EXEC,
                "net" | "socket" => class_flags |= SCOPE_SOCKET,
                _ => {}
            }
        }

        let mut path_prefixes = Vec::new();

        // 2. narrow จาก intent metadata (clear bit ได้อย่างเดียว)
        if let Some(intent) = intent {
            let meta = &intent.metadata;
            if meta.contains_key("scope_no_file") {
                class_flags &= !SCOPE_FILE_OPEN;
            }
            if meta.contains_key("scope_no_exec") {
                class_flags &= !SCOPE_EXEC;
            }
            if meta.contains_key("scope_no_net") {
                class_flags &= !SCOPE_SOCKET;
            }
            if let Some(paths) = meta.get("scope_path") {
                // หลาย path คั่นด้วย newline (path ที่มี newline ในตัวจะถูก
                // ตีความเป็นหลาย prefix — แต่ละชิ้นยังต้องผ่าน validation
                // เชิงกลไกเหมือนกัน จึงไม่มีทางหลุดกรอบ token)
                for path in paths.split('\n').filter(|p| !p.trim().is_empty()) {
                    let validated = validate_scope_path(path)?;
                    if !path_prefixes.contains(&validated) {
                        path_prefixes.push(validated);
                    }
                }
                // ประกาศ scope_path มาแต่ไม่มี path จริง — ปฏิเสธ ไม่ใช่
                // ตีความเป็น "ไม่จำกัด" (fail closed)
                if path_prefixes.is_empty() {
                    return Err(ScopeError::InvalidPath(
                        "scope_path declared but empty".to_string(),
                    ));
                }
                if path_prefixes.len() > MAX_PATH_PREFIXES {
                    return Err(ScopeError::TooManyPaths {
                        count: path_prefixes.len(),
                    });
                }
            }
        }

        Ok(Self {
            class_flags,
            path_prefixes,
        })
    }

    /// scope ที่ไม่จำกัดอะไรเลย (ทุก class เปิด ไม่มี path prefix) — ใช้เป็น
    /// พฤติกรรมเทียบเท่าก่อน H3 สำหรับ caller ที่ไม่มี intent ประกอบ
    #[must_use]
    pub fn unrestricted() -> Self {
        Self {
            class_flags: SCOPE_FILE_OPEN | SCOPE_EXEC | SCOPE_SOCKET,
            path_prefixes: Vec::new(),
        }
    }

    /// แปลงชุด path prefix เป็น buffer ขนาดคงที่ (layout ตรงกับ
    /// `struct path_prefix_set` ใน BPF) สำหรับเขียนลง map — slot ละ
    /// [`PATH_PREFIX_MAX`] ไบต์ NUL-terminated เติมจากหน้าไปหลัง, slot ที่
    /// เหลือเป็น NUL ล้วน (BPF matcher หยุดที่ slot ว่างตัวแรก)
    /// คืน `None` เมื่อ scope นี้ไม่จำกัด path
    #[must_use]
    pub fn path_set_bytes(&self) -> Option<[u8; PATH_SET_LEN]> {
        if self.path_prefixes.is_empty() {
            return None;
        }
        let mut buf = [0u8; PATH_SET_LEN];
        // compile การันตีจำนวน ≤ MAX_PATH_PREFIXES และความยาวแต่ละตัว
        // < PATH_PREFIX_MAX แล้ว
        for (slot, prefix) in self.path_prefixes.iter().enumerate() {
            let start = slot * PATH_PREFIX_MAX;
            buf[start..start + prefix.len()].copy_from_slice(prefix.as_bytes());
        }
        Some(buf)
    }
}

/// ตรวจ path ที่ประกาศใน intent เชิงกลไกล้วน (fail closed):
/// ต้อง absolute, ห้าม `..` component, ห้าม NUL byte, ยาวไม่เกิน map slot
/// และตัด trailing slash ให้ตรง semantics ของ BPF prefix matcher
fn validate_scope_path(path: &str) -> Result<String, ScopeError> {
    if !path.starts_with('/') {
        return Err(ScopeError::InvalidPath(format!(
            "must be absolute: {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(ScopeError::InvalidPath("contains NUL byte".to_string()));
    }
    if path.split('/').any(|component| component == "..") {
        return Err(ScopeError::InvalidPath(format!(
            "must not contain '..': {path:?}"
        )));
    }
    let trimmed = path.trim_end_matches('/');
    // "/" ไม่ใช่การจำกัด (ทุก path อยู่ใต้ root) และไม่ตรง semantics ของ
    // BPF matcher — ถ้าไม่ต้องการจำกัด path ให้ละ scope_path ไปเลย
    if trimmed.is_empty() {
        return Err(ScopeError::InvalidPath(
            "'/' is not a restriction — omit scope_path instead".to_string(),
        ));
    }
    // ต้องเผื่อ NUL terminator ใน BPF map slot
    if trimmed.len() >= PATH_PREFIX_MAX {
        return Err(ScopeError::InvalidPath(format!(
            "longer than {} bytes: {path:?}",
            PATH_PREFIX_MAX - 1
        )));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use intent_bus::{IntentPriority, IntentType};

    fn intent_with(pairs: &[(&str, &str)]) -> Intent {
        let mut intent = Intent::new(
            "test-intent",
            IntentType::Structured,
            "summarize project",
            IntentPriority::Medium,
            "test",
        );
        for (k, v) in pairs {
            intent.metadata.insert((*k).to_string(), (*v).to_string());
        }
        intent
    }

    #[test]
    fn token_caps_grant_classes() {
        let scope = IntentScope::compile(&["read", "net"], None).expect("compile");
        assert_eq!(scope.class_flags, SCOPE_FILE_OPEN | SCOPE_SOCKET);
        assert!(scope.path_prefixes.is_empty());
    }

    #[test]
    fn unknown_caps_grant_nothing() {
        // capability แปลกๆ ต้องไม่เปิด class ใดเลย (fail closed)
        let scope = IntentScope::compile(&["frobnicate"], None).expect("compile");
        assert_eq!(scope.class_flags, 0);
    }

    #[test]
    fn intent_narrows_but_never_widens() {
        // token ให้แค่ read — intent ปิด net เพิ่ม (no-op) และไม่มีทางเปิด exec
        let intent = intent_with(&[("scope_no_net", "1")]);
        let scope = IntentScope::compile(&["read"], Some(&intent)).expect("compile");
        assert_eq!(scope.class_flags, SCOPE_FILE_OPEN);

        let intent = intent_with(&[("scope_no_file", "1")]);
        let scope = IntentScope::compile(&["read", "exec", "net"], Some(&intent)).expect("compile");
        assert_eq!(scope.class_flags, SCOPE_EXEC | SCOPE_SOCKET);
    }

    #[test]
    fn scope_path_is_validated_mechanically() {
        let ok = intent_with(&[("scope_path", "/srv/project-x/")]);
        let scope = IntentScope::compile(&["read"], Some(&ok)).expect("compile");
        // trailing slash ถูกตัดให้ตรง BPF matcher (เทียบ prefix + '/' เอง)
        assert_eq!(scope.path_prefixes, vec!["/srv/project-x".to_string()]);

        for bad in ["relative/path", "/srv/../etc", "/x\0y"] {
            let intent = intent_with(&[("scope_path", bad)]);
            assert!(
                IntentScope::compile(&["read"], Some(&intent)).is_err(),
                "{bad:?} must be rejected"
            );
        }

        let too_long = format!("/{}", "a".repeat(PATH_PREFIX_MAX));
        let intent = intent_with(&[("scope_path", too_long.as_str())]);
        assert!(IntentScope::compile(&["read"], Some(&intent)).is_err());
    }

    #[test]
    fn multi_path_scope_compiles_and_dedupes() {
        // H3 v2: หลาย path คั่น newline — ทุกตัวต้องผ่าน validation,
        // ตัวซ้ำถูกรวบ, ลำดับคงเดิม
        let intent = intent_with(&[("scope_path", "/srv/data\n/usr\n/srv/data\n\n/lib/")]);
        let scope = IntentScope::compile(&["read"], Some(&intent)).expect("compile");
        assert_eq!(scope.path_prefixes, vec!["/srv/data", "/usr", "/lib"]);

        // ตัวใดตัวหนึ่งไม่ผ่าน = ทั้ง scope ไม่ผ่าน (fail closed)
        let intent = intent_with(&[("scope_path", "/srv/data\nrelative")]);
        assert!(IntentScope::compile(&["read"], Some(&intent)).is_err());

        // ประกาศ scope_path แต่ว่างเปล่า = ปฏิเสธ ไม่ใช่ "ไม่จำกัด"
        let intent = intent_with(&[("scope_path", "\n\n")]);
        assert!(IntentScope::compile(&["read"], Some(&intent)).is_err());
    }

    #[test]
    fn more_than_max_prefixes_is_rejected() {
        let many: Vec<String> = (0..=MAX_PATH_PREFIXES).map(|i| format!("/p{i}")).collect();
        let joined = many.join("\n");
        let intent = intent_with(&[("scope_path", joined.as_str())]);
        assert!(matches!(
            IntentScope::compile(&["read"], Some(&intent)),
            Err(ScopeError::TooManyPaths { count }) if count == MAX_PATH_PREFIXES + 1
        ));
    }

    #[test]
    fn path_set_bytes_matches_bpf_slot_layout() {
        let intent = intent_with(&[("scope_path", "/data\n/usr")]);
        let scope = IntentScope::compile(&["read"], Some(&intent)).expect("compile");
        let buf = scope.path_set_bytes().expect("prefixes present");
        assert_eq!(&buf[..5], b"/data");
        assert!(buf[5..PATH_PREFIX_MAX].iter().all(|&b| b == 0));
        assert_eq!(&buf[PATH_PREFIX_MAX..PATH_PREFIX_MAX + 4], b"/usr");
        assert!(
            buf[PATH_PREFIX_MAX + 4..].iter().all(|&b| b == 0),
            "unused slots must stay NUL so the BPF matcher stops there"
        );
        assert_eq!(IntentScope::unrestricted().path_set_bytes(), None);
    }

    #[test]
    fn root_scope_path_is_rejected() {
        // "/" ครอบทุก path = ไม่ใช่การจำกัด — ต้อง reject ไม่ใช่แกล้งจำกัด
        let intent = intent_with(&[("scope_path", "/")]);
        assert!(IntentScope::compile(&["read"], Some(&intent)).is_err());
    }
}
