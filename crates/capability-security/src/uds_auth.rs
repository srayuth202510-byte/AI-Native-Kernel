//! # ระบบยืนยันตัวตนและอนุญาตสิทธิ์ผ่าน UDS (UDS Authorization & Session Management)
//!
//! โมดูลนี้ทำหน้าที่จัดการเซสชันการเชื่อมต่อของไคลเอนต์ (เช่น CLI หรือ TUI)
//! ที่ติดต่อเข้ามาทาง Unix Domain Socket (UDS) โดยใช้ Zero-Trust Capability Token
//! เพื่อรับประกันสิทธิ์การสั่งงานตามหลักการ Least Privilege

use crate::{CapabilitySecurityManager, CapabilityToken, Scope};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use tracing::{info, warn};

/// ข้อผิดพลาดของการตรวจสอบสิทธิ์และเซสชัน UDS
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UdsAuthError {
    /// การยืนยันความถูกต้องของโทเค็นล้มเหลว
    #[error("UDS Authentication failed")]
    AuthenticationFailed,
    /// เซสชันการทำงานหมดอายุเนื่องจากไม่มีกิจกรรมตามระยะเวลาที่กำหนด
    #[error("UDS Session expired")]
    SessionExpired,
    /// ไม่พบเซสชันตามรหัสที่ระบุ
    #[error("UDS Session not found")]
    SessionNotFound,
    /// สิทธิ์ (Capability) ไม่เพียงพอสำหรับการทำคำสั่งดังกล่าว
    #[error("Insufficient capabilities. Required: {required}, Available: {available:?}")]
    InsufficientCapabilities {
        required: String,
        available: Vec<String>,
    },
    /// เกิดข้อผิดพลาดในการอ่านเขียนไฟล์เก็บโทเค็นชั่วคราว
    #[error("Token file I/O error: {0}")]
    TokenFileError(String),
}

/// ขอบเขตระดับสิทธิ์สำหรับคำสั่งควบคุมผ่านซ็อกเก็ต UDS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdsCommandCapability {
    /// สิทธิ์อ่านข้อมูลเท่านั้น (เช่น คำสั่งดึงสถานะ)
    Read,
    /// สิทธิ์เขียนและแก้ไขค่าคอนฟิกพื้นฐาน
    Write,
    /// สิทธิ์ส่งคำสั่งหรือรัน Intent (เช่น ส่งคำสั่งให้สั่ง Agent)
    Execute,
    /// สิทธิ์ดูแลระบบความปลอดภัยระดับสูงสุด (เช่น เปลี่ยนโปรไฟล์ LSM หรือการจัดการ Token)
    Admin,
}

impl UdsCommandCapability {
    /// คืนค่าเป็นข้อความสิทธิ์ตามระบบนโยบายหลัก
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Admin => "admin",
        }
    }
}

impl std::fmt::Display for UdsCommandCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// ตัวจัดกลุ่มจับคู่ชื่อคำสั่ง UDS กับ Capability ที่จำเป็นต้องใช้
pub struct CommandCapabilityMap;

impl CommandCapabilityMap {
    /// คืนระดับความต้องการความสามารถของคำสั่งที่ระบุ
    #[must_use]
    pub fn required_capability(command: &str) -> UdsCommandCapability {
        match command {
            "status" | "list-quarantine" => UdsCommandCapability::Read,
            "set-threshold" | "set-lsm-profile" => UdsCommandCapability::Admin,
            "spawn-agent" => UdsCommandCapability::Execute,
            "auth" => UdsCommandCapability::Read,
            _ => UdsCommandCapability::Execute,
        }
    }
}

/// โครงสร้างข้อมูลเซสชันการเชื่อมต่อ UDS ที่ผ่านการตรวจสอบสิทธิ์แล้ว
#[derive(Debug, Clone)]
pub struct UdsSession {
    pub session_id: u64,
    pub token_id: u64,
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub created_at: Instant,
    pub last_activity: std::sync::Arc<parking_lot::Mutex<Instant>>,
    pub granted_capabilities: Vec<String>,
}

impl UdsSession {
    /// ตรวจสอบว่าเซสชันในปัจจุบันหมดอายุตาม TTL ที่กำหนดหรือไม่
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.last_activity.lock().elapsed() > ttl
    }

    /// อัปเดตเวลาการทำกิจกรรมล่าสุดของเซสชัน
    pub fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
    }

    /// ตรวจสอบว่าเซสชันนี้มีสิทธิ์ (Capability) ตามที่กำหนดไว้หรือไม่
    #[must_use]
    pub fn has_capability(&self, capability: &str) -> bool {
        self.granted_capabilities.iter().any(|c| c == capability)
    }
}

/// ตัวจัดการและตรวจสอบสิทธิ์การควบคุมระบบผ่าน UDS
#[derive(Debug)]
pub struct UdsAuthenticator {
    security_manager: std::sync::Arc<CapabilitySecurityManager>,
    sessions: parking_lot::RwLock<HashMap<u64, UdsSession>>,
    session_ttl: Duration,
    next_session_id: std::sync::atomic::AtomicU64,
}

impl UdsAuthenticator {
    /// สร้างออบเจกต์ตรวจสอบสิทธิ์ UDS
    #[must_use]
    pub fn new(
        security_manager: std::sync::Arc<CapabilitySecurityManager>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            security_manager,
            sessions: parking_lot::RwLock::new(HashMap::new()),
            session_ttl,
            next_session_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// ดำเนินการตรวจสอบสิทธิ์โทเค็นลับ (Token Secret)
    /// หากสิทธิ์ถูกต้อง จะบันทึกสร้างเซสชันใหม่พร้อมส่งค่า `UdsSession` กลับออกไป
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาด `UdsAuthError::AuthenticationFailed` หากโทเค็นใช้งานไม่ได้ ไม่พบ หรือรหัสไม่ตรง
    pub async fn authenticate(
        &self,
        peer_uid: u32,
        peer_pid: u32,
        token_id: u64,
        token_secret: &[u8; 32],
    ) -> Result<UdsSession, UdsAuthError> {
        // ค้นหา Token ในประวัติ
        let token = self
            .security_manager
            .get_tokens()
            .into_iter()
            .find(|t| t.id == token_id)
            .ok_or(UdsAuthError::AuthenticationFailed)?;

        // เลือก capability แรกที่มีเพื่อทำการ validate
        let cap_to_validate = token
            .capabilities
            .first()
            .cloned()
            .unwrap_or_else(|| "read".to_string());

        let valid = self
            .security_manager
            .validate(token_id, token_secret, &token.scope, &cap_to_validate)
            .await
            .map_err(|_| UdsAuthError::AuthenticationFailed)?;

        if !valid {
            return Err(UdsAuthError::AuthenticationFailed);
        }

        // ตรวจเช็ค Process Scope (ถ้ามีการกำหนด Process(pid) ต้องตรงกัน)
        if let Scope::Process(pid) = token.scope {
            if pid != peer_pid {
                warn!(
                    "Authentication failed: PID mismatch. Token is bound to PID {} but peer is PID {}",
                    pid, peer_pid
                );
                return Err(UdsAuthError::AuthenticationFailed);
            }
        }

        let session_id = self
            .next_session_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let session = UdsSession {
            session_id,
            token_id,
            peer_uid,
            peer_pid,
            created_at: Instant::now(),
            last_activity: std::sync::Arc::new(parking_lot::Mutex::new(Instant::now())),
            granted_capabilities: token.capabilities.clone(),
        };

        self.sessions.write().insert(session_id, session.clone());
        info!(
            "Authenticated UDS Client session {} for PID {} / UID {}",
            session_id, peer_pid, peer_uid
        );

        Ok(session)
    }

    /// ตรวจสอบว่าเซสชัน UDS มีสิทธิ์ทำคำสั่งดังกล่าวหรือไม่
    ///
    /// # Errors
    ///
    /// ส่งคืนข้อผิดพลาดหากไม่พบเซสชัน เซสชันหมดอายุ หรือสิทธิ์ไม่พอสำหรับรันคำสั่งดังกล่าว
    pub fn authorize_command(&self, session_id: u64, command: &str) -> Result<bool, UdsAuthError> {
        let required_cap = CommandCapabilityMap::required_capability(command);
        let required_cap_str = required_cap.as_str();

        let mut sessions = self.sessions.write();
        let session = sessions
            .get_mut(&session_id)
            .ok_or(UdsAuthError::SessionNotFound)?;

        if session.is_expired(self.session_ttl) {
            sessions.remove(&session_id);
            warn!("UDS command rejected: Session {} expired", session_id);
            return Err(UdsAuthError::SessionExpired);
        }

        let has_cap = session.has_capability(required_cap_str);
        if !has_cap {
            warn!(
                "UDS command '{}' rejected: Insufficient capabilities. Required: {}, Granted: {:?}",
                command, required_cap_str, session.granted_capabilities
            );
            return Err(UdsAuthError::InsufficientCapabilities {
                required: required_cap_str.to_string(),
                available: session.granted_capabilities.clone(),
            });
        }

        session.touch();
        Ok(true)
    }

    /// ยกเลิกเซสชันตาม ID
    pub fn revoke_session(&self, session_id: u64) {
        if self.sessions.write().remove(&session_id).is_some() {
            info!("Revoked UDS Session {}", session_id);
        }
    }

    /// ล้างเซสชันทั้งหมดที่หมดอายุออกจากตาราง
    pub fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write();
        let initial_len = sessions.len();
        sessions.retain(|_, session| !session.is_expired(self.session_ttl));
        initial_len - sessions.len()
    }

    /// คืนค่าจำนวนเซสชันที่ยังรันอยู่
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// ดึงข้อมูลออบเจกต์เซสชัน
    #[must_use]
    pub fn get_session(&self, session_id: u64) -> Option<UdsSession> {
        self.sessions.read().get(&session_id).cloned()
    }
}

/// คืนค่าตำแหน่งพาธไฟล์เก็บบันทึกโทเค็นเซสชันชั่วคราว
#[must_use]
pub fn token_file_path() -> PathBuf {
    use std::os::unix::fs::MetadataExt;

    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime_dir).join("ank").join("session.token")
    } else {
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0);
        PathBuf::from(format!("/tmp/ank-session-{}.token", uid))
    }
}

/// เขียนและจัดสรรข้อมูลบันทึกสิทธิ์โทเค็นลงระบบไฟล์ชั่วคราว พร้อมตั้งสิทธิ์อ่านเขียนเฉพาะเจ้าของ (0o600)
///
/// # Errors
///
/// คืนข้อผิดพลาด `UdsAuthError::TokenFileError` หากระบบไม่สามารถบันทึกหรือเปลี่ยนโหมดเข้าถึงไฟล์ได้
pub fn provision_token_file(
    _security_manager: &CapabilitySecurityManager,
    token_id: u64,
    token: &CapabilityToken,
) -> Result<PathBuf, UdsAuthError> {
    let path = token_file_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            UdsAuthError::TokenFileError(format!("Failed to create parent dir: {e}"))
        })?;
    }

    let expires_at_epoch = token
        .expires_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let secret_hex = bytes_to_hex(&token.secret);

    let token_data = serde_json::json!({
        "token_id": token_id,
        "secret": secret_hex,
        "capabilities": token.capabilities,
        "expires_at_epoch": expires_at_epoch,
    });

    let json_str = serde_json::to_string(&token_data)
        .map_err(|e| UdsAuthError::TokenFileError(format!("Failed to serialize token: {e}")))?;

    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            UdsAuthError::TokenFileError(format!("Failed to open token file for write: {e}"))
        })?;

    file.write_all(json_str.as_bytes())
        .map_err(|e| UdsAuthError::TokenFileError(format!("Failed to write token data: {e}")))?;

    Ok(path)
}

/// โหลดรายละเอียดโทเค็นที่ได้ลงทะเบียนไว้จากระบบไฟล์ชั่วคราว
///
/// # Errors
///
/// คืนข้อผิดพลาดหากไม่พบไฟล์ โครงสร้างข้อมูลไม่ถูกต้อง หรือค่า hex ของข้อมูลลับบิดเบือน
pub fn load_token_file() -> Result<(u64, [u8; 32]), UdsAuthError> {
    let path = token_file_path();

    let content = std::fs::read_to_string(&path)
        .map_err(|e| UdsAuthError::TokenFileError(format!("Failed to read token file: {e}")))?;

    let token_data: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| UdsAuthError::TokenFileError(format!("Failed to parse token content: {e}")))?;

    let token_id = token_data["token_id"]
        .as_u64()
        .ok_or_else(|| UdsAuthError::TokenFileError("Missing token_id".to_string()))?;

    let secret_hex = token_data["secret"]
        .as_str()
        .ok_or_else(|| UdsAuthError::TokenFileError("Missing secret".to_string()))?;

    let secret = hex_to_bytes(secret_hex)
        .ok_or_else(|| UdsAuthError::TokenFileError("Invalid hex format for secret".to_string()))?;

    Ok((token_id, secret))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_to_bytes(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_uds_command_capability_display() {
        assert_eq!(format!("{}", UdsCommandCapability::Read), "read");
        assert_eq!(format!("{}", UdsCommandCapability::Write), "write");
        assert_eq!(format!("{}", UdsCommandCapability::Execute), "execute");
        assert_eq!(format!("{}", UdsCommandCapability::Admin), "admin");
    }

    #[test]
    fn test_command_capability_mapping() {
        assert_eq!(
            CommandCapabilityMap::required_capability("status"),
            UdsCommandCapability::Read
        );
        assert_eq!(
            CommandCapabilityMap::required_capability("list-quarantine"),
            UdsCommandCapability::Read
        );
        assert_eq!(
            CommandCapabilityMap::required_capability("set-threshold"),
            UdsCommandCapability::Admin
        );
        assert_eq!(
            CommandCapabilityMap::required_capability("set-lsm-profile"),
            UdsCommandCapability::Admin
        );
        assert_eq!(
            CommandCapabilityMap::required_capability("spawn-agent"),
            UdsCommandCapability::Execute
        );
        assert_eq!(
            CommandCapabilityMap::required_capability("unknown"),
            UdsCommandCapability::Execute
        );
    }

    #[test]
    fn test_session_expiry() {
        let session = UdsSession {
            session_id: 1,
            token_id: 10,
            peer_uid: 1000,
            peer_pid: 2000,
            created_at: Instant::now(),
            last_activity: std::sync::Arc::new(parking_lot::Mutex::new(Instant::now())),
            granted_capabilities: vec!["read".to_string()],
        };

        assert!(!session.is_expired(Duration::from_secs(60)));

        // จำลองเวลาในอดีต
        *session.last_activity.lock() = Instant::now() - Duration::from_secs(10);
        assert!(session.is_expired(Duration::from_secs(5)));
    }

    #[test]
    fn test_session_touch() {
        let session = UdsSession {
            session_id: 1,
            token_id: 10,
            peer_uid: 1000,
            peer_pid: 2000,
            created_at: Instant::now(),
            last_activity: std::sync::Arc::new(parking_lot::Mutex::new(
                Instant::now() - Duration::from_secs(100),
            )),
            granted_capabilities: vec!["read".to_string()],
        };

        let initial_activity = *session.last_activity.lock();
        session.touch();
        let new_activity = *session.last_activity.lock();

        assert!(new_activity > initial_activity);
        assert!(!session.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = [42u8; 32];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex.len(), 64);
        let restored = hex_to_bytes(&hex).unwrap();
        assert_eq!(bytes, restored);

        assert!(hex_to_bytes("invalid").is_none());
    }

    #[test]
    fn test_token_file_path() {
        let path = token_file_path();
        assert!(path.to_string_lossy().contains("session.token"));
    }
}
