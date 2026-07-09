#![no_main]

//! Fuzz: UDS command → capability mapping + session authorization
//!
//! command string มาจาก client ภายนอกผ่าน Unix Domain Socket — เส้นทางนี้
//! ต้อง fail-closed เสมอ: command แปลก ๆ ต้องไม่ panic และ session ที่ไม่มีจริง
//! ต้องไม่ได้รับอนุญาต

use capability_security::CapabilitySecurityManager;
use capability_security::uds_auth::{CommandCapabilityMap, UdsAuthenticator};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let command = String::from_utf8_lossy(data).into_owned();

    // 1. command → required capability ต้องไม่ panic กับ string ใด ๆ
    let capability = CommandCapabilityMap::required_capability(&command);
    let _ = capability.as_str();
    let _ = format!("{capability}");

    // 2. authorize ด้วย session id สุ่มที่ไม่เคย authenticate — ต้อง fail-closed
    let session_id = u64::from_le_bytes([
        data.first().copied().unwrap_or_default(),
        data.get(1).copied().unwrap_or_default(),
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
        data.get(4).copied().unwrap_or_default(),
        data.get(5).copied().unwrap_or_default(),
        data.get(6).copied().unwrap_or_default(),
        data.get(7).copied().unwrap_or_default(),
    ]);

    let log_path = std::env::temp_dir().join(format!(
        "ank-fuzz-uds-{}.log",
        std::process::id()
    ));
    let manager = Arc::new(CapabilitySecurityManager::new_with_log_path(log_path));
    let auth = UdsAuthenticator::new(manager, Duration::from_secs(60));

    let allowed = auth.authorize_command(session_id, &command);
    assert!(
        !matches!(allowed, Ok(true)),
        "unauthenticated session must never be authorized (fail-closed)"
    );

    let _ = auth.cleanup_expired_sessions();
    let _ = auth.active_session_count();
});
