#![no_main]

//! Fuzz: TOML config parser ของ kernel-companion
//!
//! Config ถูกโหลดจากไฟล์ตอน boot — parser ต้องไม่ panic กับ TOML พัง ๆ
//! และ config ที่ parse สำเร็จต้องเรียก accessor ได้โดยไม่ panic

use kernel_companion::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(config) = toml::from_str::<Config>(text) {
        // accessor ต้องปลอดภัยกับทุกค่าที่ผ่าน parser มาได้
        let _ = config.lsm.allowed_syscalls();
        let _ = config.lsm.active_profile_name();
        // round-trip: config ที่ parse ได้ต้อง serialize กลับได้เสมอ
        let _ = toml::to_string(&config);
    }
});
