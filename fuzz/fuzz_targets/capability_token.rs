#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(token) = serde_json::from_str::<capability_security::CapabilityToken>(s) {
            let _ = token.is_valid();
            let _ = token.allows("read");
            let _ = serde_json::to_string(&token);
        }
    }
});
