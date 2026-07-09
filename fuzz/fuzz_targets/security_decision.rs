#![no_main]

use capability_security::{
    CapabilitySecurityManager, CapabilityToken, Scope, constant_time_eq, policy::PolicyDecision,
};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime};

fuzz_target!(|data: &[u8]| {
    let token_id = data.len() as u64;
    let mut secret = [0u8; 32];
    for (index, byte) in data.iter().take(32).enumerate() {
        secret[index] = *byte;
    }

    let capability = std::str::from_utf8(data).unwrap_or("read");
    let scope = match data.first().copied().unwrap_or_default() % 3 {
        0 => Scope::Process(u32::from(data.first().copied().unwrap_or_default())),
        1 => Scope::Thread(u32::from(data.first().copied().unwrap_or_default())),
        _ => Scope::Global,
    };

    let token = CapabilityToken {
        id: token_id,
        scope,
        capabilities: vec![capability.chars().take(32).collect()],
        expires_at: SystemTime::now() + Duration::from_secs(1),
        secret,
    };

    let log_path = std::env::temp_dir().join(format!("ank-fuzz-security-{token_id}.log"));
    let _ = std::fs::remove_file(&log_path);
    let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime");
    rt.block_on(async {
        let _ = manager.issue_token(token.clone()).await;
        let _ = manager.authorize_token(&token, capability).await;
        let _ = manager
            .validate(token_id, &secret, &scope, capability)
            .await;
        let decision = manager
            .decision_for(token_id, &secret, &scope, capability)
            .await;
        let _ = matches!(decision, Ok(PolicyDecision::Allow | PolicyDecision::Deny));
    });
    let _ = constant_time_eq(&secret, &secret);
    let _ = std::fs::remove_file(log_path);
});
