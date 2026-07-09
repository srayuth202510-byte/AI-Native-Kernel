#![no_main]

use capability_security::{CapabilitySecurityManager, CapabilityToken, Scope, constant_time_eq};
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime};

fuzz_target!(|data: &[u8]| {
    let token_id = u64::from(data.first().copied().unwrap_or_default())
        | (u64::from(data.get(1).copied().unwrap_or_default()) << 8);
    let mut secret = [0u8; 32];
    for (index, byte) in data.iter().take(32).enumerate() {
        secret[index] = *byte;
    }

    let ttl = u64::from(data.get(2).copied().unwrap_or(1)).max(1);
    let scope = match data.get(3).copied().unwrap_or_default() % 3 {
        0 => Scope::Process(u32::from(data.get(4).copied().unwrap_or_default())),
        1 => Scope::Thread(u32::from(data.get(5).copied().unwrap_or_default())),
        _ => Scope::Global,
    };
    let capability = String::from_utf8_lossy(data.get(6..48).unwrap_or_default()).into_owned();

    let token = CapabilityToken {
        id: token_id,
        scope,
        capabilities: vec![capability.clone(), "read".to_string()],
        expires_at: if data.get(48).copied().unwrap_or_default() % 2 == 0 {
            SystemTime::now() + Duration::from_secs(ttl)
        } else {
            SystemTime::now() - Duration::from_secs(1)
        },
        secret,
    };

    let log_path = std::env::temp_dir().join(format!("ank-fuzz-cap-{token_id}.log"));
    let _ = std::fs::remove_file(&log_path);
    let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());

    let mut mismatched_secret = secret;
    mismatched_secret[0] ^= 0xFF;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("fuzz runtime");
    rt.block_on(async {
        let _ = manager.issue_token(token.clone()).await;
        let _ = manager.authorize_token(&token, &capability).await;
        let _ = manager
            .validate(token.id, &secret, &scope, &capability)
            .await;
        let _ = manager
            .decision_for(token.id, &secret, &scope, &capability)
            .await;

        let _ = manager
            .validate(token.id, &mismatched_secret, &scope, "read")
            .await;
        let _ = manager
            .decision_for(token.id, &mismatched_secret, &scope, "read")
            .await;

        let _ = manager.revoke_token(token.id).await;
        let _ = manager.validate(token.id, &secret, &scope, "read").await;
        let _ = manager
            .decision_for(token.id, &secret, &scope, "read")
            .await;
    });

    let _ = serde_json::to_string(&token)
        .ok()
        .and_then(|serialized| serde_json::from_str::<CapabilityToken>(&serialized).ok());
    let _ = constant_time_eq(&secret, &mismatched_secret);
    let _ = std::fs::remove_file(log_path);
});
