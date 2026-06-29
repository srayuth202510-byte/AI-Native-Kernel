#![allow(missing_docs)]
use capability_security::{
    CapabilitySecurityManager, CapabilityToken, Scope, policy::PolicyDecision,
};
use std::time::Duration;

fn manager(test_name: &str) -> (CapabilitySecurityManager, String) {
    let log_dir = std::env::temp_dir().join(format!("cap-security-int-{test_name}"));
    let _ = std::fs::remove_dir_all(&log_dir);
    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join("audit.log");
    (
        CapabilitySecurityManager::new_with_log_path(log_path),
        log_dir.display().to_string(),
    )
}

#[tokio::test]
async fn full_token_lifecycle() {
    let (manager, log_dir) = manager("full_token_lifecycle");
    let token = CapabilityToken::new(
        1,
        Scope::Global,
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0x01u8; 32],
    );

    manager
        .issue_token(token)
        .await
        .expect("issue should succeed");

    assert!(
        manager
            .validate(1, &[0x01u8; 32], &Scope::Global, "read")
            .await
            .expect("validate should succeed")
    );

    assert_eq!(
        manager
            .decision_for(1, &[0x01u8; 32], &Scope::Global, "read")
            .await
            .expect("decision should succeed"),
        PolicyDecision::Allow
    );

    assert_eq!(manager.audit_entries().await.len(), 3);
    let _ = std::fs::remove_dir_all(&log_dir);
}

#[tokio::test]
async fn multiple_tokens_isolated() {
    let (manager, log_dir) = manager("multi_tokens");

    for id in 0u64..10 {
        let token = CapabilityToken::new(
            id,
            Scope::Process(id as u32),
            vec!["execute".to_string()],
            Duration::from_secs(3600),
            [id as u8; 32],
        );
        manager
            .issue_token(token)
            .await
            .expect("issue should succeed");
    }

    for id in 0u64..10 {
        assert!(
            manager
                .validate(id, &[id as u8; 32], &Scope::Process(id as u32), "execute")
                .await
                .expect("validate should succeed")
        );
        assert!(
            !manager
                .validate(id, &[0xFFu8; 32], &Scope::Process(id as u32), "execute")
                .await
                .expect("wrong secret should fail")
        );
    }

    assert_eq!(manager.audit_entries().await.len(), 30);
    let _ = std::fs::remove_dir_all(&log_dir);
}

#[tokio::test]
async fn reject_expired_token() {
    let (manager, log_dir) = manager("reject_expired");
    let expired = CapabilityToken {
        id: 99,
        scope: Scope::Global,
        capabilities: vec!["read".to_string()],
        expires_at: std::time::SystemTime::now() - Duration::from_secs(1),
        secret: [0x99u8; 32],
    };

    manager
        .issue_token(expired)
        .await
        .expect("issue should succeed");

    assert!(
        !manager
            .validate(99, &[0x99u8; 32], &Scope::Global, "read")
            .await
            .expect("validate should succeed")
    );

    let _ = std::fs::remove_dir_all(&log_dir);
}

#[tokio::test]
async fn revoke_emits_audit_and_denies_future_validation() {
    let (manager, log_dir) = manager("revoke_audit_denial");
    let token = CapabilityToken::new(
        77,
        Scope::Process(77),
        vec!["read".to_string()],
        Duration::from_secs(3600),
        [0x77u8; 32],
    );

    manager
        .issue_token(token.clone())
        .await
        .expect("issue should succeed");
    manager
        .revoke_token(token.id)
        .await
        .expect("revoke should succeed");

    assert!(
        !manager
            .validate(token.id, &[0x77u8; 32], &Scope::Process(77), "read")
            .await
            .expect("revoked token should deny validation")
    );
    assert_eq!(
        manager
            .decision_for(token.id, &[0x77u8; 32], &Scope::Process(77), "read")
            .await
            .expect("decision should succeed"),
        PolicyDecision::Deny
    );

    let actions: Vec<String> = manager
        .audit_entries()
        .await
        .into_iter()
        .map(|entry| entry.action)
        .collect();
    assert_eq!(actions, vec!["issued", "revoked", "denied", "denied"]);

    let _ = std::fs::remove_dir_all(&log_dir);
}
