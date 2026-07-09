//! Property-based tests สำหรับ invariants ของ Capability Token และ Policy Engine
//!
//! Invariants หลักที่ต้องคงอยู่เสมอ (Zero-Trust / Fail-Closed):
//! 1. โทเค็นหมดอายุ → DENY เสมอ ไม่ว่า scope/capability/default จะเป็นอะไร
//! 2. โทเค็นไม่มี capability ที่ร้องขอ → DENY เสมอ
//! 3. capability นอก allowlist ของ engine → DENY เสมอ
//! 4. `authorize` ต้องสอดคล้องกับ `decision` ทุกกรณี
//! 5. Global scope + โทเค็นถูกต้อง + capability ใน allowlist → ALLOW

use capability_security::policy::{PolicyDecision, PolicyEngine};
use capability_security::token::{CapabilityToken, Scope};
use proptest::prelude::*;
use std::time::{Duration, SystemTime};

/// สุ่ม Scope ทุก variant
fn scope_strategy() -> impl Strategy<Value = Scope> {
    prop_oneof![
        any::<u32>().prop_map(Scope::Process),
        any::<u32>().prop_map(Scope::Thread),
        Just(Scope::Global),
    ]
}

/// สุ่มชื่อ capability จากชุดที่มีทั้งใน/นอก allowlist มาตรฐาน ("read", "execute")
fn capability_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("read".to_string()),
        Just("execute".to_string()),
        Just("write".to_string()),
        Just("delete".to_string()),
        "[a-z]{1,12}",
    ]
}

fn valid_token(id: u64, scope: Scope, capabilities: Vec<String>) -> CapabilityToken {
    CapabilityToken::new(
        id,
        scope,
        capabilities,
        Duration::from_secs(3600),
        [0xAA; 32],
    )
}

fn expired_token(id: u64, scope: Scope, capabilities: Vec<String>) -> CapabilityToken {
    CapabilityToken {
        id,
        scope,
        capabilities,
        expires_at: SystemTime::now() - Duration::from_secs(1),
        secret: [0xBB; 32],
    }
}

proptest! {
    /// Invariant 1: โทเค็นหมดอายุถูกปฏิเสธเสมอ แม้ default จะเป็น Allow
    #[test]
    fn expired_token_is_always_denied(
        id in any::<u64>(),
        token_scope in scope_strategy(),
        request_scope in scope_strategy(),
        capability in capability_strategy(),
        default_allow in any::<bool>(),
    ) {
        let default = if default_allow { PolicyDecision::Allow } else { PolicyDecision::Deny };
        let engine = PolicyEngine::new(default);
        let token = expired_token(id, token_scope, vec![capability.clone()]);

        prop_assert_eq!(
            engine.decision(&token, &request_scope, &capability),
            PolicyDecision::Deny
        );
    }

    /// Invariant 2: โทเค็นที่ไม่มี capability ที่ร้องขอถูกปฏิเสธเสมอ
    #[test]
    fn missing_capability_is_always_denied(
        id in any::<u64>(),
        token_scope in scope_strategy(),
        request_scope in scope_strategy(),
        granted in capability_strategy(),
        requested in capability_strategy(),
    ) {
        prop_assume!(granted != requested);
        let engine = PolicyEngine::new(PolicyDecision::Allow);
        let token = valid_token(id, token_scope, vec![granted]);

        prop_assert_eq!(
            engine.decision(&token, &request_scope, &requested),
            PolicyDecision::Deny
        );
    }

    /// Invariant 3: capability นอก allowlist ของ engine ถูกปฏิเสธเสมอ
    /// แม้โทเค็นจะถือ capability นั้นและ scope ตรงกัน
    #[test]
    fn capability_outside_allowlist_is_always_denied(
        id in any::<u64>(),
        scope in scope_strategy(),
        capability in "[a-z]{1,12}",
    ) {
        // allowlist มีแค่ "read" / "execute" — ตัด 2 ค่านี้ออกจากการสุ่ม
        prop_assume!(capability != "read" && capability != "execute");
        let engine = PolicyEngine::new(PolicyDecision::Allow);
        let token = valid_token(id, scope, vec![capability.clone()]);

        prop_assert_eq!(
            engine.decision(&token, &scope, &capability),
            PolicyDecision::Deny
        );
    }

    /// Invariant 4: `authorize` ต้องสอดคล้องกับ `decision` ทุกกรณี
    #[test]
    fn authorize_matches_decision(
        id in any::<u64>(),
        token_scope in scope_strategy(),
        request_scope in scope_strategy(),
        capability in capability_strategy(),
        expired in any::<bool>(),
    ) {
        let engine = PolicyEngine::default();
        let token = if expired {
            expired_token(id, token_scope, vec![capability.clone()])
        } else {
            valid_token(id, token_scope, vec![capability.clone()])
        };

        let decision = engine.decision(&token, &request_scope, &capability);
        prop_assert_eq!(
            engine.authorize(&token, &request_scope, &capability),
            decision == PolicyDecision::Allow
        );
    }

    /// Invariant 5: Global token ที่ถูกต้อง + capability ใน allowlist → ALLOW เสมอ
    #[test]
    fn valid_global_token_with_allowlisted_capability_is_allowed(
        id in any::<u64>(),
        request_scope in scope_strategy(),
        use_read in any::<bool>(),
    ) {
        let capability = if use_read { "read" } else { "execute" };
        let engine = PolicyEngine::default();
        let token = valid_token(id, Scope::Global, vec![capability.to_string()]);

        prop_assert_eq!(
            engine.decision(&token, &request_scope, capability),
            PolicyDecision::Allow
        );
    }

    /// Invariant 6: default = DENY + scope ไม่ตรงกัน (และไม่ใช่ Global) → DENY
    #[test]
    fn scope_mismatch_with_default_deny_is_denied(
        id in any::<u64>(),
        token_pid in any::<u32>(),
        request_pid in any::<u32>(),
        use_read in any::<bool>(),
    ) {
        prop_assume!(token_pid != request_pid);
        let capability = if use_read { "read" } else { "execute" };
        let engine = PolicyEngine::default();
        let token = valid_token(id, Scope::Process(token_pid), vec![capability.to_string()]);

        prop_assert_eq!(
            engine.decision(&token, &Scope::Process(request_pid), capability),
            PolicyDecision::Deny
        );
    }
}
