#![deny(unsafe_code)]

pub mod audit;
pub mod policy;
pub mod token;

use crate::audit::{AuditEntry, AuditLogger};
use crate::policy::{PolicyDecision, PolicyEngine};
pub use crate::token::{CapabilityToken, Scope};
use std::collections::HashMap;
use std::sync::RwLock;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, CapabilityError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("token validation failed")]
    TokenValidationFailed,
    #[error("policy decision denied")]
    PolicyDecisionDenied,
    #[error("audit write failed")]
    AuditWriteFailed,
    #[error("scope expansion failed")]
    ScopeExpansionFailed,
    #[error("token expiration error")]
    ExpirationError,
}

#[derive(Debug)]
pub struct CapabilitySecurityManager {
    tokens: RwLock<HashMap<u64, CapabilityToken>>,
    policy_engine: PolicyEngine,
    audit_logger: AuditLogger,
}

#[must_use]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

impl CapabilitySecurityManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::default(),
        }
    }

    #[must_use]
    pub fn new_with_log_path(log_path: std::path::PathBuf) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::new(log_path),
        }
    }

    pub fn issue_token(&self, token: CapabilityToken) {
        self.tokens
            .write()
            .expect("capability tokens lock poisoned")
            .insert(token.id, token.clone());
        self.audit_logger.record(AuditEntry::issued(token.id));
    }

    #[must_use]
    pub fn authorize_token(&self, token: &CapabilityToken, capability: &str) -> bool {
        let allowed = token.is_valid()
            && self
                .policy_engine
                .authorize(token, &token.scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger.record(entry);
        allowed
    }

    #[must_use]
    pub fn validate(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> bool {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            return false;
        };

        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger.record(AuditEntry::denied(token_id));
            return false;
        }

        let allowed = token.is_valid() && self.policy_engine.authorize(token, scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger.record(entry);
        allowed
    }

    #[must_use]
    pub fn decision_for(
        &self,
        token_id: u64,
        secret: &[u8; 32],
        scope: &Scope,
        capability: &str,
    ) -> PolicyDecision {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            self.audit_logger.record(AuditEntry::denied(token_id));
            return PolicyDecision::Deny;
        };

        if !constant_time_eq(&token.secret, secret) {
            self.audit_logger.record(AuditEntry::denied(token_id));
            return PolicyDecision::Deny;
        }

        let decision = self.policy_engine.decision(token, scope, capability);
        let entry = match decision {
            PolicyDecision::Allow => AuditEntry::allowed(token.id),
            PolicyDecision::Deny => AuditEntry::denied(token.id),
        };
        self.audit_logger.record(entry);
        decision
    }

    #[must_use]
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_logger.entries()
    }
}

impl Default for CapabilitySecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::CapabilitySecurityManager;
    use crate::policy::PolicyDecision;
    use crate::token::{CapabilityToken, Scope};
    use std::time::{Duration, SystemTime};

    #[test]
    fn issue_and_validate_token() {
        let log_path = std::env::temp_dir().join("test_audit_1.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            1,
            Scope::Process(42),
            vec!["read".to_string()],
            Duration::from_secs(60),
            [9u8; 32],
        );

        manager.issue_token(token.clone());

        assert!(manager.validate(1, &[9u8; 32], &Scope::Process(42), "read"));
        assert!(manager.authorize_token(&token, "read"));
        assert_eq!(
            manager.decision_for(1, &[9u8; 32], &Scope::Process(42), "read"),
            PolicyDecision::Allow
        );
        assert_eq!(manager.audit_entries().len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn rejects_expired_or_unauthorized_token() {
        let log_path = std::env::temp_dir().join("test_audit_2.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let expired = CapabilityToken {
            id: 2,
            scope: Scope::Thread(7),
            capabilities: vec!["write".to_string()],
            expires_at: SystemTime::now() - Duration::from_secs(1),
            secret: [8u8; 32],
        };

        manager.issue_token(expired.clone());

        assert!(!manager.authorize_token(&expired, "write"));
        assert!(!manager.validate(2, &[8u8; 32], &Scope::Thread(7), "write"));
        assert_eq!(
            manager.decision_for(2, &[8u8; 32], &Scope::Thread(7), "write"),
            PolicyDecision::Deny
        );
        assert_eq!(manager.audit_entries().len(), 4);
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn global_scope_can_authorize_across_scopes() {
        let log_path = std::env::temp_dir().join("test_audit_3.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            3,
            Scope::Global,
            vec!["execute".to_string()],
            Duration::from_secs(60),
            [7u8; 32],
        );

        manager.issue_token(token.clone());
        assert!(manager.authorize_token(&token, "execute"));
        assert_eq!(
            manager.decision_for(3, &[7u8; 32], &Scope::Process(99), "execute"),
            PolicyDecision::Allow
        );
        let _ = std::fs::remove_file(&log_path);
    }

    #[test]
    fn deny_capability_not_in_policy_allowlist() {
        let log_path = std::env::temp_dir().join("test_audit_4.log");
        let _ = std::fs::remove_file(&log_path);
        let manager = CapabilitySecurityManager::new_with_log_path(log_path.clone());
        let token = CapabilityToken::new(
            4,
            Scope::Global,
            vec!["write".to_string()],
            Duration::from_secs(60),
            [6u8; 32],
        );

        manager.issue_token(token.clone());

        assert!(!manager.authorize_token(&token, "write"));
        assert!(!manager.validate(4, &[6u8; 32], &Scope::Global, "write"));
        assert_eq!(
            manager.decision_for(4, &[6u8; 32], &Scope::Global, "write"),
            PolicyDecision::Deny
        );
        let _ = std::fs::remove_file(&log_path);
    }
}
