#![deny(unsafe_code)]

pub mod audit;
pub mod policy;
pub mod token;

use crate::audit::{AuditEntry, AuditLogger};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::token::{CapabilityToken, Scope};
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

impl CapabilitySecurityManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            policy_engine: PolicyEngine::default(),
            audit_logger: AuditLogger::default(),
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
        let allowed = token.is_valid() && self.policy_engine.authorize(token, &token.scope, capability);
        let entry = if allowed {
            AuditEntry::allowed(token.id)
        } else {
            AuditEntry::denied(token.id)
        };
        self.audit_logger.record(entry);
        allowed
    }

    #[must_use]
    pub fn validate(&self, token_id: u64, scope: &Scope, capability: &str) -> bool {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            return false;
        };

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
    pub fn decision_for(&self, token_id: u64, scope: &Scope, capability: &str) -> PolicyDecision {
        let tokens = self.tokens.read().expect("capability tokens lock poisoned");
        let Some(token) = tokens.get(&token_id) else {
            self.audit_logger.record(AuditEntry::denied(token_id));
            return PolicyDecision::Deny;
        };

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
    use crate::policy::PolicyDecision;
    use crate::token::{CapabilityToken, Scope};
    use crate::CapabilitySecurityManager;
    use std::time::{Duration, SystemTime};

    #[test]
    fn issue_and_validate_token() {
        let manager = CapabilitySecurityManager::new();
        let token = CapabilityToken::new(
            1,
            Scope::Process(42),
            vec!["read".to_string()],
            Duration::from_secs(60),
        );

        manager.issue_token(token.clone());

        assert!(manager.validate(1, &Scope::Process(42), "read"));
        assert!(manager.authorize_token(&token, "read"));
        assert_eq!(
            manager.decision_for(1, &Scope::Process(42), "read"),
            PolicyDecision::Allow
        );
        assert_eq!(manager.audit_entries().len(), 4);
    }

    #[test]
    fn rejects_expired_or_unauthorized_token() {
        let manager = CapabilitySecurityManager::new();
        let expired = CapabilityToken {
            id: 2,
            scope: Scope::Thread(7),
            capabilities: vec!["write".to_string()],
            expires_at: SystemTime::now() - Duration::from_secs(1),
        };

        manager.issue_token(expired.clone());

        assert!(!manager.authorize_token(&expired, "write"));
        assert!(!manager.validate(2, &Scope::Thread(7), "write"));
        assert_eq!(
            manager.decision_for(2, &Scope::Thread(7), "write"),
            PolicyDecision::Deny
        );
        assert_eq!(manager.audit_entries().len(), 4);
    }

    #[test]
    fn global_scope_can_authorize_across_scopes() {
        let manager = CapabilitySecurityManager::new();
        let token = CapabilityToken::new(
            3,
            Scope::Global,
            vec!["execute".to_string()],
            Duration::from_secs(60),
        );

        manager.issue_token(token.clone());
        assert!(manager.authorize_token(&token, "execute"));
        assert_eq!(
            manager.decision_for(3, &Scope::Process(99), "execute"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn deny_capability_not_in_policy_allowlist() {
        let manager = CapabilitySecurityManager::new();
        let token = CapabilityToken::new(
            4,
            Scope::Global,
            vec!["write".to_string()],
            Duration::from_secs(60),
        );

        manager.issue_token(token.clone());

        assert!(!manager.authorize_token(&token, "write"));
        assert!(!manager.validate(4, &Scope::Global, "write"));
        assert_eq!(
            manager.decision_for(4, &Scope::Global, "write"),
            PolicyDecision::Deny
        );
    }
}
