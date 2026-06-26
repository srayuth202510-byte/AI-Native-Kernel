use std::collections::BTreeSet;

use crate::token::{CapabilityToken, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    allowed_capabilities: BTreeSet<String>,
    default_decision: PolicyDecision,
}

impl PolicyEngine {
    #[must_use]
    pub fn new(default_decision: PolicyDecision) -> Self {
        Self::with_allowed_capabilities(default_decision, ["read", "execute"])
    }

    #[must_use]
    pub fn with_allowed_capabilities<I, S>(
        default_decision: PolicyDecision,
        capabilities: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed_capabilities: capabilities.into_iter().map(Into::into).collect(),
            default_decision,
        }
    }

    #[must_use]
    pub fn authorize(&self, token: &CapabilityToken, scope: &Scope, capability: &str) -> bool {
        matches!(
            self.decision(token, scope, capability),
            PolicyDecision::Allow
        )
    }

    #[must_use]
    pub fn decision(
        &self,
        token: &CapabilityToken,
        scope: &Scope,
        capability: &str,
    ) -> PolicyDecision {
        if !token.is_valid()
            || !token.allows(capability)
            || !self.allowed_capabilities.contains(capability)
        {
            return PolicyDecision::Deny;
        }

        if token.scope == *scope || matches!(token.scope, Scope::Global) {
            PolicyDecision::Allow
        } else {
            self.default_decision
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PolicyDecision::Deny)
    }
}
