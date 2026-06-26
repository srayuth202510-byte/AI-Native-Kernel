use anyhow::Result;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LsmError {
    #[error("policy decision denied")]
    Denied,
    #[error("attachment failed")]
    AttachmentFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct LsmPolicyEngine {
    default_decision: LsmDecision,
}

impl LsmPolicyEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_decision: LsmDecision::Deny,
        }
    }

    #[must_use]
    pub fn decision_for_syscall(&self, syscall: &str) -> LsmDecision {
        match syscall {
            "read" | "write" | "recvmsg" => LsmDecision::Allow,
            _ => self.default_decision,
        }
    }
}

impl Default for LsmPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct LsmAttachment {
    attached: bool,
}

impl LsmAttachment {
    #[must_use]
    pub fn new() -> Self {
        Self { attached: true }
    }

    pub fn detach(&mut self) {
        self.attached = false;
    }

    #[must_use]
    pub fn is_attached(&self) -> bool {
        self.attached
    }
}

pub fn attach_lsm_hooks(_engine: Arc<LsmPolicyEngine>) -> Result<LsmAttachment> {
    Ok(LsmAttachment::new())
}
