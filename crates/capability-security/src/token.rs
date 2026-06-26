use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityToken {
    pub id: u64,
    pub scope: Scope,
    pub capabilities: Vec<String>,
    pub expires_at: SystemTime,
}

impl CapabilityToken {
    #[must_use]
    pub fn new(id: u64, scope: Scope, capabilities: Vec<String>, ttl: Duration) -> Self {
        Self {
            id,
            scope,
            capabilities,
            expires_at: SystemTime::now() + ttl,
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        SystemTime::now() <= self.expires_at
    }

    #[must_use]
    pub fn allows(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|item| item == capability)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Process(u32),
    Thread(u32),
    Global,
}
