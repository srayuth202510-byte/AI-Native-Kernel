use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct CapabilityToken {
    pub id: u64,
    pub scope: Scope,
    #[zeroize(skip)]
    pub capabilities: Vec<String>,
    #[zeroize(skip)]
    pub expires_at: SystemTime,
    pub secret: [u8; 32],
}

impl CapabilityToken {
    #[must_use]
    pub fn new(
        id: u64,
        scope: Scope,
        capabilities: Vec<String>,
        ttl: Duration,
        secret: [u8; 32],
    ) -> Self {
        Self {
            id,
            scope,
            capabilities,
            expires_at: SystemTime::now() + ttl,
            secret,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
pub enum Scope {
    Process(u32),
    Thread(u32),
    Global,
}
