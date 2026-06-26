#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub action: &'static str,
    pub token_id: u64,
}

impl AuditEntry {
    #[must_use]
    pub fn issued(token_id: u64) -> Self {
        Self {
            action: "issued",
            token_id,
        }
    }

    #[must_use]
    pub fn allowed(token_id: u64) -> Self {
        Self {
            action: "allowed",
            token_id,
        }
    }

    #[must_use]
    pub fn denied(token_id: u64) -> Self {
        Self {
            action: "denied",
            token_id,
        }
    }
}

#[derive(Debug, Default)]
pub struct AuditLogger {
    entries: std::sync::RwLock<Vec<AuditEntry>>,
}

impl AuditLogger {
    pub fn record(&self, entry: AuditEntry) {
        self.entries
            .write()
            .expect("audit log lock poisoned")
            .push(entry);
    }

    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries
            .read()
            .expect("audit log lock poisoned")
            .clone()
    }
}
