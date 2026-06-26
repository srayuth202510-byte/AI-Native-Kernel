use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub action: String,
    pub token_id: u64,
    pub timestamp: u64,
}

impl AuditEntry {
    #[must_use]
    pub fn new(action: &str, token_id: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            action: action.to_string(),
            token_id,
            timestamp,
        }
    }

    #[must_use]
    pub fn issued(token_id: u64) -> Self {
        Self::new("issued", token_id)
    }

    #[must_use]
    pub fn allowed(token_id: u64) -> Self {
        Self::new("allowed", token_id)
    }

    #[must_use]
    pub fn denied(token_id: u64) -> Self {
        Self::new("denied", token_id)
    }
}

#[derive(Debug)]
pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    #[must_use]
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    pub fn record(&self, entry: AuditEntry) {
        // Open in append-only mode, create if it doesn't exist.
        // This is a WORM (Write Once Read Many) style operation at OS level.
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            if let Ok(json_str) = serde_json::to_string(&entry) {
                let _ = writeln!(file, "{}", json_str);
            }
        }
    }

    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        if let Ok(file) = File::open(&self.log_path) {
            let reader = BufReader::new(file);
            for line_str in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line_str) {
                    entries.push(entry);
                }
            }
        }
        entries
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new(PathBuf::from("audit.log"))
    }
}
