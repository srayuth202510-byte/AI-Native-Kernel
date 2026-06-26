#![deny(unsafe_code)]

//! # Immune System — White Blood Cell Agents
//!
//! ระบบภูมิคุ้มกันของ AI-Native Kernel ที่เลียนแบบระบบภูมิคุ้มกันของสิ่งมีชีวิต
//! โดยใช้ AI Agents เป็น "White Blood Cell Agents" ทำหน้าที่ตรวจตรา ป้องกัน และกำจัดภัยคุกคาม
//!
//! ## สถาปัตยกรรม
//! ```text
//! Macrophage Agent ─── Garbage Collection (หมดอายุ / ขยะ)
//! T-Cell Agent ─────── Anomaly Detection + Kill Threat
//! B-Cell Agent ─────── Learn Pattern + Generate Antibody (LSM Rule)
//! Cytokine Signal ──── Critical Broadcast → Swarm Mobilization
//! ```

pub mod bcell;
pub mod cytokine;
pub mod macrophage;
pub mod tcell;

pub use bcell::BCellAgent;
pub use cytokine::CytokineSignal;
pub use macrophage::MacrophageAgent;
pub use tcell::TCellAgent;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImmuneError {
    #[error("anomaly detected: {0}")]
    AnomalyDetected(String),
    #[error("quarantine failed: {0}")]
    QuarantineFailed(String),
    #[error("pattern learning failed: {0}")]
    LearningFailed(String),
}

pub type Result<T> = core::result::Result<T, ImmuneError>;
