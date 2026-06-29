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

/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub mod bcell;
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub mod cytokine;
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub mod macrophage;
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub mod tcell;

pub use bcell::BCellAgent;
pub use cytokine::CytokineSignal;
pub use macrophage::MacrophageAgent;
pub use tcell::{TCellAgent, ThreatDecision};

use thiserror::Error;

#[derive(Debug, Error)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub enum ImmuneError {
    #[error("anomaly detected: {0}")]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    AnomalyDetected(String),
    #[error("quarantine failed: {0}")]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    QuarantineFailed(String),
    #[error("pattern learning failed: {0}")]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    LearningFailed(String),
}

/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub type Result<T> = core::result::Result<T, ImmuneError>;
