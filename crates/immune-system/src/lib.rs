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

/// B-Cell: เรียนรู้ pattern การโจมตีและผลิต antibody (กฎ LSM ใหม่)
pub mod bcell;
/// Cytokine: สัญญาณ broadcast เหตุฉุกเฉินเพื่อระดม agent ทั้งระบบ
pub mod cytokine;
/// Macrophage: เก็บกวาด context หมดอายุและปล่อย process ที่พ้นโทษ
pub mod macrophage;
/// T-Cell: ตรวจจับ syscall ผิดปกติและกักกัน/kill process
pub mod tcell;

pub use bcell::BCellAgent;
pub use cytokine::CytokineSignal;
pub use macrophage::MacrophageAgent;
pub use tcell::{TCellAgent, ThreatDecision};

use thiserror::Error;

/// ข้อผิดพลาดของระบบภูมิคุ้มกัน
#[derive(Debug, Error)]
pub enum ImmuneError {
    /// ตรวจพบพฤติกรรมผิดปกติ
    #[error("anomaly detected: {0}")]
    AnomalyDetected(String),
    /// สั่งกักกัน process ไม่สำเร็จ
    #[error("quarantine failed: {0}")]
    QuarantineFailed(String),
    /// การเรียนรู้ pattern การโจมตีล้มเหลว
    #[error("pattern learning failed: {0}")]
    LearningFailed(String),
}

/// ชนิดผลลัพธ์มาตรฐานของ crate นี้ — ล้มเหลวด้วย [`ImmuneError`]
pub type Result<T> = core::result::Result<T, ImmuneError>;
