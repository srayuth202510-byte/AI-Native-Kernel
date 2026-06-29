//! # Agent Scheduler
//!
//! โมดูลนี้ทำหน้าที่จัดการวงจรชีวิต (Lifecycle), จัดลำดับความสำคัญ (Priority),
//! และการแยกส่วนการทำงาน (Isolation) ของ Agent แต่ละตัวในระบบ AI-Native Kernel.
//! ทำงานประสานงานกับ Intent Bus, Context Memory, และ Capability Security.

#![deny(unsafe_code)]

/// โมดูลย่อยที่จัดการโครงสร้างของ Agent (AgentControlBlock, AgentState)
pub mod block;
/// โมดูลย่อยสำหรับข้อผิดพลาดต่างๆ ภายใน Agent Scheduler
pub mod error;
/// โมดูลย่อยที่จัดการคิวตามลำดับความสำคัญของ Agent
pub mod priority;
/// โมดูลย่อยหลักที่รับผิดชอบการสร้าง จัดการ และยุติการทำงานของ Agent
pub mod scheduler;
/// โมดูลย่อยสำหรับดูแลความน่าเชื่อถือและการเริ่มต้นใหม่ของ Agent เมื่อมีข้อผิดพลาด
pub mod supervisor;

pub use crate::error::SchedulerError;
pub use crate::scheduler::{AgentEvent, AgentScheduler, DistributedRoutingPolicy, RemoteNodeState};
pub use capability_security::{CapabilityToken, Scope};
pub use priority::{PriorityAgent, PriorityQueue};
pub use supervisor::SupervisorService as Supervisor;
