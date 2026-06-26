//! # Agent Scheduler
//!
//! โมดูลนี้ทำหน้าที่จัดการวงจรชีวิต (Lifecycle), จัดลำดับความสำคัญ (Priority),
//! และการแยกส่วนการทำงาน (Isolation) ของ Agent แต่ละตัวในระบบ AI-Native Kernel.
//! ทำงานประสานงานกับ Intent Bus, Context Memory, และ Capability Security.

#![deny(unsafe_code)]

pub mod block;
pub mod error;
pub mod priority;
pub mod scheduler;
pub mod supervisor;

pub use crate::error::SchedulerError;
pub use crate::scheduler::{AgentEvent, AgentScheduler};
pub use capability_security::{CapabilityToken, Scope};
pub use priority::{PriorityAgent, PriorityQueue};
pub use supervisor::SupervisorService as Supervisor;
