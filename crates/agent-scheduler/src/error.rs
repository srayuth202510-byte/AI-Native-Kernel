use thiserror::Error;

/// ข้อผิดพลาดที่เกิดขึ้นภายในระบบจัดตารางการทำงานของ Agent (Agent Scheduler)
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SchedulerError {
    /// เกิดขึ้นเมื่อพยายามสปอน Agent ด้วย ID ที่มีอยู่แล้วในระบบ
    #[error("agent already exists")]
    AgentAlreadyExists,
    
    /// ไม่พบ Agent ที่ระบุในสารระบบ
    #[error("agent not found")]
    AgentNotFound,
    
    /// การดำเนินการล้มเหลวเนื่องจาก Agent ไม่ได้อยู่ในสถานะ Running
    #[error("agent is not running")]
    AgentNotRunning,
    
    /// การดำเนินการล้มเหลวเนื่องจาก Agent ไม่ได้อยู่ในสถานะ Paused
    #[error("agent is not paused")]
    AgentNotPaused,
    
    /// ล้มเหลวในการส่งเจตจำนง (Intent) ลงสู่ Intent Bus
    #[error("intent dispatch failed")]
    IntentDispatchFailed,
    
    /// เกิดข้อผิดพลาดในการอัปเดตข้อมูลบริบท (Context Update)
    #[error("context update failed")]
    ContextUpdateFailed,
    
    /// การขอรับสิทธิ์ความสามารถ (Capability Token) ถูกปฏิเสธ
    #[error("capability denied")]
    CapabilityDenied,
    
    /// เกิดข้อผิดพลาดระบบความปลอดภัยภายในเมื่อขอรับสิทธิ์ความสามารถ
    #[error("capability security failure")]
    CapabilitySecurityFailed,
}
