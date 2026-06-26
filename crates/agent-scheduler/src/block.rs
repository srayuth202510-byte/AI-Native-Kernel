use crate::priority::Priority;
use capability_security::CapabilityToken;
use std::time::Instant;

/// ข้อมูลควบคุมและสถานะของ Agent (Agent Control Block หรือ ACB)
/// เก็บข้อมูล Metadata ทั้งหมดที่จำเป็นต่อการบริหารจัดการ จัดสรรทรัพยากร และรักษาความปลอดภัยของ Agent
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentControlBlock {
    /// ID ของ Agent (ค่าเริ่มต้นคือ 0 ก่อนจัดสรร)
    pub id: u64,
    /// สถานะปัจจุบันของ Agent
    pub state: AgentState,
    /// ลำดับความสำคัญในการทำงาน (Priority) ของ Agent
    pub priority: Priority,
    /// คีย์ชี้ไปยังข้อมูลบริบท (Context Key) ในระบบประมวลผล Context Storage
    pub context_key: Option<String>,
    /// รายการสิทธิ์และข้อจำกัดการเข้าถึง (Capability Tokens) ที่ได้รับอนุญาต
    pub capabilities: Vec<CapabilityToken>,
    /// จำนวนครั้งที่ระบบพยายามเข้าทำการ Restart หลังเกิดความผิดพลาด
    pub restart_attempts: u32,
    /// เวลาล่าสุดที่ตัวควบคุม (Supervisor) ได้ทำการเริ่มการทำงานของ Agent นี้ใหม่
    pub last_restart: Instant,
}

/// สถานะวงจรชีวิต (Lifecycle States) ของ Agent ในระบบ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentState {
    /// อยู่ในระหว่างการสร้างข้อมูลและการเตรียมทรัพยากร
    Creating,
    /// กำลังทำงานอยู่ในระบบ
    Running,
    /// ถูกสั่งพักการทำงานชั่วคราว
    Paused,
    /// กำลังเข้าสู่กระบวนการทำลายและถอนการติดตั้งออกจากระบบ
    Terminating,
    /// เกิดเหตุขัดข้องหรือเกิดข้อผิดพลาดร้ายแรงขึ้น
    Failed,
    /// กำลังถูกเริ่มการทำงานใหม่ (Restart) โดย Supervisor Service
    Restarting,
}

impl AgentControlBlock {
    /// สร้าง Agent Control Block ชุดใหม่สำหรับ ID ที่กำหนด ด้วยค่าเริ่มต้นของระบบ
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            state: AgentState::Creating,
            priority: Priority::Batch,
            context_key: None,
            capabilities: Vec::new(),
            restart_attempts: 0,
            last_restart: Instant::now(),
        }
    }
}
