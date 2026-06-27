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
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use capability_security::Scope;

    #[test]
    fn test_agent_control_block_creation() {
        let acb = AgentControlBlock::new(42);
        assert_eq!(acb.id, 42);
        assert_eq!(acb.state, AgentState::Creating);
        assert_eq!(acb.priority, Priority::Batch);
        assert!(acb.context_key.is_none());
        assert!(acb.capabilities.is_empty());
        assert_eq!(acb.restart_attempts, 0);
        assert!(acb.last_restart.elapsed().as_nanos() > 0);
    }

    #[test]
    fn test_agent_control_block_with_custom_state() {
        let mut acb = AgentControlBlock::new(100);
        acb.state = AgentState::Running;
        acb.priority = Priority::Interactive;
        acb.context_key = Some("ctx123".to_string());
        acb.capabilities = vec![CapabilityToken::new(
            1,
            Scope::Global,
            vec!["read".to_string()],
            std::time::Duration::from_secs(60),
            [0x42u8; 32],
        )];
        acb.restart_attempts = 2;
        acb.last_restart = Instant::now() - std::time::Duration::from_secs(10);

        assert_eq!(acb.id, 100);
        assert_eq!(acb.state, AgentState::Running);
        assert_eq!(acb.priority, Priority::Interactive);
        assert_eq!(acb.context_key, Some("ctx123".to_string()));
        assert_eq!(acb.capabilities.len(), 1);
        assert_eq!(acb.restart_attempts, 2);
        assert!(acb.last_restart.elapsed().as_secs() >= 10);
    }

    #[test]
    fn test_agent_state_enum_all_variants() {
        let states = [
            AgentState::Creating,
            AgentState::Running,
            AgentState::Paused,
            AgentState::Terminating,
            AgentState::Failed,
            AgentState::Restarting,
        ];

        for state in states.iter().copied() {
            let mut acb = AgentControlBlock::new(0);
            acb.state = state;
            assert_eq!(acb.state, state);
        }
    }

    #[test]
    fn test_agent_control_block_clone() {
        let acb1 = AgentControlBlock::new(42);
        let acb2 = acb1.clone();

        assert_eq!(acb1.id, acb2.id);
        assert_eq!(acb1.state, acb2.state);
        assert_eq!(acb1.priority, acb2.priority);
        assert_eq!(acb1.context_key, acb2.context_key);
        assert_eq!(acb1.capabilities, acb2.capabilities);
        assert_eq!(acb1.restart_attempts, acb2.restart_attempts);
    }

    #[test]
    fn test_agent_control_block_debug() {
        let acb = AgentControlBlock::new(42);
        let debug_str = format!("{:?}", acb);
        assert!(debug_str.contains("AgentControlBlock"));
        assert!(debug_str.contains("id: 42"));
    }
}
