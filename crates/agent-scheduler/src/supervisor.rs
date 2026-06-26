use crate::block::{AgentControlBlock, AgentState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// บริการ Supervisor สำหรับตรวจสอบ เฝ้าระวัง และกู้คืนระบบการทำงานของ Agent (Self-healing)
/// ทำหน้าที่ติดตามสถานะ และทำการเริ่มต้นการทำงานใหม่ (Restart) เมื่อ Agent ล้มเหลวแบบอัตโนมัติ
#[derive(Debug, Clone)]
pub struct SupervisorService {
    /// รายการ AgentControlBlock ทั้งหมดในระบบ
    agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
    /// จำนวนครั้งสูงสุดที่อนุญาตให้ทำการ Restart Agent หลังจากล้มเหลว
    max_restarts: u32,
    /// ค่าตั้งต้นของเวลารอคอยแบบทวีคูณ (Backoff Delay) หน่วยเป็นมิลลิวินาที
    restart_backoff_ms: u64,
}

impl SupervisorService {
    /// สร้างอินสแตนซ์ใหม่ของ SupervisorService
    #[must_use]
    pub fn new(
        agents: Arc<RwLock<HashMap<u64, AgentControlBlock>>>,
        max_restarts: u32,
        restart_backoff_ms: u64,
    ) -> Self {
        Self {
            agents,
            max_restarts,
            restart_backoff_ms,
        }
    }

    /// ตรวจสอบและดำเนินมาตรการกู้คืน Agent ตัวใดตัวหนึ่ง โดยพิจารณาจากสถานะปัจจุบัน
    /// คืนค่าเป็น `true` หากกระบวนการติดตามผลหรือการ Restart สำเร็จ หรือ Agent ทำงานปกติ
    pub async fn monitor_agent(&self, agent: &AgentControlBlock) -> bool {
        match agent.state {
            // หากตรวจพบว่า Agent ล้มเหลว (Failed)
            AgentState::Failed => {
                // หากจำนวนครั้งที่ล้มเหลวยังไม่เกินกำหนด ให้ดำเนินการกู้คืนสถานะ
                if agent.restart_attempts < self.max_restarts {
                    // คำนวณ Backoff Delay แบบทวีคูณ (Exponential Backoff) จำกัดสูงสุดที่ 2^10 เท่า
                    let attempts = agent.restart_attempts.min(10);
                    let multiplier = 1_u64 << attempts;
                    let backoff = std::time::Duration::from_millis(
                        self.restart_backoff_ms.saturating_mul(multiplier),
                    );
                    // หน่วงเวลาก่อนเริ่มการกู้คืน
                    tokio::time::sleep(backoff).await;
                    self.restart_agent(agent.id).await
                } else {
                    // หากจำนวนครั้งการกู้คืนเกินเกณฑ์ที่กำหนดแล้ว จะไม่พยายามดึงกลับมาใหม่
                    false
                }
            }
            // หากตรวจพบว่า Agent กลับมาทำงานเรียบร้อยแล้ว (Running)
            AgentState::Running => {
                // ล้างตัวนับการล้มเหลว (Reset Counter) ให้เป็นศูนย์
                if agent.restart_attempts > 0 {
                    self.reset_restart_counter(agent.id).await;
                }
                true
            }
            // สถานะอื่นๆ (เช่น Creating, Paused, Terminating, Restarting) จะไม่มีการดำเนินกิจกรรมใดๆ
            _ => false,
        }
    }

    /// เริ่มต้นการประมวลผล Agent ใหม่อีกครั้ง โดยเปลี่ยนสถานะเป็น Running หลังกู้ภัยสำเร็จ
    async fn restart_agent(&self, agent_id: u64) -> bool {
        // เปลี่ยนสถานะเป็น Restarting และเพิ่มจำนวนครั้งการรีสตาร์ทขึ้น 1 ขณะถือครอง Write Lock ในระยะเวลาสั้นๆ
        {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.state = AgentState::Restarting;
                agent.restart_attempts = agent.restart_attempts.saturating_add(1);
                agent.last_restart = std::time::Instant::now();
            } else {
                return false;
            }
        }

        // นอนรอชั่วคราวเพื่อทำความสะอาดหรือปล่อยคิวประมวลผลโดยไม่มีความจำเป็นต้องถือ Lock ค้างไว้
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // เปลี่ยนสถานะกลับเป็น Running ภายใต้การถือครอง Write Lock ตัวใหม่เป็นระยะสั้นๆ
        {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&agent_id) {
                agent.state = AgentState::Running;
                true
            } else {
                false
            }
        }
    }

    /// ล้างค่าสถิติการรีสตาร์ทของ Agent ให้กลับมาเริ่มต้นนับใหม่ที่ศูนย์
    async fn reset_restart_counter(&self, agent_id: u64) {
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&agent_id) {
            agent.restart_attempts = 0;
        }
    }

    /// เริ่มต้นลูปตรวจตราเพื่อเฝ้าระวัง Agent ทั้งหมดแบบวนซ้ำ (Monitoring Loop)
    pub async fn start_monitoring_loop(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));

        loop {
            // รอจนกระทั่งครบกำหนดเวลา Tick ถัดไป
            interval.tick().await;

            // คัดลอกภาพถ่ายสถานะ (Snapshot) ของ Agent ทั้งหมดเพื่อเลี่ยงปัญหาการ Lock ค้างนาน
            let snapshot = {
                let agents = self.agents.read().await;
                agents.values().cloned().collect::<Vec<_>>()
            };

            // ประเมินผลและติดตามพฤติกรรมของ Agent แต่ละตัว
            for agent in snapshot {
                let _ = self.monitor_agent(&agent).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{AgentControlBlock, AgentState};
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_supervisor_restarts_failed_agent() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(1);
        agent.state = AgentState::Failed;
        agents.write().await.insert(1, agent);

        let supervisor = SupervisorService::new(agents.clone(), 3, 1);

        // ดึงสำเนาข้อมูล Agent ออกมาก่อนเพื่อปล่อย Read Lock ทันทีโดยไม่ค้างไว้
        let agent_to_monitor = {
            let reader = supervisor.agents.read().await;
            reader[&1].clone()
        };

        let restarted = supervisor.monitor_agent(&agent_to_monitor).await;
        assert!(restarted);

        let final_agent = &supervisor.agents.read().await[&1];
        assert_eq!(final_agent.state, AgentState::Running);
        assert_eq!(final_agent.restart_attempts, 1);
    }

    #[tokio::test]
    async fn test_supervisor_gives_up_after_max_restarts() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(2);
        agent.state = AgentState::Failed;
        agent.restart_attempts = 3;
        agents.write().await.insert(2, agent);

        let supervisor = SupervisorService::new(agents.clone(), 3, 1);

        // ดึงสำเนาข้อมูล Agent ออกมาก่อนเพื่อปล่อย Read Lock ทันทีโดยไม่ค้างไว้
        let agent_to_monitor = {
            let reader = supervisor.agents.read().await;
            reader[&2].clone()
        };

        let restarted = supervisor.monitor_agent(&agent_to_monitor).await;
        assert!(!restarted);

        let final_agent = &supervisor.agents.read().await[&2];
        assert_eq!(final_agent.state, AgentState::Failed);
        assert_eq!(final_agent.restart_attempts, 3);
    }

    #[tokio::test]
    async fn test_supervisor_loop_fault_injection() {
        let agents = Arc::new(RwLock::new(HashMap::new()));

        let mut agent = AgentControlBlock::new(3);
        agent.state = AgentState::Running;
        agents.write().await.insert(3, agent);

        let supervisor = SupervisorService::new(agents.clone(), 5, 1);

        // รันลูปเฝ้าระวังของ Supervisor ไว้ในเบื้องหลัง
        let supervisor_clone = supervisor.clone();
        let loop_handle = tokio::spawn(async move {
            supervisor_clone.start_monitoring_loop().await;
        });

        // หน่วงเวลาสั้นๆ เพื่อให้การทำงานของลูปเริ่มต้นและทำการ Tick ครั้งแรกสำเร็จ
        tokio::time::sleep(Duration::from_millis(50)).await;

        // จำลองสถานการณ์บกพร่อง: ปรับเปลี่ยนสถานะของ Agent ที่กำลังวิ่งอยู่ให้เป็น Failed (Fault Injection)
        {
            let mut writer = agents.write().await;
            if let Some(a) = writer.get_mut(&3) {
                a.state = AgentState::Failed;
            }
        }

        // รอคอยจนกระทั่งลูปของ Supervisor ตรวจพบและดำเนินการกู้ระบบใหม่เรียบร้อย
        tokio::time::sleep(Duration::from_millis(300)).await;

        // ตรวจสอบว่าระบบ Supervisor ได้ทำการกู้ภัยและ Restart กลับมายังสถานะ Running ได้จริง
        {
            let reader = agents.read().await;
            let a = &reader[&3];
            assert_eq!(a.state, AgentState::Running);
        }

        // ยกเลิกและหยุดการทำงานลูปของ Supervisor ในเบื้องหลัง
        loop_handle.abort();
    }
}
