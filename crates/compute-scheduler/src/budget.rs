use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// ข้อผิดพลาดสำหรับ GpuBudgetController
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum BudgetError {
    /// ไม่เคยตั้งงบประมาณให้ agent นี้
    #[error("Agent {agent} has no budget configured")]
    AgentNotFound {
        /// ชื่อ agent ที่หาไม่พบ
        agent: String,
    },
    /// คำขอเกินงบประมาณ VRAM ที่เหลือของ agent
    #[error("Agent {agent} budget exceeded: ต้องการ {requested} ไบต์ เหลือ {remaining} ไบต์")]
    BudgetExceeded {
        /// ชื่อ agent ที่ขอเกินงบ
        agent: String,
        /// จำนวนไบต์ที่ขอ
        requested: usize,
        /// จำนวนไบต์ที่ยังเหลือในงบ
        remaining: usize,
    },
    /// ระบบมีแรงกดดันหน่วยความจำรวม (ไม่ใช่แค่ agent เดียว)
    #[error("System memory pressure: {reason}")]
    SystemPressure {
        /// คำอธิบายสาเหตุของแรงกดดัน
        reason: String,
    },
}

/// ระดับความสำคัญของ Agent — ส่งผลต่อการ preempt
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AgentPriority {
    /// งานระบบปฏิบัติการ (kernel services)
    System = 3,
    /// งานผู้ใช้ที่ต้องการตอบสนองทันที (real-time)
    Interactive = 2,
    /// งานทั่วไป
    Normal = 1,
    /// งานพื้นหลัง (batch, training)
    Batch = 0,
}

/// งบประมาณ VRAM สำหรับ agent แต่ละตัว
#[derive(Debug, Clone, Copy)]
pub struct AgentBudget {
    /// VRAM สูงสุดที่ agent นี้ใช้ได้ (ไบต์)
    pub max_bytes: usize,
    /// VRAM ที่ใช้อยู่ปัจจุบัน (ไบต์)
    pub used_bytes: usize,
    /// ระดับความสำคัญ (ใช้สำหรับ preemption)
    pub priority: AgentPriority,
}

impl AgentBudget {
    /// สร้างงบประมาณใหม่ (เริ่มต้นยังไม่ใช้ VRAM เลย)
    #[must_use]
    pub fn new(max_bytes: usize, priority: AgentPriority) -> Self {
        Self {
            max_bytes,
            used_bytes: 0,
            priority,
        }
    }

    /// VRAM คงเหลือสำหรับ agent นี้
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.max_bytes.saturating_sub(self.used_bytes)
    }

    /// ตรวจสอบว่ามีพื้นที่พอหรือไม่
    #[must_use]
    pub fn can_allocate(&self, size_bytes: usize) -> bool {
        self.remaining() >= size_bytes
    }
}

/// GpuBudgetController — จัดการงบประมาณ VRAM แบบ per-agent
///
/// ## การทำงาน
/// - แต่ละ agent มีงบประมาณ VRAM ของตัวเอง (max_bytes)
/// - Agent ระดับความสำคัญสูงกว่าสามารถ preempt agent ระดับต่ำกว่าได้
/// - รองรับ system memory pressure detection
/// - กัน agent ตัวหนึ่งกิน VRAM จนตัวอื่นทำงานไม่ได้
#[derive(Debug)]
pub struct GpuBudgetController {
    /// งบประมาณของแต่ละ agent (agent_id → budget)
    budgets: RwLock<HashMap<String, AgentBudget>>,
    /// ขนาด VRAM รวมของระบบ (ไบต์)
    system_capacity: usize,
    /// ค่าเริ่มต้นของงบประมาณสำหรับ agent ใหม่ (ไบต์)
    default_budget: usize,
}

impl GpuBudgetController {
    /// สร้าง GpuBudgetController ใหม่
    #[must_use]
    pub fn new(system_capacity: usize) -> Self {
        Self {
            budgets: RwLock::new(HashMap::new()),
            system_capacity,
            default_budget: system_capacity / 8, // default: ⅛ ของ VRAM ทั้งหมด
        }
    }

    /// สร้าง GpuBudgetController พร้อม default budget ที่กำหนด
    #[must_use]
    pub fn with_default_budget(mut self, default_budget: usize) -> Self {
        self.default_budget = default_budget;
        self
    }

    /// ลงทะเบียน agent พร้อมงบประมาณเริ่มต้น
    pub fn register_agent(&self, agent_id: &str, priority: AgentPriority) {
        let mut budgets = self.budgets.write();
        let budget = AgentBudget::new(self.default_budget, priority);
        budgets.insert(agent_id.to_string(), budget);
        debug!(
            agent = %agent_id,
            budget_mb = %(self.default_budget / 1024 / 1024),
            priority = ?priority,
            "Agent registered with GPU budget"
        );
    }

    /// ลงทะเบียน agent พร้อมงบประมาณที่กำหนดเอง
    pub fn register_agent_with_budget(
        &self,
        agent_id: &str,
        max_bytes: usize,
        priority: AgentPriority,
    ) {
        let mut budgets = self.budgets.write();
        let budget = AgentBudget::new(max_bytes, priority);
        budgets.insert(agent_id.to_string(), budget);
        info!(
            agent = %agent_id,
            budget_mb = %(max_bytes / 1024 / 1024),
            priority = ?priority,
            "Agent registered with custom GPU budget"
        );
    }

    /// ขอจัดสรร VRAM สำหรับ agent
    ///
    /// # Errors
    /// คืน `BudgetError::BudgetExceeded` ถ้าเกินวงเงิน
    /// คืน `BudgetError::SystemPressure` ถ้าระบบมีหน่วยความจำไม่พอ
    pub fn allocate(&self, agent_id: &str, size_bytes: usize) -> Result<(), BudgetError> {
        let mut budgets = self.budgets.write();
        let budget = budgets
            .get_mut(agent_id)
            .ok_or_else(|| BudgetError::AgentNotFound {
                agent: agent_id.to_string(),
            })?;

        if !budget.can_allocate(size_bytes) {
            warn!(
                agent = %agent_id,
                requested = %size_bytes,
                remaining = %budget.remaining(),
                max = %budget.max_bytes,
                "Agent VRAM budget exceeded"
            );
            return Err(BudgetError::BudgetExceeded {
                agent: agent_id.to_string(),
                requested: size_bytes,
                remaining: budget.remaining(),
            });
        }

        budget.used_bytes = budget.used_bytes.saturating_add(size_bytes);
        debug!(
            agent = %agent_id,
            allocated = %size_bytes,
            total_used = %budget.used_bytes,
            remaining = %budget.remaining(),
            "Agent VRAM allocation approved"
        );
        Ok(())
    }

    /// คืน VRAM ที่ agent ใช้อยู่
    pub fn deallocate(&self, agent_id: &str, size_bytes: usize) {
        let mut budgets = self.budgets.write();
        if let Some(budget) = budgets.get_mut(agent_id) {
            budget.used_bytes = budget.used_bytes.saturating_sub(size_bytes);
            debug!(
                agent = %agent_id,
                released = %size_bytes,
                total_used = %budget.used_bytes,
                "Agent VRAM deallocated"
            );
        }
    }

    /// ลบ agent ออกจากระบบ — คืน VRAM ทั้งหมด
    pub fn unregister_agent(&self, agent_id: &str) -> Option<AgentBudget> {
        let mut budgets = self.budgets.write();
        let budget = budgets.remove(agent_id);
        if budget.is_some() {
            info!(agent = %agent_id, "Agent unregistered, GPU budget released");
        }
        budget
    }

    /// Preempt agent ระดับความสำคัญต่ำกว่าเพื่อเพิ่มพื้นที่
    ///
    /// คืนรายชื่อ agent ที่ถูก preempt
    pub fn preempt_for(&self, requesting_agent: &str, needed_bytes: usize) -> Vec<String> {
        let budgets = self.budgets.read();
        let requesting_priority = budgets
            .get(requesting_agent)
            .map(|b| b.priority)
            .unwrap_or(AgentPriority::Normal);

        let mut preemptable: Vec<(String, usize, AgentPriority)> = budgets
            .iter()
            .filter(|(id, b)| {
                *id != requesting_agent && b.priority < requesting_priority && b.used_bytes > 0
            })
            .map(|(id, b)| (id.clone(), b.used_bytes, b.priority))
            .collect();

        // เรียงตาม priority ต่ำสุดก่อน (preempt คนที่สำคัญน้อยที่สุดก่อน)
        preemptable.sort_by_key(|(_, _, p)| *p);

        let mut freed = 0usize;
        let mut preempted = Vec::new();

        for (id, used, _) in &preemptable {
            if freed >= needed_bytes {
                break;
            }
            freed = freed.saturating_add(*used);
            preempted.push(id.clone());
        }

        if !preempted.is_empty() {
            info!(
                preempted = ?preempted,
                needed = %needed_bytes,
                freed = %freed,
                "GPU budget preemption triggered"
            );
        }

        preempted
    }

    /// ตรวจสอบว่ามี system memory pressure หรือไม่
    #[must_use]
    pub fn under_pressure(&self) -> bool {
        let budgets = self.budgets.read();
        let total_used: usize = budgets.values().map(|b| b.used_bytes).sum();
        // ถ้าใช้ VRAM เกิน 90% — ถือว่ามี pressure
        if self.system_capacity > 0 {
            total_used as f64 / self.system_capacity as f64 > 0.9
        } else {
            false
        }
    }

    /// ดึงข้อมูลงบประมาณของ agent
    #[must_use]
    pub fn get_budget(&self, agent_id: &str) -> Option<AgentBudget> {
        self.budgets.read().get(agent_id).copied()
    }

    /// จำนวน agent ที่ลงทะเบียน
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.budgets.read().len()
    }

    /// VRAM รวมที่ใช้ไปทั้งหมด
    #[must_use]
    pub fn total_used(&self) -> usize {
        let budgets = self.budgets.read();
        budgets.values().map(|b| b.used_bytes).sum()
    }

    /// รายชื่อ agent IDs ทั้งหมดที่ลงทะเบียน
    #[must_use]
    pub fn agent_ids(&self) -> Vec<String> {
        self.budgets.read().keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_register_and_allocate() {
        let ctl = GpuBudgetController::new(1000).with_default_budget(500);
        ctl.register_agent("agent-a", AgentPriority::Normal);
        assert!(ctl.allocate("agent-a", 300).is_ok());
        assert_eq!(ctl.get_budget("agent-a").unwrap().used_bytes, 300);
    }

    #[test]
    fn budget_exceeded_returns_error() {
        let ctl = GpuBudgetController::new(1000);
        ctl.register_agent_with_budget("agent-b", 500, AgentPriority::Normal);
        assert!(ctl.allocate("agent-b", 400).is_ok());
        // 400 + 200 > 500
        let err = ctl.allocate("agent-b", 200).unwrap_err();
        assert!(matches!(err, BudgetError::BudgetExceeded { .. }));
    }

    #[test]
    fn budget_agent_not_found() {
        let ctl = GpuBudgetController::new(1000);
        let err = ctl.allocate("ghost", 100).unwrap_err();
        assert!(matches!(err, BudgetError::AgentNotFound { .. }));
    }

    #[test]
    fn budget_deallocate_reduces_usage() {
        let ctl = GpuBudgetController::new(2000).with_default_budget(1000);
        ctl.register_agent("agent-c", AgentPriority::Normal);
        ctl.allocate("agent-c", 500).unwrap();
        ctl.deallocate("agent-c", 200);
        assert_eq!(ctl.get_budget("agent-c").unwrap().used_bytes, 300);
    }

    #[test]
    fn budget_unregister_removes_agent() {
        let ctl = GpuBudgetController::new(1000).with_default_budget(500);
        ctl.register_agent("agent-d", AgentPriority::Interactive);
        ctl.allocate("agent-d", 100).unwrap();
        let budget = ctl.unregister_agent("agent-d");
        assert!(budget.is_some());
        assert_eq!(ctl.agent_count(), 0);
    }

    #[test]
    fn budget_preempt_lower_priority() {
        let ctl = GpuBudgetController::new(1000);
        ctl.register_agent_with_budget("high", 500, AgentPriority::Interactive);
        ctl.register_agent_with_budget("low", 500, AgentPriority::Batch);
        ctl.allocate("low", 400).unwrap();
        assert_eq!(ctl.total_used(), 400);

        // high tries to preempt low
        let preempted = ctl.preempt_for("high", 300);
        assert_eq!(preempted.len(), 1);
        assert_eq!(preempted[0], "low");
    }

    #[test]
    fn budget_preempt_multiple_agents() {
        let ctl = GpuBudgetController::new(2000);
        ctl.register_agent_with_budget("high", 1000, AgentPriority::Interactive);
        ctl.register_agent_with_budget("low1", 500, AgentPriority::Batch);
        ctl.register_agent_with_budget("low2", 500, AgentPriority::Batch);
        ctl.allocate("low1", 500).unwrap();
        ctl.allocate("low2", 300).unwrap();

        let preempted = ctl.preempt_for("high", 600);
        assert_eq!(preempted.len(), 2); // needs both low1 + low2
    }

    #[test]
    fn budget_no_preempt_same_or_higher_priority() {
        let ctl = GpuBudgetController::new(1000);
        ctl.register_agent_with_budget("same", 500, AgentPriority::Normal);
        ctl.register_agent_with_budget("other", 500, AgentPriority::Normal);
        ctl.allocate("same", 300).unwrap();

        let preempted = ctl.preempt_for("other", 400);
        assert!(preempted.is_empty()); // same priority, no preemption
    }

    #[test]
    fn budget_under_pressure_detection() {
        let ctl = GpuBudgetController::new(1000);
        ctl.register_agent_with_budget("hog", 1000, AgentPriority::Batch);
        ctl.allocate("hog", 950).unwrap();
        assert!(ctl.under_pressure());
    }
}
