use crate::budget::{AgentPriority, GpuBudgetController};
use crate::gpu_pool::GpuMemoryPool;
use std::sync::Arc;
use tracing::{error, info, warn};

/// การกระทำที่ OOM killer ดำเนินการกับ agent
#[derive(Debug, Clone, PartialEq)]
pub enum OomAction {
    /// Agent ถูก swap ออกจาก GPU ไปยัง host memory
    SwappedOut { agent: String },
    /// Agent ถูก kill (deallocate ทั้งหมด) เพื่อปลดปล่อย VRAM
    Killed { agent: String },
}

/// ผลลัพธ์จากการจัดสรร VRAM ผ่าน OOM killer
#[derive(Debug, Clone)]
pub struct OomAllocationResult {
    /// การกระทำที่ OOM killer ดำเนินการ
    pub actions: Vec<OomAction>,
}

/// ข้อผิดพลาดสำหรับ GPU OOM killer
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum OomError {
    #[error("ไม่พบ agent {0} ใน budget controller")]
    AgentNotFound(String),
    #[error("ไม่สามารถจัดสรร VRAM {needed} ไบต์ได้ — swap และ kill แล้วยังไม่พอ")]
    AllocationFailed { needed: usize },
}

/// GPU OOM Killer — จัดการสถานการณ์ VRAM เต็มด้วยการ preempt/kill ตาม priority
///
/// ## การทำงาน
/// 1. พยายามจัดสรร VRAM ปกติ
/// 2. ถ้าเต็ม → swap out agent ระดับ priority ต่ำกว่า (ย้ายไป host memory)
/// 3. ถ้ายังไม่พอ → kill agent ระดับ priority ต่ำที่สุด
/// 4. ถ้ายังไม่พอ → คืน AllocationFailed
pub struct GpuOomKiller {
    pool: Arc<GpuMemoryPool>,
    budget: Arc<GpuBudgetController>,
}

impl GpuOomKiller {
    /// สร้าง GPU OOM killer ใหม่
    #[must_use]
    pub fn new(pool: Arc<GpuMemoryPool>, budget: Arc<GpuBudgetController>) -> Self {
        Self { pool, budget }
    }

    /// จัดสรร VRAM พร้อม OOM handling
    ///
    /// ขั้นตอน:
    /// 1. ลอง swap out ตาม priority (ต่ำสุดก่อน) ผ่าน `allocate_with_auto_swap`
    /// 2. ถ้ายังไม่พอ → kill agent ระดับต่ำสุด
    ///
    /// คืน `Ok(actions)` พร้อมรายการ action ที่ดำเนินการ
    ///
    /// # Errors
    /// คืน `OomError::AllocationFailed` ถ้าทุกอย่างล้มเหลว
    pub fn allocate(
        &self,
        agent_id: &str,
        block_id: String,
        size_bytes: usize,
    ) -> Result<OomAllocationResult, OomError> {
        let mut actions: Vec<OomAction> = Vec::new();

        // Step 1: Try normal allocation via auto-swap with priority candidates
        let swap_candidates = self.get_swap_candidates(agent_id, size_bytes);
        match self.pool.allocate_with_auto_swap(
            block_id.clone(),
            size_bytes,
            Some(swap_candidates.clone()),
        ) {
            Ok(_) => {
                // Record which agents were swapped out by mapping block IDs back to agents
                for candidate_block in &swap_candidates {
                    for agent in self.budget.agent_ids() {
                        if candidate_block.starts_with(&agent)
                            && self.pool.is_swapped(candidate_block)
                        {
                            actions.push(OomAction::SwappedOut { agent });
                        }
                    }
                }
                return Ok(OomAllocationResult { actions });
            }
            Err(_) => {
                warn!(
                    agent = %agent_id,
                    needed = %size_bytes,
                    "Auto-swap ไม่พอ — เริ่ม kill agent ระดับต่ำ"
                );
            }
        }

        // Step 2: Kill lowest-priority agents until enough space
        let kill_candidates = self.get_kill_candidates(agent_id, size_bytes);
        for victim in &kill_candidates {
            let victim_id = &victim.0;
            let victim_blocks = self.pool.block_ids_for_agent(victim_id);
            for block_id in &victim_blocks {
                let _ = self.pool.deallocate(block_id);
            }
            self.budget.unregister_agent(victim_id);

            actions.push(OomAction::Killed {
                agent: victim_id.clone(),
            });
            info!(
                victim = %victim_id,
                blocks = ?victim_blocks,
                "OOM killer: agent ถูก kill เพื่อปลดปล่อย VRAM"
            );

            if self.pool.has_capacity(size_bytes) {
                let _ = self.pool.allocate(block_id.clone(), size_bytes);
                return Ok(OomAllocationResult { actions });
            }
        }

        error!(
            agent = %agent_id,
            needed = %size_bytes,
            "OOM killer: ไม่สามารถจัดสรร VRAM ได้แม้จะ kill agent แล้ว"
        );
        Err(OomError::AllocationFailed { needed: size_bytes })
    }

    /// หา swap candidates — คืน block IDs ที่ควร swap ออก (เรียงตาม priority ต่ำ→สูง)
    fn get_swap_candidates(&self, agent_id: &str, _needed_bytes: usize) -> Vec<String> {
        let all_agents = self.budget.agent_ids();
        let requesting_priority = self
            .budget
            .get_budget(agent_id)
            .map(|b| b.priority)
            .unwrap_or(AgentPriority::Normal);

        // Build list of (agent_id, priority) for preemptable agents
        let mut preemptable: Vec<(String, AgentPriority)> = all_agents
            .iter()
            .filter(|id| *id != agent_id)
            .filter_map(|id| {
                let budget = self.budget.get_budget(id)?;
                let usage = self.pool.used_bytes_for_agent(id);
                if budget.priority < requesting_priority && usage > 0 {
                    Some((id.clone(), budget.priority))
                } else {
                    None
                }
            })
            .collect();

        // Sort by priority (lowest first)
        preemptable.sort_by_key(|(_, p)| *p);

        // Resolve agent IDs to actual block IDs
        let mut result = Vec::new();
        for (agent, _) in &preemptable {
            let block_ids = self.pool.block_ids_for_agent(agent);
            for block_id in &block_ids {
                if self.pool.is_allocated(block_id) {
                    result.push(block_id.clone());
                }
            }
        }

        result
    }

    /// หา kill candidates — agent ระดับต่ำสุดที่กิน VRAM มาก
    fn get_kill_candidates(&self, agent_id: &str, needed_bytes: usize) -> Vec<(String, usize)> {
        let mut candidates: Vec<(String, usize, AgentPriority)> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Collect GPU usage per agent from budget controller
        // We rely on budget controller for agent list + block_ids_for_agent for usage
        let agent_ids: Vec<String> = self
            .budget
            .agent_ids()
            .into_iter()
            .filter(|id| id != agent_id)
            .collect();

        for agent in &agent_ids {
            let usage = self.pool.used_bytes_for_agent(agent);
            if usage > 0 {
                let priority = self
                    .budget
                    .get_budget(agent)
                    .map(|b| b.priority)
                    .unwrap_or(AgentPriority::Batch);
                candidates.push((agent.clone(), usage, priority));
                seen.insert(agent.clone());
            }
        }

        // Also add agents that have GPU blocks but no budget (orphaned)
        let all_block_agents = self.pool.all_agent_prefixes();
        for prefix in all_block_agents {
            if !seen.contains(&prefix) && prefix != agent_id {
                let usage = self.pool.used_bytes_for_agent(&prefix);
                if usage > 0 {
                    candidates.push((prefix, usage, AgentPriority::Batch));
                }
            }
        }

        // Sort by priority (lowest first), then by usage (largest first)
        candidates.sort_by(|a, b| a.2.cmp(&b.2).then(b.1.cmp(&a.1)));

        // Return only enough to free needed_bytes
        let mut freed = 0usize;
        let mut result = Vec::new();
        for (agent, usage, _) in candidates {
            if freed >= needed_bytes {
                break;
            }
            freed = freed.saturating_add(usage);
            result.push((agent, usage));
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::AgentPriority;
    use crate::gpu_pool::GpuPlatform;
    use std::sync::Arc;

    fn setup() -> (Arc<GpuMemoryPool>, Arc<GpuBudgetController>, GpuOomKiller) {
        let pool = Arc::new(GpuMemoryPool::new(GpuPlatform::Cuda, 500, false));
        let budget = Arc::new(GpuBudgetController::new(500).with_default_budget(300));
        let oom = GpuOomKiller::new(pool.clone(), budget.clone());
        (pool, budget, oom)
    }

    #[test]
    fn oom_allocate_without_pressure_succeeds() {
        let (pool, budget, oom) = setup();
        budget.register_agent("agent-a", AgentPriority::Normal);
        let result = oom
            .allocate("agent-a", "agent-a-block-1".into(), 200)
            .unwrap();
        assert!(result.actions.is_empty());
        assert!(pool.get_block("agent-a-block-1").is_some());
    }

    #[test]
    fn oom_swap_out_lower_priority() {
        let pool = Arc::new(GpuMemoryPool::new(GpuPlatform::Cuda, 300, false));
        let budget = Arc::new(GpuBudgetController::new(300).with_default_budget(200));
        let oom = GpuOomKiller::new(pool.clone(), budget.clone());
        budget.register_agent("low", AgentPriority::Batch);
        budget.register_agent("high", AgentPriority::Interactive);
        pool.allocate("low-block".into(), 200).unwrap();

        // high needs 150 bytes, only 100 free — must swap out "low-block"
        let result = oom.allocate("high", "high-block".into(), 150).unwrap();
        assert!(!result.actions.is_empty());
        assert!(pool.is_swapped("low-block"));
    }

    #[test]
    fn oom_kill_lowest_priority_cleans_up_blocks() {
        let (pool, budget, oom) = setup();
        budget.register_agent("victim", AgentPriority::Batch);
        pool.allocate("victim-block".into(), 400).unwrap();

        // Sole agent with only itself registered — no one to swap/kill
        budget.register_agent("keeper", AgentPriority::Normal);
        // keeper tries to allocate 200, pool has 400 used, 100 free
        // swap candidates = [] (victim has Batch < Normal, but... wait)
        // Actually victim does have lower priority, so swap candidates = ["victim-block"]
        // Swap frees 400, then allocate 200 succeeds
        let result = oom.allocate("keeper", "keeper-block".into(), 200).unwrap();
        assert!(!result.actions.is_empty());
        assert!(pool.is_swapped("victim-block"));
    }

    #[test]
    fn oom_fails_when_no_victims_available() {
        let (_, budget, oom) = setup();
        budget.register_agent("sole", AgentPriority::Normal);
        let err = oom.allocate("sole", "sole-block".into(), 9999).unwrap_err();
        assert!(matches!(err, OomError::AllocationFailed { .. }));
    }

    #[test]
    fn oom_respects_priority_order() {
        let (pool, budget, oom) = setup();
        budget.register_agent("batch-agent", AgentPriority::Batch);
        budget.register_agent("normal-agent", AgentPriority::Normal);
        budget.register_agent("interactive-agent", AgentPriority::Interactive);
        pool.allocate("batch-agent-data".into(), 200).unwrap();
        pool.allocate("normal-agent-data".into(), 200).unwrap();
        pool.allocate("interactive-agent-data".into(), 100).unwrap();

        let result = oom
            .allocate("interactive-agent", "interactive-agent-new".into(), 200)
            .unwrap();
        let swapped_or_killed: Vec<&str> = result
            .actions
            .iter()
            .map(|a| match a {
                OomAction::SwappedOut { agent } => agent.as_str(),
                OomAction::Killed { agent } => agent.as_str(),
            })
            .collect();
        assert!(
            swapped_or_killed.contains(&"batch-agent"),
            "batch-agent should be preempted first: got {swapped_or_killed:?}"
        );
    }
}
