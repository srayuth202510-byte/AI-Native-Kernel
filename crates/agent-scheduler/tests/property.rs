//! Property-based tests สำหรับ invariants ของ Priority Queue
//!
//! Invariants หลัก:
//! 1. ลำดับการ pop ต้องไม่เพิ่มขึ้น (non-increasing) ตาม (Priority, id)
//! 2. จำนวนสมาชิก: push n ครั้ง แล้ว pop ได้ครบ n ตัวพอดี
//! 3. ตัวแรกที่ pop ต้องเป็นตัวที่มากที่สุดในบรรดาที่ push เข้าไป

use agent_scheduler::priority::{Priority, PriorityAgent, PriorityQueue};
use proptest::prelude::*;

fn priority_strategy() -> impl Strategy<Value = Priority> {
    prop_oneof![
        Just(Priority::Eco),
        Just(Priority::Batch),
        Just(Priority::Interactive),
        Just(Priority::RealTime),
    ]
}

fn agent_strategy() -> impl Strategy<Value = PriorityAgent> {
    (any::<u64>(), priority_strategy()).prop_map(|(id, priority)| PriorityAgent::new(id, priority))
}

proptest! {
    /// Invariant 1 + 2: pop ได้ครบทุกตัวและเรียงจากมากไปน้อยตาม (Priority, id) เสมอ
    #[test]
    fn pop_order_is_non_increasing(agents in prop::collection::vec(agent_strategy(), 0..64)) {
        let mut queue = PriorityQueue::new();
        for agent in &agents {
            queue.push(agent.clone());
        }
        prop_assert_eq!(queue.len(), agents.len());

        let mut popped = Vec::with_capacity(agents.len());
        while let Some(agent) = queue.pop() {
            popped.push(agent);
        }

        prop_assert_eq!(popped.len(), agents.len());
        prop_assert!(queue.is_empty());

        for pair in popped.windows(2) {
            // ตัวก่อนหน้าต้อง >= ตัวถัดไปเสมอ (BinaryHeap เป็น max-heap)
            prop_assert!(pair[0] >= pair[1]);
        }
    }

    /// Invariant 3: ตัวแรกที่ pop คือตัวที่มากที่สุดของทั้งชุด
    #[test]
    fn first_pop_is_maximum(agents in prop::collection::vec(agent_strategy(), 1..64)) {
        let mut queue = PriorityQueue::new();
        for agent in &agents {
            queue.push(agent.clone());
        }

        let first = queue.pop().expect("queue is non-empty");
        for agent in &agents {
            prop_assert!(first >= *agent);
        }
    }

    /// Priority ordering ต้องคงลำดับ Eco < Batch < Interactive < RealTime
    #[test]
    fn realtime_always_preempts_lower_priorities(
        id_rt in any::<u64>(),
        others in prop::collection::vec(
            (any::<u64>(), prop_oneof![
                Just(Priority::Eco),
                Just(Priority::Batch),
                Just(Priority::Interactive),
            ]),
            0..32,
        ),
    ) {
        let mut queue = PriorityQueue::new();
        for (id, priority) in &others {
            queue.push(PriorityAgent::new(*id, *priority));
        }
        queue.push(PriorityAgent::new(id_rt, Priority::RealTime));

        let first = queue.pop().expect("queue is non-empty");
        prop_assert_eq!(first.priority, Priority::RealTime);
    }
}
