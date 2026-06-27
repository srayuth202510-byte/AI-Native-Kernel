use std::collections::BinaryHeap;

/// ระดับความสำคัญของ Agent ในการจัดสรรลำดับการประมวลผล (Priority Levels)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// ระดับประหยัดพลังงาน/ทรัพยากรสูงสุด (Eco) สำหรับงานเบื้องหลังที่ไม่เร่งรีบ
    Eco,
    /// ระดับการประมวลผลเป็นกลุ่ม (Batch) สำหรับงานประมวลผลข้อมูลทั่วไปที่ไม่ต้องการการตอบกลับทันที
    Batch,
    /// ระดับโต้ตอบทันที (Interactive) สำหรับงานที่ต้องตอบสนองหรือปฏิสัมพันธ์กับผู้ใช้
    Interactive,
    /// ระดับเวลาจริง (Real-Time) สำหรับงานสำคัญสูงสุดที่ต้องการความล่าช้าต่ำสุด (Low-latency)
    RealTime,
}

/// ตัวแทน Agent ที่มีเฉพาะ ID และลำดับความสำคัญ เพื่อใช้สำหรับการเปรียบเทียบในคิว
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityAgent {
    /// ID ของ Agent
    pub id: u64,
    /// ระดับความสำคัญของ Agent
    pub priority: Priority,
}

impl PriorityAgent {
    /// สร้างอินสแตนซ์ใหม่ของ PriorityAgent
    #[must_use]
    pub fn new(id: u64, priority: Priority) -> Self {
        Self { id, priority }
    }
}

// กำหนดเงื่อนไขการเรียงลำดับ (Ord): จัดลำดับตาม Priority ก่อนเป็นหลัก
// หาก Priority เท่ากัน จะเรียงลำดับตาม ID ของ Agent เป็นลำดับถัดไป เพื่อให้ได้ผลลัพธ์การจัดคิวที่สม่ำเสมอ
impl Ord for PriorityAgent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for PriorityAgent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// คิวลำดับความสำคัญ (Priority Queue) ที่ใช้โครงสร้าง Binary Heap ในการจัดคิวของ Agent
#[derive(Default)]
pub struct PriorityQueue {
    /// โครงสร้าง Binary Heap ของ PriorityAgent ที่เรียงลำดับสูงสุดไว้บนสุด
    heap: BinaryHeap<PriorityAgent>,
}

impl PriorityQueue {
    /// สร้างคิวลำดับความสำคัญเปล่าชุดใหม่
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// เพิ่ม Agent เข้าสู่คิวลำดับความสำคัญ
    pub fn push(&mut self, agent: PriorityAgent) {
        self.heap.push(agent);
    }

    /// ดึง Agent ที่มีความสำคัญสูงสุดออกจากคิว
    pub fn pop(&mut self) -> Option<PriorityAgent> {
        self.heap.pop()
    }

    /// ตรวจสอบว่ามีคิวที่ยังค้างการประมวลผลอยู่หรือไม่
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// ตรวจสอบจำนวน Agent ทั้งหมดที่ค้างอยู่ในคิว
    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_agent_creation() {
        let agent = PriorityAgent::new(42, Priority::Interactive);
        assert_eq!(agent.id, 42);
        assert_eq!(agent.priority, Priority::Interactive);
    }

    #[test]
    fn test_priority_ordering() {
        let agents = vec![
            PriorityAgent::new(1, Priority::Eco),
            PriorityAgent::new(2, Priority::Batch),
            PriorityAgent::new(3, Priority::Interactive),
            PriorityAgent::new(4, Priority::RealTime),
        ];

        let mut heap = BinaryHeap::new();
        for agent in agents {
            heap.push(agent);
        }

        assert_eq!(heap.pop().unwrap().priority, Priority::RealTime);
        assert_eq!(heap.pop().unwrap().priority, Priority::Interactive);
        assert_eq!(heap.pop().unwrap().priority, Priority::Batch);
        assert_eq!(heap.pop().unwrap().priority, Priority::Eco);
    }

    #[test]
    fn test_priority_agent_with_same_priority() {
        let agent1 = PriorityAgent::new(5, Priority::Batch);
        let agent2 = PriorityAgent::new(3, Priority::Batch);

        let mut heap = BinaryHeap::new();
        heap.push(agent1);
        heap.push(agent2);

        assert_eq!(heap.pop().unwrap().id, 5);
        assert_eq!(heap.pop().unwrap().id, 3);
    }

    #[test]
    fn test_priority_queue_basic_operations() {
        let mut queue = PriorityQueue::new();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.push(PriorityAgent::new(1, Priority::Batch));
        queue.push(PriorityAgent::new(2, Priority::Eco));
        queue.push(PriorityAgent::new(3, Priority::Interactive));

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 3);

        let popped = queue.pop().unwrap();
        assert_eq!(popped.priority, Priority::Interactive);
        assert_eq!(popped.id, 3);

        assert_eq!(queue.len(), 2);
        assert!(queue.pop().unwrap().priority == Priority::Batch);
        assert!(queue.pop().unwrap().priority == Priority::Eco);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_priority_enum_derived_traits() {
        let priorities = [
            Priority::Eco,
            Priority::Batch,
            Priority::Interactive,
            Priority::RealTime,
        ];

        for (i, p1) in priorities.iter().enumerate() {
            for (j, p2) in priorities.iter().enumerate() {
                let cmp = p1.cmp(p2);
                let partial_cmp = p1.partial_cmp(p2);
                assert_eq!(Some(cmp), partial_cmp);

                if i <= j {
                    assert!(p1 <= p2);
                }
                if i >= j {
                    assert!(p1 >= p2);
                }
                assert_eq!(p1 == p2, i == j);
                assert_eq!(p1 != p2, i != j);
            }
        }
    }

    #[test]
    fn test_priority_enum_hash() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        map.insert(Priority::Eco, "eco");
        map.insert(Priority::Batch, "batch");
        map.insert(Priority::Interactive, "interactive");
        map.insert(Priority::RealTime, "realtime");

        assert_eq!(map[&Priority::Eco], "eco");
        assert_eq!(map[&Priority::Batch], "batch");
        assert_eq!(map[&Priority::Interactive], "interactive");
        assert_eq!(map[&Priority::RealTime], "realtime");
    }

    #[test]
    fn test_priority_queue_clear() {
        let mut queue = PriorityQueue::new();
        queue.push(PriorityAgent::new(1, Priority::Batch));
        queue.push(PriorityAgent::new(2, Priority::Eco));

        assert_eq!(queue.len(), 2);

        queue = PriorityQueue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_priority_agent_debug() {
        let agent = PriorityAgent::new(42, Priority::Interactive);
        let debug_str = format!("{:?}", agent);
        assert!(debug_str.contains("PriorityAgent"));
        assert!(debug_str.contains("id: 42"));
        assert!(debug_str.contains("Interactive"));
    }
}
