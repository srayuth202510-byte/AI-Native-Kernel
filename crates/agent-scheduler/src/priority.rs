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
