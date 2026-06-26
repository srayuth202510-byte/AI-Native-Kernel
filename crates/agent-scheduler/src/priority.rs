use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    Eco,
    Batch,
    Interactive,
    RealTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityAgent {
    pub id: u64,
    pub priority: Priority,
}

impl PriorityAgent {
    #[must_use]
    pub fn new(id: u64, priority: Priority) -> Self {
        Self { id, priority }
    }
}

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

#[derive(Default)]
pub struct PriorityQueue {
    heap: BinaryHeap<PriorityAgent>,
}

impl PriorityQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, agent: PriorityAgent) {
        self.heap.push(agent);
    }

    pub fn pop(&mut self) -> Option<PriorityAgent> {
        self.heap.pop()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.heap.len()
    }
}
