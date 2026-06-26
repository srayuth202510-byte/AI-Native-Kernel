#![allow(unused_imports)]

use std::collections::BinaryHeap;
use priority::Priority;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    Eco,
    Batch,
    Interactive,
    RealTime,
}

impl Ord for Priority {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Priority::RealTime, Priority::RealTime) => std::cmp::Ordering::Equal,
            (Priority::RealTime, _) => std::cmp::Ordering::Greater,
            (_, Priority::RealTime) => std::cmp::Ordering::Less,
            (Priority::Interactive, Priority::Interactive) => std::cmp::Ordering::Equal,
            (Priority::Interactive, _) => std::cmp::Ordering::Greater,
            (_, Priority::Interactive) => std::cmp::Ordering::Less,
            (Priority::Eco, Priority::Eco) => std::cmp::Ordering::Equal,
            (Priority::Batch, Priority::Batch) => std::cmp::Ordering::Equal,
            (Priority::Eco, Priority::Batch) => std::cmp::Ordering::Greater,
            (Priority::Batch, Priority::Eco) => std::cmp::Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct PriorityQueue {
    heap: BinaryHeap<PriorityAgent>,
}

#[derive(Debug, Clone)]
struct PriorityAgent {
    id: u64,
    priority: Priority,
    agent_data: Box<dyn std::any::Any>,
}

impl PriorityAgent {
    fn new(id: u64, priority: Priority, agent_data: Box<dyn std::any::Any>) -> Self {
        Self { id, priority, agent_data }
    }
}

impl Ord for PriorityAgent {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for PriorityAgent {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for PriorityAgent {}

impl PartialEq for PriorityAgent {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PriorityQueue {
    pub fn new() -> Self {
        Self { heap: BinaryHeap::new() }
    }
    
    pub fn push(&mut self, agent: PriorityAgent) {
        self.heap.push(agent);
    }
    
    pub fn pop(&mut self) -> Option<PriorityAgent> {
        self.heap.pop()
    }
    
    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
    
    pub fn len(&self) -> usize {
        self.heap.len()
    }
}