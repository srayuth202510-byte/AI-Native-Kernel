use std::collections::{HashMap, VecDeque};

#[derive(Debug, Default)]
pub struct HotStore {
    entries: HashMap<String, Vec<u8>>,
    order: VecDeque<String>,
}

impl HotStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: String, value: Vec<u8>) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, value);
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn evict_oldest(&mut self) -> Option<(String, Vec<u8>)> {
        let key = self.order.pop_front()?;
        self.entries.remove(&key).map(|value| (key, value))
    }
}
