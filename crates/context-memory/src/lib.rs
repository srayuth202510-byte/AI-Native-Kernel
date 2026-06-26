#![deny(unsafe_code)]

pub mod cold;
pub mod hot;
pub mod warm;

use crate::cold::ColdStore;
use crate::hot::HotStore;
use crate::warm::WarmStore;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContextError {
    #[error("context page not found")]
    NotFound,
}

pub type Result<T> = core::result::Result<T, ContextError>;

pub struct ContextMemoryManager {
    hot: Arc<std::sync::RwLock<HotStore>>,
    warm: Arc<std::sync::RwLock<WarmStore>>,
    cold: Arc<std::sync::RwLock<ColdStore>>,
    hot_capacity: usize,
    warm_capacity: usize,
}

impl ContextMemoryManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hot: Arc::new(std::sync::RwLock::new(HotStore::new())),
            warm: Arc::new(std::sync::RwLock::new(WarmStore::new())),
            cold: Arc::new(std::sync::RwLock::new(ColdStore::new())),
            hot_capacity: 256,
            warm_capacity: 1_024,
        }
    }

    pub fn put(&self, key: impl Into<String>, value: Vec<u8>) {
        let key = key.into();
        let mut hot = self.hot.write().expect("hot memory lock poisoned");
        hot.insert(key, value);

        if hot.len() > self.hot_capacity {
            let evicted = hot.evict_oldest();
            drop(hot);

            if let Some((evicted_key, evicted_value)) = evicted {
                let mut warm = self.warm.write().expect("warm memory lock poisoned");
                warm.insert(evicted_key.clone(), evicted_value);

                if warm.len() > self.warm_capacity {
                    let spilled = warm.evict_oldest();
                    drop(warm);

                    if let Some((spilled_key, spilled_value)) = spilled {
                        self.cold
                            .write()
                            .expect("cold memory lock poisoned")
                            .insert(spilled_key, spilled_value);
                    }
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        if let Some(value) = self.hot.read().expect("hot memory lock poisoned").get(key) {
            return Ok(value);
        }

        if let Some(value) = self
            .warm
            .read()
            .expect("warm memory lock poisoned")
            .get(key)
        {
            return Ok(value);
        }

        if let Some(value) = self
            .cold
            .read()
            .expect("cold memory lock poisoned")
            .get(key)
        {
            return Ok(value);
        }

        Err(ContextError::NotFound)
    }
}

impl Default for ContextMemoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get_round_trip() {
        let memory = ContextMemoryManager::new();
        memory.put("ctx-1", b"hello".to_vec());

        let value = memory.get("ctx-1").expect("context should exist");
        assert_eq!(value, b"hello".to_vec());
    }
}
