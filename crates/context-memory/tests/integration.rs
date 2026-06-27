use context_memory::{ContextError, ContextMemoryManager};

#[test]
fn eviction_preserves_data_in_warm() {
    let memory = ContextMemoryManager::with_capacity(3, 5);
    memory.put("keep", b"important".to_vec());
    memory.put("a", b"1".to_vec());
    memory.put("b", b"2".to_vec());

    assert_eq!(memory.tier_of("keep"), Some("hot"));

    memory.put("c", b"3".to_vec());
    assert_eq!(memory.tier_of("keep"), Some("warm"));
    assert!(memory.get("keep").is_ok(), "data should survive eviction");

    memory.put("d", b"4".to_vec());
    memory.put("e", b"5".to_vec());
    memory.put("f", b"6".to_vec());

    assert!(
        memory.get("keep").is_ok(),
        "keep should survive multiple evictions"
    );
    assert_eq!(memory.get("keep").unwrap(), b"important".to_vec());
}

#[test]
fn promote_warm_to_hot_round_trip() {
    let memory = ContextMemoryManager::with_capacity(1, 5);
    memory.put("key", b"promote-me".to_vec());
    assert_eq!(memory.tier_of("key"), Some("hot"));

    memory.put("other", b"bump".to_vec());
    assert_eq!(
        memory.tier_of("key"),
        Some("warm"),
        "key should be evicted to warm"
    );

    memory.promote("key").expect("promote should succeed");
    assert_eq!(
        memory.tier_of("key"),
        Some("hot"),
        "key should be promoted back to hot"
    );
    assert_eq!(memory.get("key").unwrap(), b"promote-me".to_vec());
}

#[test]
fn demote_hot_to_warm_round_trip() {
    let memory = ContextMemoryManager::new();
    memory.put("hot-data", b"will-be-demoted".to_vec());
    assert_eq!(memory.tier_of("hot-data"), Some("hot"));

    memory.demote("hot-data").expect("demote should succeed");
    assert_eq!(
        memory.tier_of("hot-data"),
        Some("warm"),
        "should be in warm after demote"
    );
    assert_eq!(
        memory.get("hot-data").unwrap(),
        b"will-be-demoted".to_vec(),
        "data intact after demote"
    );
}

#[test]
fn missing_key_propagates_correctly() {
    let memory = ContextMemoryManager::new();
    assert_eq!(memory.tier_of("ghost"), None);
    assert_eq!(memory.get("ghost"), Err(ContextError::NotFound));
    assert_eq!(memory.promote("ghost"), Err(ContextError::NotFound));
    assert_eq!(memory.demote("ghost"), Err(ContextError::NotFound));
}

#[test]
fn large_payload_eviction() {
    let memory = ContextMemoryManager::with_capacity(2, 2);
    let large = vec![0xABu8; 100_000];

    memory.put("large-1", large.clone());
    memory.put("large-2", large.clone());
    memory.put("large-3", large.clone());
    memory.put("large-4", large.clone());
    memory.put("large-5", large.clone());

    let val = memory.get("large-1").expect("should survive evictions");
    assert_eq!(val.len(), 100_000);
}
