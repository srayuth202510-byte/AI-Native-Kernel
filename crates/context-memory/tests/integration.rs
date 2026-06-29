#![allow(missing_docs)]
use context_memory::p2p_mesh::P2PMeshManager;
use context_memory::{ContextError, ContextMemoryManager};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

fn reserve_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

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

#[tokio::test]
async fn distributed_context_sync_and_fetch_round_trip() {
    let port_a = reserve_port();
    let port_b = reserve_port();
    let mesh_a = Arc::new(P2PMeshManager::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port_a,
    )));
    let mesh_b = Arc::new(P2PMeshManager::new(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        port_b,
    )));

    let listener_a = tokio::spawn(Arc::clone(&mesh_a).start_listener());
    let listener_b = tokio::spawn(Arc::clone(&mesh_b).start_listener());
    tokio::time::sleep(Duration::from_millis(100)).await;

    mesh_b
        .clone()
        .connect_to_peer(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port_a))
        .await
        .expect("peer connect should succeed");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let memory_a = Arc::new(ContextMemoryManager::new());
    let memory_b = Arc::new(ContextMemoryManager::new());
    memory_a.attach_mesh(Arc::clone(&mesh_a));
    memory_b.attach_mesh(Arc::clone(&mesh_b));

    memory_a
        .put_distributed("shared-ctx", b"mesh-value".to_vec())
        .await
        .expect("distributed put should succeed");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let fetched = memory_b
        .get_distributed("shared-ctx")
        .await
        .expect("remote fetch should succeed");
    assert_eq!(fetched, b"mesh-value".to_vec());
    assert_eq!(memory_b.get("shared-ctx").unwrap(), b"mesh-value".to_vec());

    listener_a.abort();
    listener_b.abort();
}
