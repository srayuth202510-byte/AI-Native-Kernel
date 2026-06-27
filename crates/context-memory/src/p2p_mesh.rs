use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: String,
    pub addr: SocketAddr,
    pub last_seen: std::time::Instant,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct P2PMessage {
    pub from: String,
    pub to: Option<String>,
    pub msg_type: MessageType,
    pub data: Vec<u8>,
    pub timestamp: std::time::Instant,
}

#[derive(Debug, Clone)]
pub enum MessageType {
    Ping,
    Pong,
    NeighborList,
    RecordSync,
    IdentityMap,
}

pub struct P2PMeshManager {
    pub local_node: NodeInfo,
    pub known_nodes: HashMap<String, NodeInfo>,
    pub discovery_interval: Duration,
    pub message_tx: mpsc::Sender<P2PMessage>,
    pub message_rx: Option<mpsc::Receiver<P2PMessage>>,
}

impl P2PMeshManager {
    pub fn new(addr: SocketAddr) -> Self {
        let node_id = Uuid::new_v4().to_string();
        let local_node = NodeInfo {
            id: node_id.clone(),
            addr,
            last_seen: std::time::Instant::now(),
            capabilities: vec!["semantic".to_string(), "filesystem".to_string()],
        };
        
        let (tx, rx) = mpsc::channel(1000);
        
        Self {
            local_node,
            known_nodes: HashMap::new(),
            discovery_interval: Duration::from_secs(30),
            message_tx: tx,
            message_rx: Some(rx),
        }
    }

    pub async fn start_discovery_loop(&mut self) {
        let tx = self.message_tx.clone();
        let interval = self.discovery_interval;
        
        tokio::spawn(async move {
            loop {
                sleep(interval).await;
                // Broadcast ping to known nodes
                let ping_msg = P2PMessage {
                    from: "discovery".to_string(),
                    to: None,
                    msg_type: MessageType::Ping,
                    data: Vec::new(),
                    timestamp: std::time::Instant::now(),
                };
                let _ = tx.send(ping_msg).await;
            }
        });
    }

    pub fn get_neighbor_list(&self) -> Vec<NodeInfo> {
        self.known_nodes.values().cloned().collect()
    }

    pub fn add_node(&mut self, node: NodeInfo) {
        self.known_nodes.insert(node.id.clone(), node);
    }

    pub fn remove_node(&mut self, node_id: &str) {
        self.known_nodes.remove(node_id);
    }

    pub fn is_connected(&self, node_id: &str) -> bool {
        if let Some(node) = self.known_nodes.get(node_id) {
            node.last_seen.elapsed() < Duration::from_secs(60)
        } else {
            false
        }
    }

    pub fn get_all_connected_nodes(&self) -> Vec<NodeInfo> {
        self.known_nodes
            .values()
            .filter(|node| node.last_seen.elapsed() < Duration::from_secs(60))
            .cloned()
            .collect()
    }
}