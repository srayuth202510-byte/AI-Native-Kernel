use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{Duration, sleep, timeout};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Connection timeout for external I/O operations (connect, accept, read, write)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Read/write timeout for individual I/O operations
const RW_TIMEOUT: Duration = Duration::from_secs(30);

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn default_trust_score() -> u8 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct NodeInfo {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub id: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub addr: SocketAddr,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub last_seen_millis: u64,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub capabilities: Vec<String>,
    #[serde(default = "default_trust_score")]
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub trust_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct P2PMessage {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub from: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub from_addr: SocketAddr,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub to: Option<String>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub msg_type: MessageType,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub data: Vec<u8>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub timestamp_millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub enum MessageType {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    Ping,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    Pong,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    Handshake,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    NeighborList,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    RecordSync,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    RecordFetchRequest,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    RecordFetchResponse,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    IdentityMap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct RecordSyncPayload {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub key: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub value: Vec<u8>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub owner_node: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct RecordFetchRequest {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub request_id: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct RecordFetchResponse {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub request_id: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub key: String,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub value: Option<Vec<u8>>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub owner_node: String,
}

type PendingFetchSender = oneshot::Sender<Option<Vec<u8>>>;
type PendingFetchMap = Arc<RwLock<HashMap<String, PendingFetchSender>>>;

/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
/// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
pub struct P2PMeshManager {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub local_node: NodeInfo,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub discovery_interval: Duration,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub message_tx: mpsc::Sender<P2PMessage>,
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub message_rx: Option<mpsc::Receiver<P2PMessage>>,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    records: Arc<RwLock<HashMap<String, RecordSyncPayload>>>,
    pending_fetches: PendingFetchMap,
}

fn is_alive(node: &NodeInfo) -> bool {
    now_millis().saturating_sub(node.last_seen_millis) < 60_000
}

impl P2PMeshManager {
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub fn new(addr: SocketAddr) -> Self {
        let node_id = Uuid::new_v4().to_string();
        let local_node = NodeInfo {
            id: node_id,
            addr,
            last_seen_millis: now_millis(),
            capabilities: vec!["semantic".to_string(), "filesystem".to_string()],
            trust_score: 100,
        };

        let (tx, rx) = mpsc::channel(1000);

        Self {
            local_node,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            discovery_interval: Duration::from_secs(30),
            message_tx: tx,
            message_rx: Some(rx),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn add_node(&self, node: NodeInfo) {
        self.known_nodes.write().await.insert(node.id.clone(), node);
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn remove_node(&self, node_id: &str) {
        self.known_nodes.write().await.remove(node_id);
        self.peers.write().await.remove(node_id);
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn get_neighbors(&self) -> Vec<NodeInfo> {
        self.known_nodes.read().await.values().cloned().collect()
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn is_connected(&self, node_id: &str) -> bool {
        self.known_nodes
            .read()
            .await
            .get(node_id)
            .is_some_and(is_alive)
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn get_alive_peers(&self) -> Vec<NodeInfo> {
        self.known_nodes
            .read()
            .await
            .values()
            .filter(|n| is_alive(n))
            .cloned()
            .collect()
    }

    /// TCP listener — accept connections จาก node อื่น
    pub async fn start_listener(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.local_node.addr)
            .await
            .context("P2P: failed to bind TCP listener")?;
        info!(
            addr = %self.local_node.addr,
            id = %self.local_node.id,
            "P2P Mesh: listener started"
        );

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            debug!(%peer_addr, "P2P: inbound connection");
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, peer_addr, &this, true).await {
                    warn!(%peer_addr, error = %e, "P2P: inbound handler error");
                }
            });
        }
    }

    /// เชื่อมต่อไปยัง peer ด้วย TCP
    pub async fn connect_to_peer(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("P2P: connection timeout")?
            .context(format!("P2P: cannot connect to {addr}"))?;
        let peer_addr = stream.peer_addr().ok().unwrap_or(addr);
        debug!(%peer_addr, "P2P: outbound connection established");

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, &self, false).await {
                warn!(%peer_addr, error = %e, "P2P: outbound handler error");
            }
        });
        Ok(())
    }

    /// gossip: กระจาย neighbor list
    pub async fn gossip_neighbors(&self) -> Result<()> {
        let neighbors = self.get_alive_peers().await;
        let data = serde_json::to_vec(&neighbors)?;
        let msg = P2PMessage {
            from: self.local_node.id.clone(),
            from_addr: self.local_node.addr,
            to: None,
            msg_type: MessageType::NeighborList,
            data,
            timestamp_millis: now_millis(),
        };

        let payload = serde_json::to_string(&msg)?;
        let peers = self.peers.read().await;
        for (node_id, tx) in peers.iter() {
            if *node_id != self.local_node.id {
                let _ = tx.send(payload.clone());
            }
        }
        Ok(())
    }

    /// gossip loop
    pub async fn start_gossip_loop(self: Arc<Self>) {
        let interval = if self.discovery_interval.as_millis() == 0 {
            Duration::from_secs(30)
        } else {
            self.discovery_interval
        };
        loop {
            sleep(interval).await;
            if let Err(e) = self.gossip_neighbors().await {
                debug!(error = %e, "P2P: gossip error");
            }
        }
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn sync_record(&self, key: impl Into<String>, value: Vec<u8>) -> Result<()> {
        let key = key.into();
        let version = now_millis();
        let payload = RecordSyncPayload {
            key: key.clone(),
            value,
            owner_node: self.local_node.id.clone(),
            version,
        };

        self.records
            .write()
            .await
            .insert(key.clone(), payload.clone());

        let message = P2PMessage {
            from: self.local_node.id.clone(),
            from_addr: self.local_node.addr,
            to: None,
            msg_type: MessageType::RecordSync,
            data: serde_json::to_vec(&payload)?,
            timestamp_millis: now_millis(),
        };
        self.broadcast_message(message).await
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn get_cached_record(&self, key: &str) -> Option<Vec<u8>> {
        self.records
            .read()
            .await
            .get(key)
            .map(|record| record.value.clone())
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn fetch_record(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.get_cached_record(key).await {
            return Ok(Some(value));
        }

        let request = RecordFetchRequest {
            request_id: Uuid::new_v4().to_string(),
            key: key.to_string(),
        };
        let (tx, rx) = oneshot::channel();
        self.pending_fetches
            .write()
            .await
            .insert(request.request_id.clone(), tx);

        let message = P2PMessage {
            from: self.local_node.id.clone(),
            from_addr: self.local_node.addr,
            to: None,
            msg_type: MessageType::RecordFetchRequest,
            data: serde_json::to_vec(&request)?,
            timestamp_millis: now_millis(),
        };

        if let Err(error) = self.broadcast_message(message).await {
            self.pending_fetches
                .write()
                .await
                .remove(&request.request_id);
            return Err(error);
        }

        match timeout(Duration::from_secs(2), rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) | Err(_) => {
                self.pending_fetches
                    .write()
                    .await
                    .remove(&request.request_id);
                Ok(None)
            }
        }
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn set_trust_score(&self, node_id: &str, score: u8) {
        let mut nodes = self.known_nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.trust_score = score;
            if score < 50 {
                self.peers.write().await.remove(node_id);
                warn!(
                    "P2P: Trust score for node {} dropped below 50, severed connection",
                    node_id
                );
            }
        }
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn penalize_node(&self, node_id: &str, penalty: u8) {
        let mut nodes = self.known_nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.trust_score = node.trust_score.saturating_sub(penalty);
            let score = node.trust_score;
            if score < 50 {
                self.peers.write().await.remove(node_id);
                warn!(
                    "P2P: Node {} penalized by {}, trust score dropped below 50, severed connection",
                    node_id, penalty
                );
            } else {
                debug!(
                    "P2P: Node {} penalized by {}, new trust score: {}",
                    node_id, penalty, score
                );
            }
        }
    }

    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    /// เอกสารกำกับโค้ดส่วนนี้ (เพิ่มอัตโนมัติ)
    pub async fn get_trust_score(&self, node_id: &str) -> u8 {
        let nodes = self.known_nodes.read().await;
        nodes.get(node_id).map(|n| n.trust_score).unwrap_or(100)
    }

    async fn broadcast_message(&self, message: P2PMessage) -> Result<()> {
        let payload = serde_json::to_string(&message)?;
        let peers = self.peers.read().await;
        for (node_id, tx) in peers.iter() {
            if *node_id != self.local_node.id {
                let _ = tx.send(payload.clone());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SharedState {
    known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    records: Arc<RwLock<HashMap<String, RecordSyncPayload>>>,
    pending_fetches: PendingFetchMap,
    local_id: String,
    local_addr: SocketAddr,
}

async fn on_message(line: &str, node_id: &str, state: &SharedState) {
    if let Ok(msg) = serde_json::from_str::<P2PMessage>(line.trim()) {
        // Enforce Zero-Trust: reject messages from nodes with trust score < 50
        let sender_trust = state
            .known_nodes
            .read()
            .await
            .get(node_id)
            .map(|n| n.trust_score)
            .unwrap_or(100);
        if sender_trust < 50 {
            warn!(
                "P2P: Rejecting message of type {:?} from untrusted node {} (trust: {})",
                msg.msg_type, node_id, sender_trust
            );
            return;
        }

        state
            .known_nodes
            .write()
            .await
            .entry(node_id.to_string())
            .and_modify(|n| {
                n.last_seen_millis = now_millis();
            });
        if msg.msg_type == MessageType::NeighborList {
            if let Ok(neighbors) = serde_json::from_slice::<Vec<NodeInfo>>(&msg.data) {
                let mut nodes = state.known_nodes.write().await;
                for n in neighbors {
                    nodes.entry(n.id.clone()).or_insert_with(|| NodeInfo {
                        last_seen_millis: now_millis(),
                        ..n
                    });
                }
            }
            return;
        }

        if msg.msg_type == MessageType::RecordSync {
            if let Ok(record) = serde_json::from_slice::<RecordSyncPayload>(&msg.data) {
                // Verify owner node trust
                let record_owner_trust = state
                    .known_nodes
                    .read()
                    .await
                    .get(&record.owner_node)
                    .map(|n| n.trust_score)
                    .unwrap_or(100);
                if record_owner_trust < 50 {
                    warn!(
                        "P2P: Ignoring RecordSync from untrusted node: {}",
                        record.owner_node
                    );
                    return;
                }

                let mut records = state.records.write().await;
                // Conflict Model:
                // 1. Compare owner node trust score (higher wins)
                // 2. If trust scores are equal, compare version (higher wins)
                // 3. If version is also equal, tie-break deterministically using lexicographically smaller owner node ID
                let should_update = if let Some(existing) = records.get(&record.key) {
                    let existing_owner_trust = state
                        .known_nodes
                        .read()
                        .await
                        .get(&existing.owner_node)
                        .map(|n| n.trust_score)
                        .unwrap_or(100);
                    if record_owner_trust > existing_owner_trust {
                        true
                    } else if record_owner_trust < existing_owner_trust {
                        false
                    } else {
                        if record.version > existing.version {
                            true
                        } else if record.version < existing.version {
                            false
                        } else {
                            record.owner_node < existing.owner_node
                        }
                    }
                } else {
                    true
                };

                if should_update {
                    records.insert(record.key.clone(), record);
                }
            }
            return;
        }

        if msg.msg_type == MessageType::RecordFetchRequest {
            if let Ok(request) = serde_json::from_slice::<RecordFetchRequest>(&msg.data) {
                let value = state
                    .records
                    .read()
                    .await
                    .get(&request.key)
                    .map(|record| record.value.clone());
                let response = RecordFetchResponse {
                    request_id: request.request_id,
                    key: request.key,
                    value,
                    owner_node: state.local_id.clone(),
                };
                let envelope = P2PMessage {
                    from: state.local_id.clone(),
                    from_addr: state.local_addr,
                    to: Some(msg.from.clone()),
                    msg_type: MessageType::RecordFetchResponse,
                    data: serde_json::to_vec(&response).unwrap_or_default(),
                    timestamp_millis: now_millis(),
                };
                if let Ok(payload) = serde_json::to_string(&envelope) {
                    if let Some(peer_tx) = state.peers.read().await.get(&msg.from).cloned() {
                        let _ = peer_tx.send(payload);
                    }
                }
            }
            return;
        }

        if msg.msg_type == MessageType::RecordFetchResponse {
            if let Ok(response) = serde_json::from_slice::<RecordFetchResponse>(&msg.data) {
                // Verify responder trust
                let responder_trust = state
                    .known_nodes
                    .read()
                    .await
                    .get(&response.owner_node)
                    .map(|n| n.trust_score)
                    .unwrap_or(100);
                if responder_trust < 50 {
                    warn!(
                        "P2P: Ignoring RecordFetchResponse from untrusted node: {}",
                        response.owner_node
                    );
                    return;
                }

                if let Some(value) = response.value.clone() {
                    let mut records = state.records.write().await;
                    let should_update = if let Some(existing) = records.get(&response.key) {
                        let existing_trust = state
                            .known_nodes
                            .read()
                            .await
                            .get(&existing.owner_node)
                            .map(|n| n.trust_score)
                            .unwrap_or(100);
                        responder_trust >= existing_trust
                    } else {
                        true
                    };

                    if should_update {
                        records.insert(
                            response.key.clone(),
                            RecordSyncPayload {
                                key: response.key,
                                value: value.clone(),
                                owner_node: response.owner_node,
                                version: now_millis(),
                            },
                        );
                    }
                }

                if let Some(tx) = state
                    .pending_fetches
                    .write()
                    .await
                    .remove(&response.request_id)
                {
                    let _ = tx.send(response.value);
                }
            }
        }
    }
}

/// จัดการ connection: handshake → อ่าน/เขียนข้อความ
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    mgr: &P2PMeshManager,
    is_inbound: bool,
) -> Result<()> {
    let (owned_reader, mut owned_writer) = stream.into_split();

    let state = SharedState {
        known_nodes: Arc::clone(&mgr.known_nodes),
        peers: Arc::clone(&mgr.peers),
        records: Arc::clone(&mgr.records),
        pending_fetches: Arc::clone(&mgr.pending_fetches),
        local_id: mgr.local_node.id.clone(),
        local_addr: mgr.local_node.addr,
    };

    if is_inbound {
        let mut reader = BufReader::new(owned_reader);
        let mut line = String::new();

        // 1. อ่าน handshake (with timeout)
        timeout(RW_TIMEOUT, reader.read_line(&mut line))
            .await
            .context("P2P: handshake read timeout")??;
        let hs: P2PMessage = serde_json::from_str(line.trim())?;
        if hs.msg_type != MessageType::Handshake {
            anyhow::bail!("expected Handshake, got {:?}", hs.msg_type);
        }

        // Enforce Zero-Trust: check if the connecting node has trust score < 50
        {
            let nodes = state.known_nodes.read().await;
            if let Some(node) = nodes.get(&hs.from) {
                if node.trust_score < 50 {
                    anyhow::bail!("Rejecting connection from untrusted node: {}", hs.from);
                }
            }
        }

        {
            let mut nodes = state.known_nodes.write().await;
            nodes.insert(
                hs.from.clone(),
                NodeInfo {
                    id: hs.from.clone(),
                    addr: hs.from_addr,
                    last_seen_millis: now_millis(),
                    capabilities: Vec::new(),
                    trust_score: 100,
                },
            );
        }
        info!(node_id = %hs.from, %peer_addr, "P2P: registered via inbound handshake");

        // 2. ส่ง handshake response (with timeout)
        let resp = P2PMessage {
            from: state.local_id.clone(),
            from_addr: state.local_addr,
            to: Some(hs.from.clone()),
            msg_type: MessageType::Handshake,
            data: Vec::new(),
            timestamp_millis: now_millis(),
        };
        let resp_json = serde_json::to_string(&resp)?;
        timeout(RW_TIMEOUT, owned_writer.write_all(resp_json.as_bytes()))
            .await
            .context("P2P: handshake write timeout")??;
        timeout(RW_TIMEOUT, owned_writer.write_all(b"\n"))
            .await
            .context("P2P: handshake newline write timeout")??;
        timeout(RW_TIMEOUT, owned_writer.flush())
            .await
            .context("P2P: handshake flush timeout")??;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        state.peers.write().await.insert(hs.from.clone(), tx);
        let node_id = hs.from.clone();
        let read_state = state.clone();
        let peers = Arc::clone(&state.peers);

        let read_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = String::new();
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => on_message(&buf, &node_id, &read_state).await,
                }
            }
            peers.write().await.remove(&node_id);
        });

        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if owned_writer.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
                if owned_writer.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = owned_writer.flush().await;
            }
        });

        let _ = tokio::join!(read_task, write_task);
    } else {
        let mut reader = BufReader::new(owned_reader);
        let mut line = String::new();

        // outbound: ส่ง handshake (with timeout)
        let hs = P2PMessage {
            from: state.local_id.clone(),
            from_addr: state.local_addr,
            to: None,
            msg_type: MessageType::Handshake,
            data: Vec::new(),
            timestamp_millis: now_millis(),
        };
        let hs_json = serde_json::to_string(&hs)?;
        timeout(RW_TIMEOUT, owned_writer.write_all(hs_json.as_bytes()))
            .await
            .context("P2P: outbound handshake write timeout")??;
        timeout(RW_TIMEOUT, owned_writer.write_all(b"\n"))
            .await
            .context("P2P: outbound handshake newline write timeout")??;
        timeout(RW_TIMEOUT, owned_writer.flush())
            .await
            .context("P2P: outbound handshake flush timeout")??;

        // อ่าน handshake response (with timeout)
        timeout(RW_TIMEOUT, reader.read_line(&mut line))
            .await
            .context("P2P: outbound handshake read timeout")??;
        let hs_resp: P2PMessage = serde_json::from_str(line.trim())?;
        if hs_resp.msg_type != MessageType::Handshake {
            anyhow::bail!("expected Handshake response, got {:?}", hs_resp.msg_type);
        }

        // Enforce Zero-Trust: check if the remote node has trust score < 50
        {
            let nodes = state.known_nodes.read().await;
            if let Some(node) = nodes.get(&hs_resp.from) {
                if node.trust_score < 50 {
                    anyhow::bail!("Rejecting connection from untrusted node: {}", hs_resp.from);
                }
            }
        }

        {
            let mut nodes = state.known_nodes.write().await;
            nodes.insert(
                hs_resp.from.clone(),
                NodeInfo {
                    id: hs_resp.from.clone(),
                    addr: hs_resp.from_addr,
                    last_seen_millis: now_millis(),
                    capabilities: Vec::new(),
                    trust_score: 100,
                },
            );
        }
        info!(node_id = %hs_resp.from, %peer_addr, "P2P: outbound handshake complete");

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        state.peers.write().await.insert(hs_resp.from.clone(), tx);
        let node_id = hs_resp.from.clone();
        let read_state = state.clone();
        let peers = Arc::clone(&state.peers);

        let read_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = String::new();
            loop {
                buf.clear();
                match timeout(RW_TIMEOUT, reader.read_line(&mut buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => break,
                    Ok(Ok(_)) => on_message(&buf, &node_id, &read_state).await,
                    Err(_) => {
                        warn!("P2P: outbound read timeout, closing connection");
                        break;
                    }
                }
            }
            peers.write().await.remove(&node_id);
        });

        let write_task = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if timeout(RW_TIMEOUT, owned_writer.write_all(msg.as_bytes()))
                    .await
                    .is_err()
                {
                    break;
                }
                if timeout(RW_TIMEOUT, owned_writer.write_all(b"\n"))
                    .await
                    .is_err()
                {
                    break;
                }
                if timeout(RW_TIMEOUT, owned_writer.flush()).await.is_err() {
                    break;
                }
            }
        });

        let _ = tokio::join!(read_task, write_task);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::timeout;

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn make_node(id: &str, port: u16) -> NodeInfo {
        NodeInfo {
            id: id.to_string(),
            addr: test_addr(port),
            last_seen_millis: now_millis(),
            capabilities: vec!["test".to_string()],
            trust_score: 100,
        }
    }

    #[tokio::test]
    async fn now_millis_returns_reasonable_value() {
        let t = now_millis();
        // should be around year 2026+ (roughly > 1.7T ms since epoch)
        assert!(
            t > 1_700_000_000_000,
            "epoch millis should be > 1.7T, got {t}"
        );
        // should not be in the far future
        assert!(
            t < 2_000_000_000_000,
            "epoch millis should be < 2T, got {t}"
        );
    }

    #[tokio::test]
    async fn is_alive_recent_returns_true() {
        let node = make_node("alive", 9001);
        assert!(is_alive(&node));
    }

    #[tokio::test]
    async fn is_alive_stale_returns_false() {
        let node = NodeInfo {
            last_seen_millis: now_millis() - 120_000, // 2 min ago
            ..make_node("stale", 9002)
        };
        assert!(!is_alive(&node));
    }

    #[tokio::test]
    async fn manager_new_sets_local_node() {
        let m = P2PMeshManager::new(test_addr(0));
        assert!(!m.local_node.id.is_empty());
        assert_eq!(m.local_node.addr.port(), 0);
        assert!(m.message_rx.is_some());
    }

    #[tokio::test]
    async fn manager_add_and_get_neighbors() {
        let m = P2PMeshManager::new(test_addr(0));
        let n1 = make_node("node-a", 9010);
        let n2 = make_node("node-b", 9011);
        m.add_node(n1).await;
        m.add_node(n2).await;
        let neighbors = m.get_neighbors().await;
        assert_eq!(neighbors.len(), 2);
    }

    #[tokio::test]
    async fn manager_remove_node() {
        let m = P2PMeshManager::new(test_addr(0));
        let n1 = make_node("node-remove", 9020);
        m.add_node(n1).await;
        assert_eq!(m.get_neighbors().await.len(), 1);
        m.remove_node("node-remove").await;
        assert_eq!(m.get_neighbors().await.len(), 0);
    }

    #[tokio::test]
    async fn manager_is_connected_recent() {
        let m = P2PMeshManager::new(test_addr(0));
        let n = make_node("connected", 9030);
        m.add_node(n).await;
        assert!(m.is_connected("connected").await);
    }

    #[tokio::test]
    async fn manager_is_connected_unknown() {
        let m = P2PMeshManager::new(test_addr(0));
        assert!(!m.is_connected("nonexistent").await);
    }

    #[tokio::test]
    async fn manager_get_alive_peers_filters_stale() {
        let m = P2PMeshManager::new(test_addr(0));
        m.add_node(make_node("fresh", 9040)).await;
        m.add_node(NodeInfo {
            last_seen_millis: now_millis() - 120_000,
            ..make_node("stale", 9041)
        })
        .await;
        let alive = m.get_alive_peers().await;
        assert_eq!(alive.len(), 1);
        assert_eq!(alive[0].id, "fresh");
        assert_eq!(alive[0].addr.port(), 9040);
    }

    #[tokio::test]
    async fn p2p_message_serde_roundtrip() {
        let msg = P2PMessage {
            from: "node-a".to_string(),
            from_addr: test_addr(9050),
            to: None,
            msg_type: MessageType::Handshake,
            data: vec![1, 2, 3],
            timestamp_millis: now_millis(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: P2PMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.from, "node-a");
        assert_eq!(deserialized.msg_type, MessageType::Handshake);
        assert_eq!(deserialized.data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn on_message_updates_last_seen() {
        let known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let state = SharedState {
            known_nodes: Arc::clone(&known_nodes),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9059),
        };
        let node = make_node("target", 9060);
        known_nodes
            .write()
            .await
            .insert("target".to_string(), node.clone());

        let ping = P2PMessage {
            from: "target".to_string(),
            from_addr: test_addr(9060),
            to: None,
            msg_type: MessageType::Ping,
            data: Vec::new(),
            timestamp_millis: now_millis(),
        };
        let line = serde_json::to_string(&ping).unwrap();

        let old_seen = node.last_seen_millis;
        tokio::time::sleep(Duration::from_millis(1)).await;
        on_message(&line, "target", &state).await;
        let updated = known_nodes
            .read()
            .await
            .get("target")
            .unwrap()
            .last_seen_millis;
        assert!(updated >= old_seen, "last_seen should update");
    }

    #[tokio::test]
    async fn on_message_with_neighborlist_merges_nodes() {
        let known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let state = SharedState {
            known_nodes: Arc::clone(&known_nodes),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9069),
        };
        known_nodes
            .write()
            .await
            .insert("local".to_string(), make_node("local", 9070));

        let remote_nodes = vec![make_node("remote-a", 9080), make_node("remote-b", 9081)];
        let data = serde_json::to_vec(&remote_nodes).unwrap();
        let msg = P2PMessage {
            from: "local".to_string(),
            from_addr: test_addr(9070),
            to: None,
            msg_type: MessageType::NeighborList,
            data,
            timestamp_millis: now_millis(),
        };
        let line = serde_json::to_string(&msg).unwrap();

        on_message(&line, "local", &state).await;
        let nodes = known_nodes.read().await;
        assert_eq!(nodes.len(), 3);
        assert!(nodes.contains_key("remote-a"));
        assert!(nodes.contains_key("remote-b"));
    }

    #[tokio::test]
    async fn two_nodes_tcp_handshake() {
        let a = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        // Bind listener manually, pass handle_connection for each accept
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let a_ref = a.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = listener_a.accept().await.unwrap();
                let mgr = a_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, &mgr, true).await;
                });
            }
        });

        let b = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        tokio::time::sleep(Duration::from_millis(50)).await;

        timeout(
            Duration::from_secs(5),
            b.clone().connect_to_peer(test_addr(port_a)),
        )
        .await
        .expect("connect_to_peer timeout")
        .expect("connect_to_peer failed");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let a_peers = a.get_alive_peers().await;
        let b_peers = b.get_alive_peers().await;
        assert!(!a_peers.is_empty(), "Node A should have discovered Node B");
        assert!(!b_peers.is_empty(), "Node B should have discovered Node A");
    }

    #[tokio::test]
    async fn gossip_propagates_neighbors() {
        let a = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let a_ref = a.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = listener_a.accept().await.unwrap();
                let mgr = a_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, &mgr, true).await;
                });
            }
        });

        let b = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _port_b = listener_b.local_addr().unwrap().port();
        let b_ref = b.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = listener_b.accept().await.unwrap();
                let mgr = b_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, &mgr, true).await;
                });
            }
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        timeout(
            Duration::from_secs(5),
            b.clone().connect_to_peer(test_addr(port_a)),
        )
        .await
        .expect("A↔B connect timeout")
        .expect("A↔B connect result");
        tokio::time::sleep(Duration::from_millis(200)).await;

        b.gossip_neighbors().await.expect("B gossip");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let a_peers = a.get_alive_peers().await;
        assert!(
            a_peers.iter().any(|n| n.id == b.local_node.id),
            "A should know B after gossip"
        );
    }

    #[tokio::test]
    async fn connect_to_unreachable_returns_error() {
        let m = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        let result = m
            .connect_to_peer(test_addr(1)) // port 1 is privileged = connection refused
            .await;
        assert!(result.is_err(), "connect to unreachable should fail");
    }

    #[tokio::test]
    async fn node_info_serialization() {
        let n = make_node("serde-test", 9090);
        let json = serde_json::to_string(&n).unwrap();
        let back: NodeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "serde-test");
        assert_eq!(back.addr.port(), 9090);
        assert_eq!(back.capabilities, vec!["test"]);
    }

    #[tokio::test]
    async fn record_sync_replication_updates_peer_cache() {
        let a = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let a_ref = a.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = listener_a.accept().await.unwrap();
                let mgr = a_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, &mgr, true).await;
                });
            }
        });

        let b = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        timeout(
            Duration::from_secs(5),
            b.clone().connect_to_peer(test_addr(port_a)),
        )
        .await
        .expect("connect timeout")
        .expect("connect result");
        tokio::time::sleep(Duration::from_millis(200)).await;

        a.sync_record("shared-key", b"shared-value".to_vec())
            .await
            .expect("sync should succeed");
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            b.get_cached_record("shared-key").await,
            Some(b"shared-value".to_vec())
        );
    }

    #[tokio::test]
    async fn fetch_record_returns_peer_value() {
        let a = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();
        let a_ref = a.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = listener_a.accept().await.unwrap();
                let mgr = a_ref.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, peer_addr, &mgr, true).await;
                });
            }
        });

        let b = Arc::new(P2PMeshManager::new(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));
        timeout(
            Duration::from_secs(5),
            b.clone().connect_to_peer(test_addr(port_a)),
        )
        .await
        .expect("connect timeout")
        .expect("connect result");
        tokio::time::sleep(Duration::from_millis(200)).await;

        a.records.write().await.insert(
            "fetch-key".to_string(),
            RecordSyncPayload {
                key: "fetch-key".to_string(),
                value: b"fetch-value".to_vec(),
                owner_node: a.local_node.id.clone(),
                version: now_millis(),
            },
        );

        let fetched = b
            .fetch_record("fetch-key")
            .await
            .expect("fetch should work");
        assert_eq!(fetched, Some(b"fetch-value".to_vec()));
        assert_eq!(
            b.get_cached_record("fetch-key").await,
            Some(b"fetch-value".to_vec())
        );
    }

    #[tokio::test]
    async fn test_trust_score_default_and_penalize() {
        let m = P2PMeshManager::new(test_addr(0));
        let peer = make_node("peer-x", 9999);
        m.add_node(peer.clone()).await;

        assert_eq!(m.get_trust_score("peer-x").await, 100);

        m.penalize_node("peer-x", 30).await;
        assert_eq!(m.get_trust_score("peer-x").await, 70);

        m.penalize_node("peer-x", 30).await;
        assert_eq!(m.get_trust_score("peer-x").await, 40); // drops below 50
    }

    #[tokio::test]
    async fn test_conflict_resolution_rules() {
        let known_nodes = Arc::new(RwLock::new(HashMap::new()));
        let records = Arc::new(RwLock::new(HashMap::new()));
        let state = SharedState {
            known_nodes: Arc::clone(&known_nodes),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::clone(&records),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9099),
        };

        // Setup nodes with different trust scores
        let mut node_low = make_node("node-low", 9001);
        node_low.trust_score = 45; // untrusted
        let mut node_mid = make_node("node-mid", 9002);
        node_mid.trust_score = 60;
        let mut node_high = make_node("node-high", 9003);
        node_high.trust_score = 90;

        known_nodes
            .write()
            .await
            .insert("node-low".to_string(), node_low);
        known_nodes
            .write()
            .await
            .insert("node-mid".to_string(), node_mid);
        known_nodes
            .write()
            .await
            .insert("node-high".to_string(), node_high);

        // 1. RecordSync from untrusted node should be ignored
        let payload_low = RecordSyncPayload {
            key: "key1".to_string(),
            value: b"val-low".to_vec(),
            owner_node: "node-low".to_string(),
            version: 100,
        };
        let msg_low = P2PMessage {
            from: "node-low".to_string(),
            from_addr: test_addr(9001),
            to: None,
            msg_type: MessageType::RecordSync,
            data: serde_json::to_vec(&payload_low).unwrap(),
            timestamp_millis: now_millis(),
        };
        let line_low = serde_json::to_string(&msg_low).unwrap();
        on_message(&line_low, "node-low", &state).await;
        assert!(records.read().await.get("key1").is_none());

        // 2. RecordSync from mid-trust node should succeed
        let payload_mid = RecordSyncPayload {
            key: "key1".to_string(),
            value: b"val-mid".to_vec(),
            owner_node: "node-mid".to_string(),
            version: 100,
        };
        let msg_mid = P2PMessage {
            from: "node-mid".to_string(),
            from_addr: test_addr(9002),
            to: None,
            msg_type: MessageType::RecordSync,
            data: serde_json::to_vec(&payload_mid).unwrap(),
            timestamp_millis: now_millis(),
        };
        let line_mid = serde_json::to_string(&msg_mid).unwrap();
        on_message(&line_mid, "node-mid", &state).await;
        assert_eq!(
            records.read().await.get("key1").unwrap().value,
            b"val-mid".to_vec()
        );

        // 3. Higher trust node (node-high) should overwrite lower trust node (node-mid) even if version is same or lower
        let payload_high = RecordSyncPayload {
            key: "key1".to_string(),
            value: b"val-high".to_vec(),
            owner_node: "node-high".to_string(),
            version: 50, // lower version but higher trust
        };
        let msg_high = P2PMessage {
            from: "node-high".to_string(),
            from_addr: test_addr(9003),
            to: None,
            msg_type: MessageType::RecordSync,
            data: serde_json::to_vec(&payload_high).unwrap(),
            timestamp_millis: now_millis(),
        };
        let line_high = serde_json::to_string(&msg_high).unwrap();
        on_message(&line_high, "node-high", &state).await;
        assert_eq!(
            records.read().await.get("key1").unwrap().value,
            b"val-high".to_vec()
        );

        // 4. If trust is equal, higher version wins
        let payload_high_v2 = RecordSyncPayload {
            key: "key1".to_string(),
            value: b"val-high-v2".to_vec(),
            owner_node: "node-high".to_string(),
            version: 150, // higher version
        };
        let msg_high_v2 = P2PMessage {
            from: "node-high".to_string(),
            from_addr: test_addr(9003),
            to: None,
            msg_type: MessageType::RecordSync,
            data: serde_json::to_vec(&payload_high_v2).unwrap(),
            timestamp_millis: now_millis(),
        };
        let line_high_v2 = serde_json::to_string(&msg_high_v2).unwrap();
        on_message(&line_high_v2, "node-high", &state).await;
        assert_eq!(
            records.read().await.get("key1").unwrap().value,
            b"val-high-v2".to_vec()
        );
    }
}
