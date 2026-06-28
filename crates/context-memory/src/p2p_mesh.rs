use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio::time::{Duration, sleep};
use tracing::{debug, info, warn};
use uuid::Uuid;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub addr: SocketAddr,
    pub last_seen_millis: u64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PMessage {
    pub from: String,
    pub from_addr: SocketAddr,
    pub to: Option<String>,
    pub msg_type: MessageType,
    pub data: Vec<u8>,
    pub timestamp_millis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    Ping,
    Pong,
    Handshake,
    NeighborList,
    RecordSync,
    IdentityMap,
}

pub struct P2PMeshManager {
    pub local_node: NodeInfo,
    pub known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    pub discovery_interval: Duration,
    pub message_tx: mpsc::Sender<P2PMessage>,
    pub message_rx: Option<mpsc::Receiver<P2PMessage>>,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
}

fn is_alive(node: &NodeInfo) -> bool {
    now_millis().saturating_sub(node.last_seen_millis) < 60_000
}

impl P2PMeshManager {
    pub fn new(addr: SocketAddr) -> Self {
        let node_id = Uuid::new_v4().to_string();
        let local_node = NodeInfo {
            id: node_id,
            addr,
            last_seen_millis: now_millis(),
            capabilities: vec!["semantic".to_string(), "filesystem".to_string()],
        };

        let (tx, rx) = mpsc::channel(1000);

        Self {
            local_node,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            discovery_interval: Duration::from_secs(30),
            message_tx: tx,
            message_rx: Some(rx),
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_node(&self, node: NodeInfo) {
        self.known_nodes.write().await.insert(node.id.clone(), node);
    }

    pub async fn remove_node(&self, node_id: &str) {
        self.known_nodes.write().await.remove(node_id);
        self.peers.write().await.remove(node_id);
    }

    pub async fn get_neighbors(&self) -> Vec<NodeInfo> {
        self.known_nodes.read().await.values().cloned().collect()
    }

    pub async fn is_connected(&self, node_id: &str) -> bool {
        self.known_nodes
            .read()
            .await
            .get(node_id)
            .is_some_and(is_alive)
    }

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
        let stream = TcpStream::connect(addr)
            .await
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
}

#[derive(Clone)]
struct SharedState {
    known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    local_id: String,
    local_addr: SocketAddr,
}

async fn on_message(
    line: &str,
    node_id: &str,
    known_nodes: &Arc<RwLock<HashMap<String, NodeInfo>>>,
) {
    if let Ok(msg) = serde_json::from_str::<P2PMessage>(line.trim()) {
        known_nodes
            .write()
            .await
            .entry(node_id.to_string())
            .and_modify(|n| {
                n.last_seen_millis = now_millis();
            });
        if msg.msg_type == MessageType::NeighborList {
            if let Ok(neighbors) = serde_json::from_slice::<Vec<NodeInfo>>(&msg.data) {
                let mut nodes = known_nodes.write().await;
                for n in neighbors {
                    nodes.entry(n.id.clone()).or_insert_with(|| NodeInfo {
                        last_seen_millis: now_millis(),
                        ..n
                    });
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
        local_id: mgr.local_node.id.clone(),
        local_addr: mgr.local_node.addr,
    };

    if is_inbound {
        let mut reader = BufReader::new(owned_reader);
        let mut line = String::new();

        // 1. อ่าน handshake
        reader.read_line(&mut line).await?;
        let hs: P2PMessage = serde_json::from_str(line.trim())?;
        if hs.msg_type != MessageType::Handshake {
            anyhow::bail!("expected Handshake, got {:?}", hs.msg_type);
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
                },
            );
        }
        info!(node_id = %hs.from, %peer_addr, "P2P: registered via inbound handshake");

        // 2. ส่ง handshake response
        let resp = P2PMessage {
            from: state.local_id.clone(),
            from_addr: state.local_addr,
            to: Some(hs.from.clone()),
            msg_type: MessageType::Handshake,
            data: Vec::new(),
            timestamp_millis: now_millis(),
        };
        let resp_json = serde_json::to_string(&resp)?;
        owned_writer.write_all(resp_json.as_bytes()).await?;
        owned_writer.write_all(b"\n").await?;
        owned_writer.flush().await?;

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        state.peers.write().await.insert(hs.from.clone(), tx);
        let node_id = hs.from.clone();
        let known_nodes = Arc::clone(&state.known_nodes);
        let peers = Arc::clone(&state.peers);

        let read_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = String::new();
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => on_message(&buf, &node_id, &known_nodes).await,
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

        // outbound: ส่ง handshake
        let hs = P2PMessage {
            from: state.local_id.clone(),
            from_addr: state.local_addr,
            to: None,
            msg_type: MessageType::Handshake,
            data: Vec::new(),
            timestamp_millis: now_millis(),
        };
        let hs_json = serde_json::to_string(&hs)?;
        owned_writer.write_all(hs_json.as_bytes()).await?;
        owned_writer.write_all(b"\n").await?;
        owned_writer.flush().await?;

        // อ่าน handshake response
        reader.read_line(&mut line).await?;
        let hs_resp: P2PMessage = serde_json::from_str(line.trim())?;
        if hs_resp.msg_type != MessageType::Handshake {
            anyhow::bail!("expected Handshake response, got {:?}", hs_resp.msg_type);
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
                },
            );
        }
        info!(node_id = %hs_resp.from, %peer_addr, "P2P: outbound handshake complete");

        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        state.peers.write().await.insert(hs_resp.from.clone(), tx);
        let node_id = hs_resp.from.clone();
        let known_nodes = Arc::clone(&state.known_nodes);
        let peers = Arc::clone(&state.peers);

        let read_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut buf = String::new();
            loop {
                buf.clear();
                match reader.read_line(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => on_message(&buf, &node_id, &known_nodes).await,
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
    }

    Ok(())
}
