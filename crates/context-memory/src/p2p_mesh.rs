use crate::mesh_auth::MeshAuth;
use crate::mesh_tls::MeshTls;
use crate::swim::FailureDetector;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
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

/// ข้อมูลประจำตัวของ node หนึ่งตัวใน P2P mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// รหัสประจำ node (UUID)
    pub id: String,
    /// ที่อยู่ TCP ที่ node นี้เปิดรับการเชื่อมต่อ
    pub addr: SocketAddr,
    /// เวลาที่เห็น node นี้ล่าสุด (epoch millis) ใช้ตรวจความสด
    pub last_seen_millis: u64,
    /// ความสามารถที่ node นี้ให้บริการ (เช่น "semantic", "filesystem")
    pub capabilities: Vec<String>,
    /// คะแนนความน่าเชื่อถือ 0–100 (ต่ำกว่า 50 จะถูกตัดการเชื่อมต่อ)
    #[serde(default = "default_trust_score")]
    pub trust_score: u8,
}

/// ซองข้อความที่รับส่งระหว่าง node ใน mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PMessage {
    /// รหัส node ผู้ส่ง
    pub from: String,
    /// ที่อยู่ TCP ของผู้ส่ง (ใช้เชื่อมกลับ)
    pub from_addr: SocketAddr,
    /// รหัส node ผู้รับ (`None` = broadcast ถึงทุก node)
    pub to: Option<String>,
    /// ชนิดของข้อความ กำหนดวิธี decode ฟิลด์ `data`
    pub msg_type: MessageType,
    /// payload ที่ serialize แล้ว (โครงสร้างขึ้นกับ `msg_type`)
    pub data: Vec<u8>,
    /// เวลาสร้างข้อความ (epoch millis)
    pub timestamp_millis: u64,
}

/// ชนิดข้อความในโปรโตคอล P2P mesh
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    /// ตรวจสุขภาพ peer (heartbeat ขาไป)
    Ping,
    /// ตอบกลับ `Ping` (heartbeat ขากลับ)
    Pong,
    /// แนะนำตัวเมื่อเชื่อมต่อครั้งแรก แลกเปลี่ยน NodeInfo
    Handshake,
    /// กระจายรายชื่อ node ที่รู้จักเพื่อ gossip discovery
    NeighborList,
    /// กระจาย record ที่เขียนใหม่ให้ replica ทั่ว mesh
    RecordSync,
    /// ขอดึงค่า record จาก node อื่น (payload: [`RecordFetchRequest`])
    RecordFetchRequest,
    /// ตอบกลับคำขอดึง record (payload: [`RecordFetchResponse`])
    RecordFetchResponse,
    /// ซิงก์ตารางแมป identity ระหว่าง node
    IdentityMap,
    /// กระจายสถานะทรัพยากรของ node (payload: [`NodeTelemetry`])
    NodeTelemetry,
}

/// payload ของ `RecordSync` — record หนึ่งรายการพร้อมเวอร์ชันสำหรับ conflict resolution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordSyncPayload {
    /// คีย์ของ record
    pub key: String,
    /// ค่าแบบ binary
    pub value: Vec<u8>,
    /// รหัส node เจ้าของข้อมูลต้นทาง
    pub owner_node: String,
    /// เวอร์ชัน (epoch millis ตอนเขียน) — ค่ามากกว่าชนะ
    pub version: u64,
}

/// คำขอดึง record จาก node อื่นใน mesh
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordFetchRequest {
    /// รหัสคำขอ ใช้จับคู่กับ response ที่ตอบกลับมา
    pub request_id: String,
    /// คีย์ของ record ที่ต้องการ
    pub key: String,
}

/// คำตอบของ [`RecordFetchRequest`]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordFetchResponse {
    /// รหัสคำขอเดิมที่คำตอบนี้จับคู่ด้วย
    pub request_id: String,
    /// คีย์ของ record ที่ถูกขอ
    pub key: String,
    /// ค่า record (`None` = node ปลายทางไม่มีคีย์นี้)
    pub value: Option<Vec<u8>>,
    /// รหัส node ที่เป็นเจ้าของค่า
    pub owner_node: String,
}

/// สถานะทรัพยากรของ node หนึ่งตัว ใช้ประกอบการตัดสินใจ route งานข้าม mesh
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeTelemetry {
    /// รหัส node เจ้าของ telemetry นี้
    pub node_id: String,
    /// จำนวน slot ว่างที่รับ agent เพิ่มได้
    pub available_agent_slots: usize,
    /// เพดานจำนวน agent สูงสุดของ node
    pub max_agents: usize,
    /// จำนวน agent ที่กำลังรันอยู่
    pub running_agents: usize,
    /// ความสามารถที่ node ให้บริการ
    pub capabilities: Vec<String>,
    /// ที่อยู่ intent bridge สำหรับส่งงานข้าม node (ถ้าเปิดใช้)
    pub bridge_addr: Option<String>,
    /// เวลาเก็บ telemetry (epoch millis)
    pub timestamp_millis: u64,
}

type PendingFetchSender = oneshot::Sender<Option<Vec<u8>>>;
type PendingFetchMap = Arc<RwLock<HashMap<String, PendingFetchSender>>>;

/// ตัวจัดการ P2P mesh: discovery, replication ของ record, trust score
/// และ failure detection (SWIM) ระหว่าง node ของ context memory
pub struct P2PMeshManager {
    /// ข้อมูลประจำตัวของ node ฝั่งเรา
    pub local_node: NodeInfo,
    /// ตาราง node ที่รู้จักทั้งหมด (key = node id)
    pub known_nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    /// คาบเวลาการทำ discovery รอบถัดไป
    pub discovery_interval: Duration,
    /// ปลายทางส่งข้อความเข้า loop ประมวลผลภายใน
    pub message_tx: mpsc::Sender<P2PMessage>,
    /// ปลายทางรับข้อความ (ถูก take ไปใช้ตอน start event loop)
    pub message_rx: Option<mpsc::Receiver<P2PMessage>>,
    peers: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    records: Arc<RwLock<HashMap<String, RecordSyncPayload>>>,
    pending_fetches: PendingFetchMap,
    telemetries: Arc<RwLock<HashMap<String, NodeTelemetry>>>,
    /// ตัวตรวจจับ node ล้มเหลวแบบ SWIM (alive/suspect/dead)
    pub failure_detector: FailureDetector,
    /// ตัวเซ็น/ตรวจข้อความด้วย HMAC + replay guard (H6) — `None` = โหมด
    /// unauthenticated (dev/test เท่านั้น; production ต้องตั้ง key)
    auth: Option<Arc<MeshAuth>>,
    /// TLS acceptor/connector เข้ารหัสสาย (H7) — derive จาก PSK เดียวกับ H6
    tls: Option<Arc<MeshTls>>,
}

impl P2PMeshManager {
    /// สร้าง mesh manager ด้วย node id สุ่ม (UUID) และ capability ดีฟอลต์
    pub fn new(addr: SocketAddr) -> Self {
        Self::new_with_node_config(
            addr,
            Uuid::new_v4().to_string(),
            vec!["semantic".to_string(), "filesystem".to_string()],
        )
    }

    /// สร้าง mesh manager โดยระบุ node id และรายการ capability เอง
    pub fn new_with_node_config(
        addr: SocketAddr,
        node_id: String,
        capabilities: Vec<String>,
    ) -> Self {
        let local_node = NodeInfo {
            id: node_id,
            addr,
            last_seen_millis: now_millis(),
            capabilities,
            trust_score: 100,
        };

        let (tx, rx) = mpsc::channel(1000);

        let failure_detector = FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None));

        Self {
            local_node,
            known_nodes: Arc::new(RwLock::new(HashMap::new())),
            discovery_interval: Duration::from_secs(30),
            message_tx: tx,
            message_rx: Some(rx),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
            telemetries: Arc::new(RwLock::new(HashMap::new())),
            failure_detector,
            auth: None,
            tls: None,
        }
    }

    /// เปิดใช้ mutual authentication + integrity (H6) และ mTLS เข้ารหัสสาย
    /// (H7) ด้วย pre-shared key เดียวต่อ mesh — HMAC เซ็นทุกข้อความ, TLS
    /// เข้ารหัส transport ด้วย cert ที่ derive จาก PSK เดียวกัน node ที่ไม่ถือ
    /// key เดียวกันจะ handshake TLS ไม่ผ่านและคุยด้วยไม่ได้
    ///
    /// # Errors
    /// คืน error หาก build TLS config จาก PSK ไม่สำเร็จ
    pub fn with_mesh_key(mut self, key: Vec<u8>) -> Result<Self> {
        let tls = MeshTls::from_psk(&key)
            .map_err(|e| anyhow::anyhow!("cannot build mesh TLS from key: {e}"))?;
        self.tls = Some(Arc::new(tls));
        self.auth = Some(Arc::new(MeshAuth::new(key)));
        Ok(self)
    }

    /// `true` หาก mesh นี้เปิด authentication อยู่
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_some()
    }

    /// `true` หาก mesh นี้เปิด TLS เข้ารหัสสายอยู่
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.tls.is_some()
    }

    /// ห่อ+เซ็นข้อความเป็น wire line (หรือ plain JSON ถ้าไม่มี key)
    fn seal_wire(&self, msg: &P2PMessage) -> Result<String> {
        match &self.auth {
            Some(auth) => Ok(auth.seal(msg)?),
            None => Ok(serde_json::to_string(msg)?),
        }
    }

    /// ลงทะเบียน node เข้าตาราง — ถ้า `last_seen` เก่ากว่า 60 วินาทีจะถูกตั้งสถานะ suspect ทันที
    pub async fn add_node(&self, node: NodeInfo) {
        let is_stale = node.last_seen_millis + 60_000 < now_millis();
        if is_stale {
            self.failure_detector
                .suspect(&node.id, "stale_last_seen")
                .await;
        } else {
            self.failure_detector.register(&node.id).await;
        }
        self.known_nodes.write().await.insert(node.id.clone(), node);
    }

    /// ถอด node ออกจากตารางและตัดการเชื่อมต่อ พร้อม mark dead ใน failure detector
    pub async fn remove_node(&self, node_id: &str) {
        self.failure_detector.mark_dead(node_id).await;
        self.known_nodes.write().await.remove(node_id);
        self.peers.write().await.remove(node_id);
    }

    /// คืนรายชื่อ node ทั้งหมดที่รู้จัก (ไม่กรองสถานะ alive)
    pub async fn get_neighbors(&self) -> Vec<NodeInfo> {
        self.known_nodes.read().await.values().cloned().collect()
    }

    /// ตรวจว่า node นี้ยังเชื่อมต่ออยู่ (รู้จัก และสถานะ SWIM = Alive)
    pub async fn is_connected(&self, node_id: &str) -> bool {
        self.failure_detector.get_status(node_id).await == crate::swim::NodeStatus::Alive
            && self.known_nodes.read().await.contains_key(node_id)
    }

    /// คืนเฉพาะ node ที่ failure detector ยืนยันว่ายังมีชีวิต (Alive)
    pub async fn get_alive_peers(&self) -> Vec<NodeInfo> {
        let alive = self.failure_detector.alive_nodes().await;
        self.known_nodes
            .read()
            .await
            .values()
            .filter(|n| alive.contains(&n.id))
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
            let (stream, peer_addr) = timeout(CONNECTION_TIMEOUT, listener.accept())
                .await
                .context("P2P: accept timeout")??;
            debug!(%peer_addr, "P2P: inbound connection");
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                // H7: ห่อ TLS ก่อนถ้าเปิด mesh key — ไม่งั้นใช้ TCP plaintext
                if let Some(tls) = this.tls.clone() {
                    match timeout(CONNECTION_TIMEOUT, tls.acceptor().accept(stream)).await {
                        Ok(Ok(tls_stream)) => {
                            if let Err(e) =
                                handle_connection(tls_stream, peer_addr, &this, true).await
                            {
                                warn!(%peer_addr, error = %e, "P2P: inbound handler error");
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(%peer_addr, error = %e, "P2P: inbound TLS handshake rejected")
                        }
                        Err(_) => warn!(%peer_addr, "P2P: inbound TLS handshake timeout"),
                    }
                } else if let Err(e) = handle_connection(stream, peer_addr, &this, true).await {
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
            // H7: ห่อ TLS ก่อนถ้าเปิด mesh key — ไม่งั้นใช้ TCP plaintext
            if let Some(tls) = self.tls.clone() {
                match timeout(
                    CONNECTION_TIMEOUT,
                    tls.connector().connect(MeshTls::server_name(), stream),
                )
                .await
                {
                    Ok(Ok(tls_stream)) => {
                        if let Err(e) = handle_connection(tls_stream, peer_addr, &self, false).await
                        {
                            warn!(%peer_addr, error = %e, "P2P: outbound handler error");
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(%peer_addr, error = %e, "P2P: outbound TLS handshake rejected")
                    }
                    Err(_) => warn!(%peer_addr, "P2P: outbound TLS handshake timeout"),
                }
            } else if let Err(e) = handle_connection(stream, peer_addr, &self, false).await {
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

        let payload = self.seal_wire(&msg)?;
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

    /// SWIM failure detector background loop
    pub async fn start_failure_detector_loop(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(5)).await;
            let dead = self.failure_detector.ping_round().await;
            for node_id in &dead {
                warn!(node_id, "P2P: SWIM marked node as dead");
                self.remove_node(node_id).await;
            }
        }
    }

    /// เขียน record ลง store ฝั่งเราแล้ว broadcast ให้ทุก node ใน mesh replicate ตาม
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

    /// อ่านค่า record จาก cache ฝั่งเราเท่านั้น (ไม่ยิงคำขอข้ามเครือข่าย)
    pub async fn get_cached_record(&self, key: &str) -> Option<Vec<u8>> {
        self.records
            .read()
            .await
            .get(key)
            .map(|record| record.value.clone())
    }

    /// อ่านค่า record — ลอง cache ก่อน ถ้าไม่มีจึงยิงคำขอไปถาม node อื่นใน mesh
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

    /// ตั้งคะแนนความน่าเชื่อถือของ node — ต่ำกว่า 50 จะถูกตัดการเชื่อมต่อทันที
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

    /// หักคะแนนความน่าเชื่อถือของ node (saturating) — ต่ำกว่า 50 จะถูกตัดการเชื่อมต่อ
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

    /// อ่านคะแนนความน่าเชื่อถือของ node (ไม่รู้จัก = 100 ตามค่าเริ่มต้น)
    pub async fn get_trust_score(&self, node_id: &str) -> u8 {
        let nodes = self.known_nodes.read().await;
        nodes.get(node_id).map(|n| n.trust_score).unwrap_or(100)
    }

    /// บันทึก telemetry ของ node ฝั่งเราแล้ว broadcast ให้ทั้ง mesh รับรู้
    pub async fn publish_node_telemetry(&self, telemetry: NodeTelemetry) -> Result<()> {
        self.telemetries
            .write()
            .await
            .insert(telemetry.node_id.clone(), telemetry.clone());

        let message = P2PMessage {
            from: self.local_node.id.clone(),
            from_addr: self.local_node.addr,
            to: None,
            msg_type: MessageType::NodeTelemetry,
            data: serde_json::to_vec(&telemetry)?,
            timestamp_millis: now_millis(),
        };
        self.broadcast_message(message).await
    }

    /// คืน snapshot ของ telemetry ล่าสุดจากทุก node ที่เคยรายงานเข้ามา
    pub async fn get_telemetry_snapshot(&self) -> HashMap<String, NodeTelemetry> {
        self.telemetries.read().await.clone()
    }

    async fn broadcast_message(&self, message: P2PMessage) -> Result<()> {
        let payload = self.seal_wire(&message)?;
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
    telemetries: Arc<RwLock<HashMap<String, NodeTelemetry>>>,
    local_id: String,
    local_addr: SocketAddr,
    failure_detector: FailureDetector,
    auth: Option<Arc<MeshAuth>>,
}

impl SharedState {
    /// ห่อ+เซ็นข้อความเป็น wire line (หรือ plain JSON ถ้าไม่มี key)
    fn seal_wire(&self, msg: &P2PMessage) -> Result<String> {
        match &self.auth {
            Some(auth) => Ok(auth.seal(msg)?),
            None => Ok(serde_json::to_string(msg)?),
        }
    }

    /// ตรวจ+แกะ wire line เป็น [`P2PMessage`] — คืน `None` ถ้า auth ไม่ผ่าน
    /// (signature ผิด/replay/stale) หรือ parse ไม่ได้ ผู้เรียกต้องทิ้งข้อความ
    fn open_wire(&self, line: &str) -> Option<P2PMessage> {
        match &self.auth {
            Some(auth) => match auth.open(line) {
                Ok(msg) => Some(msg),
                Err(e) => {
                    warn!(error = %e, "P2P: rejecting message that failed mesh authentication");
                    None
                }
            },
            None => serde_json::from_str::<P2PMessage>(line.trim()).ok(),
        }
    }
}

async fn on_message(line: &str, node_id: &str, state: &SharedState) {
    state.failure_detector.record_ack(node_id).await;

    if let Some(msg) = state.open_wire(line) {
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

        if msg.msg_type == MessageType::NodeTelemetry {
            if let Ok(telemetry) = serde_json::from_slice::<NodeTelemetry>(&msg.data) {
                state
                    .telemetries
                    .write()
                    .await
                    .insert(telemetry.node_id.clone(), telemetry.clone());
                let mut nodes = state.known_nodes.write().await;
                nodes
                    .entry(telemetry.node_id.clone())
                    .and_modify(|node| {
                        node.last_seen_millis = now_millis();
                        if !telemetry.capabilities.is_empty() {
                            node.capabilities = telemetry.capabilities.clone();
                        }
                    })
                    .or_insert(NodeInfo {
                        id: telemetry.node_id,
                        addr: msg.from_addr,
                        last_seen_millis: now_millis(),
                        capabilities: telemetry.capabilities,
                        trust_score: 100,
                    });
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
                if let Ok(payload) = state.seal_wire(&envelope) {
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
async fn handle_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    mgr: &P2PMeshManager,
    is_inbound: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // tokio::io::split รองรับทั้ง TcpStream (plaintext) และ TlsStream (H7)
    let (owned_reader, mut owned_writer) = tokio::io::split(stream);

    let state = SharedState {
        known_nodes: Arc::clone(&mgr.known_nodes),
        peers: Arc::clone(&mgr.peers),
        records: Arc::clone(&mgr.records),
        pending_fetches: Arc::clone(&mgr.pending_fetches),
        telemetries: Arc::clone(&mgr.telemetries),
        local_id: mgr.local_node.id.clone(),
        local_addr: mgr.local_node.addr,
        failure_detector: mgr.failure_detector.clone(),
        auth: mgr.auth.clone(),
    };

    if is_inbound {
        let mut reader = BufReader::new(owned_reader);
        let mut line = String::new();

        // 1. อ่าน handshake (with timeout)
        timeout(RW_TIMEOUT, reader.read_line(&mut line))
            .await
            .context("P2P: handshake read timeout")??;
        let hs = state
            .open_wire(&line)
            .context("P2P: inbound handshake failed mesh authentication")?;
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
        state.failure_detector.record_ack(&hs.from).await;
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
        let resp_json = state.seal_wire(&resp)?;
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
                match timeout(RW_TIMEOUT, reader.read_line(&mut buf)).await {
                    Ok(Ok(0)) | Ok(Err(_)) => {
                        read_state
                            .failure_detector
                            .suspect(&node_id, "inbound_eof")
                            .await;
                        break;
                    }
                    Ok(Ok(_)) => on_message(&buf, &node_id, &read_state).await,
                    Err(_) => {
                        warn!("P2P: inbound read timeout, closing connection");
                        read_state
                            .failure_detector
                            .suspect(&node_id, "inbound_timeout")
                            .await;
                        break;
                    }
                }
            }
            {
                let mut peers = peers.write().await;
                peers.remove(&node_id);
                drop(peers);
            }
            read_state.failure_detector.mark_dead(&node_id).await;
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
        let hs_json = state.seal_wire(&hs)?;
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
        let hs_resp = state
            .open_wire(&line)
            .context("P2P: outbound handshake response failed mesh authentication")?;
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
        state.failure_detector.record_ack(&hs_resp.from).await;
        info!(node_id = %hs_resp.from, %peer_addr, "P2P: registered via outbound handshake");

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
                    Ok(Ok(0)) | Ok(Err(_)) => {
                        read_state
                            .failure_detector
                            .suspect(&node_id, "outbound_eof")
                            .await;
                        break;
                    }
                    Ok(Ok(_)) => on_message(&buf, &node_id, &read_state).await,
                    Err(_) => {
                        warn!("P2P: outbound read timeout, closing connection");
                        read_state
                            .failure_detector
                            .suspect(&node_id, "outbound_timeout")
                            .await;
                        break;
                    }
                }
            }
            {
                let mut peers = peers.write().await;
                peers.remove(&node_id);
                drop(peers);
            }
            read_state.failure_detector.mark_dead(&node_id).await;
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

    /// Returns true if the environment allows TCP bind (not sandboxed).
    fn can_bind_tcp() -> bool {
        use std::net::TcpListener;
        TcpListener::bind("127.0.0.1:0").is_ok()
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
        let m = P2PMeshManager::new(test_addr(0));
        m.add_node(make_node("alive", 9001)).await;
        assert!(m.is_connected("alive").await);
    }

    #[tokio::test]
    async fn is_alive_stale_returns_false() {
        let m = P2PMeshManager::new(test_addr(0));
        m.add_node(make_node("stale", 9002)).await;
        // mark as suspect (simulate failure)
        m.failure_detector.suspect("stale", "test").await;
        assert!(!m.is_connected("stale").await);
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
            telemetries: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9059),
            failure_detector: FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None)),
            auth: None,
        };
        let node = make_node("target", 9060);
        state.failure_detector.register("target").await;
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
            telemetries: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9069),
            failure_detector: FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None)),
            auth: None,
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
        if !can_bind_tcp() {
            eprintln!("SKIP: two_nodes_tcp_handshake (no TCP bind capability)");
            return;
        }
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
        if !can_bind_tcp() {
            eprintln!("SKIP: gossip_propagates_neighbors (no TCP bind capability)");
            return;
        }
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
        if !can_bind_tcp() {
            eprintln!("SKIP: record_sync_replication_updates_peer_cache (no TCP bind capability)");
            return;
        }
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
        if !can_bind_tcp() {
            eprintln!("SKIP: fetch_record_returns_peer_value (no TCP bind capability)");
            return;
        }
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
    async fn telemetry_roundtrip_updates_snapshot() {
        let known_nodes = Arc::new(RwLock::new(HashMap::new()));
        let telemetries = Arc::new(RwLock::new(HashMap::new()));
        let state = SharedState {
            known_nodes: Arc::clone(&known_nodes),
            peers: Arc::new(RwLock::new(HashMap::new())),
            records: Arc::new(RwLock::new(HashMap::new())),
            pending_fetches: Arc::new(RwLock::new(HashMap::new())),
            telemetries: Arc::clone(&telemetries),
            local_id: "local".to_string(),
            local_addr: test_addr(9098),
            failure_detector: FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None)),
            auth: None,
        };
        let telemetry = NodeTelemetry {
            node_id: "node-telemetry".to_string(),
            available_agent_slots: 7,
            max_agents: 10,
            running_agents: 3,
            capabilities: vec!["small".to_string()],
            bridge_addr: Some("127.0.0.1:9191".to_string()),
            timestamp_millis: now_millis(),
        };
        let msg = P2PMessage {
            from: "node-telemetry".to_string(),
            from_addr: test_addr(9191),
            to: None,
            msg_type: MessageType::NodeTelemetry,
            data: serde_json::to_vec(&telemetry).unwrap(),
            timestamp_millis: now_millis(),
        };

        on_message(
            &serde_json::to_string(&msg).unwrap(),
            "node-telemetry",
            &state,
        )
        .await;

        let snapshot = telemetries.read().await;
        assert_eq!(
            snapshot
                .get("node-telemetry")
                .unwrap()
                .available_agent_slots,
            7
        );
        let nodes = known_nodes.read().await;
        assert_eq!(
            nodes.get("node-telemetry").unwrap().capabilities,
            vec!["small".to_string()]
        );
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
            telemetries: Arc::new(RwLock::new(HashMap::new())),
            local_id: "local".to_string(),
            local_addr: test_addr(9099),
            failure_detector: FailureDetector::new(Arc::new(|_| None), Arc::new(|_, _| None)),
            auth: None,
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

    // ── H6: mutual authentication over real TCP loopback ──

    fn loopback() -> SocketAddr {
        // port 0 = ให้ OS เลือก port ว่างเอง
        "127.0.0.1:0".parse().unwrap()
    }

    async fn bound_manager(node: &str, key: Option<&[u8]>) -> Arc<P2PMeshManager> {
        // bind ก่อนเพื่อรู้ port จริง แล้วสร้าง manager ด้วย addr นั้น
        let listener = TcpListener::bind(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut mgr = P2PMeshManager::new_with_node_config(addr, node.to_string(), vec![]);
        if let Some(k) = key {
            mgr = mgr.with_mesh_key(k.to_vec()).expect("build mesh key");
        }
        let mgr = Arc::new(mgr);
        let listener_mgr = Arc::clone(&mgr);
        tokio::spawn(async move {
            let _ = listener_mgr.start_listener().await;
        });
        // ให้ listener bind เสร็จก่อนคืน
        sleep(Duration::from_millis(50)).await;
        mgr
    }

    #[tokio::test]
    async fn authenticated_peers_with_matching_key_connect() {
        let key = b"shared-mesh-secret";
        let a = bound_manager("node-a", Some(key)).await;
        let b = bound_manager("node-b", Some(key)).await;
        assert!(a.is_authenticated(), "H6 HMAC auth active");
        assert!(a.is_encrypted(), "H7 mTLS active");

        Arc::clone(&a)
            .connect_to_peer(b.local_node.addr)
            .await
            .expect("connect");

        // handshake (ผ่าน TLS + HMAC) สำเร็จ → ต่างฝ่ายต่างรู้จักกัน
        let connected = wait_until(2000, || async {
            a.is_connected("node-b").await && b.is_connected("node-a").await
        })
        .await;
        assert!(
            connected,
            "peers with matching keys must complete the TLS + handshake"
        );
    }

    #[tokio::test]
    async fn peer_with_wrong_key_is_rejected() {
        let a = bound_manager("node-a", Some(b"correct-key")).await;
        let b = bound_manager("node-b", Some(b"WRONG-key")).await;

        let _ = Arc::clone(&a).connect_to_peer(b.local_node.addr).await;

        // wrong key → TLS cert (derive จาก PSK) ไม่ตรง → handshake ถูก
        // ปฏิเสธที่ชั้น TLS ก่อนถึง HMAC ด้วยซ้ำ → ไม่มีใครลงทะเบียนเป็น peer
        let connected = wait_until(1500, || async {
            a.is_connected("node-b").await || b.is_connected("node-a").await
        })
        .await;
        assert!(
            !connected,
            "a peer holding the wrong key must never be admitted"
        );
    }

    /// poll เงื่อนไขทุก 25ms จนจริงหรือหมดเวลา (คืน true ถ้าจริงทัน)
    async fn wait_until<F, Fut>(timeout_ms: u64, mut cond: F) -> bool
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if cond().await {
                return true;
            }
            sleep(Duration::from_millis(25)).await;
        }
        cond().await
    }
}
