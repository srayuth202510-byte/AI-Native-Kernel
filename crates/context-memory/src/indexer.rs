#![deny(unsafe_code)]

//! Incremental Semantic Indexing — ระบบดัชนีไฟล์เชิงความหมายแบบเพิ่มขึ้น
//!
//! คัดกรองและสร้างดัชนีเฉพาะไฟล์ที่เปลี่ยนแปลง เพื่อลด latency ในการสร้าง Index
//! ใช้ file watcher (inotify) + content hashing + batch processing

use crate::semantic::SemanticStore;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};

/// Timeout สำหรับ I/O operations
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// ขนาดสูงสุดของไฟล์ที่จะ embedding ทั้งหมดใน vector เดียว (bytes)
/// ไฟล์ที่ใหญ่กว่าจะถูกแบ่งเป็น chunks
const MAX_SINGLE_EMBED_SIZE: usize = 8192;

/// จำนวนครั้งสูงสุดสำหรับ retry Qdrant operations
const MAX_RETRIES: u32 = 3;

/// ระยะเวลา wait ก่อน retry (exponential backoff)
const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// ค่าเริ่มต้นของ batch window สำหรับ debounce (ms)
const _DEFAULT_BATCH_WINDOW_MS: u64 = 500;

/// ค่าเริ่มต้นของ max batch size
const _DEFAULT_MAX_BATCH_SIZE: usize = 50;

// ── IndexManifest ─────────────────────────────────────────────────────────

/// ข้อมูล manifest ของไฟล์ที่ถูก index แล้ว
/// ใช้สำหรับติดตามว่าไฟล์ใดถูก index ไปแล้วบ้าง และต้อง re-index หรือไม่
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexManifestEntry {
    /// path ของไฟล์ (relative to base_dir)
    pub path: String,
    /// SHA-256 hash ของเนื้อหาไฟล์
    pub content_hash: [u8; 32],
    /// เวลาที่ index ครั้งล่าสุด
    pub last_indexed_mtime: SystemTime,
    /// จำนวน chunks ที่ถูก index
    pub chunk_count: u32,
    /// รายการ point IDs ใน Qdrant (สำหรับลบก่อน re-index)
    pub point_ids: Vec<String>,
    /// ขนาดไฟล์ (bytes)
    pub file_size: u64,
}

/// สถานะของ manifest database
pub struct ManifestStore {
    /// path สำหรับเก็บ manifest (JSON file)
    manifest_path: PathBuf,
    /// in-memory cache ของ manifest
    entries: RwLock<HashMap<String, IndexManifestEntry>>,
}

impl ManifestStore {
    /// สร้าง ManifestStore ใหม่ หรือโหลดจากไฟล์ที่มีอยู่
    #[instrument(skip())]
    pub async fn new(manifest_dir: &Path) -> Result<Self> {
        let manifest_path = manifest_dir.join("index_manifest.json");

        let entries = if manifest_path.exists() {
            let data = timeout(IO_TIMEOUT, tokio::fs::read(&manifest_path))
                .await
                .context("manifest read timeout")?
                .context("failed to read manifest file")?;

            let parsed: HashMap<String, IndexManifestEntry> =
                serde_json::from_slice(&data).context("failed to parse manifest")?;

            info!(count = parsed.len(), "loaded index manifest");
            parsed
        } else {
            info!("no existing manifest found, starting fresh");
            HashMap::new()
        };

        Ok(Self {
            manifest_path,
            entries: RwLock::new(entries),
        })
    }

    /// ดึงข้อมูล manifest ของไฟล์
    pub async fn get(&self, path: &str) -> Option<IndexManifestEntry> {
        self.entries.read().await.get(path).cloned()
    }

    /// ตรวจสอบว่าไฟล์ต้อง re-index หรือไม่
    ///
    /// คืน `true` ถ้า:
    /// - ไฟล์ไม่มีใน manifest (new file)
    /// - content hash เปลี่ยนแปลง
    /// - mtime ใหม่กว่า last_indexed_mtime
    pub async fn needs_reindex(
        &self,
        path: &str,
        current_hash: &[u8; 32],
        current_mtime: SystemTime,
    ) -> bool {
        match self.entries.read().await.get(path) {
            None => true, // ไฟล์ใหม่
            Some(entry) => {
                entry.content_hash != *current_hash || entry.last_indexed_mtime < current_mtime
            }
        }
    }

    /// บันทึกข้อมูล manifest ของไฟล์
    pub async fn upsert(&self, entry: IndexManifestEntry) {
        self.entries.write().await.insert(entry.path.clone(), entry);
    }

    /// ลบข้อมูล manifest ของไฟล์
    pub async fn remove(&self, path: &str) -> Option<IndexManifestEntry> {
        self.entries.write().await.remove(path)
    }

    /// คืนรายการ paths ทั้งหมดที่อยู่ใน manifest
    pub async fn all_paths(&self) -> Vec<String> {
        self.entries.read().await.keys().cloned().collect()
    }

    /// คืนจำนวน entries ทั้งหมด
    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    /// ตรวจสอบว่า manifest ว่างเปล่าหรือไม่
    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// บันทึก manifest ลงไฟล์ ( persist to disk)
    #[instrument(skip(self))]
    pub async fn flush(&self) -> Result<()> {
        let entries = self.entries.read().await;
        let data = serde_json::to_vec_pretty(&*entries).context("failed to serialize manifest")?;

        // เขียนลง temp file แล้ว rename เพื่อความ atomic
        let temp_path = self.manifest_path.with_extension("json.tmp");
        timeout(IO_TIMEOUT, tokio::fs::write(&temp_path, &data))
            .await
            .context("manifest write timeout")?
            .context("failed to write manifest temp file")?;

        timeout(
            IO_TIMEOUT,
            tokio::fs::rename(&temp_path, &self.manifest_path),
        )
        .await
        .context("manifest rename timeout")?
        .context("failed to rename manifest file")?;

        debug!(count = entries.len(), "manifest flushed to disk");
        Ok(())
    }
}

// ── ChangeDetector ────────────────────────────────────────────────────────

/// ตรวจสอบการเปลี่ยนแปลงของไฟล์โดยใช้ SHA-256 content hash
pub struct ChangeDetector {
    /// manifest store สำหรับเปรียบเทียบ hash
    manifest: Arc<ManifestStore>,
}

/// ผลลัพธ์ของการตรวจสอบการเปลี่ยนแปลง
#[derive(Debug, Clone)]
pub enum FileChange {
    /// ไฟล์ใหม่ที่ยังไม่เคย index
    Created { path: String },
    /// ไฟล์ที่มีการเปลี่ยนแปลงเนื้อหา
    Modified { path: String },
    /// ไฟล์ที่ถูกลบ
    Deleted { path: String },
}

impl ChangeDetector {
    /// สร้าง ChangeDetector ใหม่
    #[must_use]
    pub fn new(manifest: Arc<ManifestStore>) -> Self {
        Self { manifest }
    }

    /// คำนวณ SHA-256 hash ของเนื้อหาไฟล์
    #[instrument(skip(content))]
    pub fn compute_hash(content: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.finalize().into()
    }

    /// ตรวจสอบว่าไฟล์มีการเปลี่ยนแปลงหรือไม่
    #[instrument(skip(self, base_dir))]
    pub async fn check_file(&self, base_dir: &Path, path: &str) -> Result<Option<FileChange>> {
        let file_path = base_dir.join(path);

        // ตรวจสอบว่าไฟล์ยังมีอยู่หรือไม่
        if !file_path.exists() {
            // ไฟล์ถูกลบ
            if self.manifest.get(path).await.is_some() {
                return Ok(Some(FileChange::Deleted {
                    path: path.to_string(),
                }));
            }
            return Ok(None);
        }

        // อ่านเนื้อหาไฟล์
        let content = timeout(IO_TIMEOUT, tokio::fs::read(&file_path))
            .await
            .context("file read timeout during change detection")?
            .context("failed to read file for change detection")?;

        let current_hash = Self::compute_hash(&content);

        // ดึง mtime ของไฟล์
        let metadata = timeout(IO_TIMEOUT, tokio::fs::metadata(&file_path))
            .await
            .context("metadata read timeout")?
            .context("failed to read file metadata")?;

        let current_mtime = metadata.modified().unwrap_or(SystemTime::now());

        // ตรวจสอบกับ manifest
        if self
            .manifest
            .needs_reindex(path, &current_hash, current_mtime)
            .await
        {
            let is_new = self.manifest.get(path).await.is_none();
            if is_new {
                Ok(Some(FileChange::Created {
                    path: path.to_string(),
                }))
            } else {
                Ok(Some(FileChange::Modified {
                    path: path.to_string(),
                }))
            }
        } else {
            Ok(None)
        }
    }

    /// ตรวจสอบทุกไฟล์ใน directory
    #[instrument(skip(self, base_dir))]
    pub async fn scan_all(&self, base_dir: &Path) -> Result<Vec<FileChange>> {
        let mut changes = Vec::new();
        self.walk_and_check(base_dir, base_dir, &mut changes)
            .await?;
        Ok(changes)
    }

    /// Recursive directory walker สำหรับตรวจสอบการเปลี่ยนแปลง
    async fn walk_and_check(
        &self,
        base_dir: &Path,
        current_dir: &Path,
        changes: &mut Vec<FileChange>,
    ) -> Result<()> {
        let mut entries = timeout(IO_TIMEOUT, tokio::fs::read_dir(current_dir))
            .await
            .context("read_dir timeout during scan")?
            .context("failed to read directory during scan")?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .context("next_entry timeout during scan")?
        {
            let path = entry.path();
            if entry
                .file_type()
                .await
                .context("file_type timeout")?
                .is_dir()
            {
                Box::pin(self.walk_and_check(base_dir, &path, changes)).await?;
            } else {
                let relative = path
                    .strip_prefix(base_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();

                if let Some(change) = self.check_file(base_dir, &relative).await? {
                    changes.push(change);
                }
            }
        }

        Ok(())
    }

    /// ตรวจสอบไฟล์ที่ถูกลบ (ไฟล์ที่อยู่ใน manifest แต่ไม่มีในดิสก์)
    pub async fn find_deleted(&self, base_dir: &Path) -> Vec<String> {
        let manifest_paths = self.manifest.all_paths().await;
        let mut deleted = Vec::new();

        for path in manifest_paths {
            let file_path = base_dir.join(&path);
            if !file_path.exists() {
                deleted.push(path);
            }
        }

        deleted
    }
}

// ── BatchAccumulator ──────────────────────────────────────────────────────

/// คิวสำหรับสะสมการเปลี่ยนแปลงก่อนส่งเข้า indexer
/// ใช้ debounce window เพื่อรวมการเปลี่ยนแปลงที่เกิดขึ้นใกล้เคียงกัน
pub struct BatchAccumulator {
    /// ช่องรับ file changes
    change_rx: mpsc::Receiver<FileChange>,
    /// ช่องส่ง batched changes
    batch_tx: mpsc::Sender<Vec<FileChange>>,
    /// ระยะเวลา debounce window
    batch_window: Duration,
    /// จำนวนสูงสุดต่อ batch
    max_batch_size: usize,
}

impl BatchAccumulator {
    /// สร้าง BatchAccumulator ใหม่
    #[must_use]
    pub fn new(
        change_rx: mpsc::Receiver<FileChange>,
        batch_tx: mpsc::Sender<Vec<FileChange>>,
        batch_window_ms: u64,
        max_batch_size: usize,
    ) -> Self {
        Self {
            change_rx,
            batch_tx,
            batch_window: Duration::from_millis(batch_window_ms),
            max_batch_size,
        }
    }

    /// เริ่มต้น batching loop
    pub async fn run(mut self) {
        let mut buffer: Vec<FileChange> = Vec::new();
        let mut window_start = tokio::time::Instant::now();

        loop {
            tokio::select! {
                change = self.change_rx.recv() => {
                    match change {
                        Some(change) => {
                            buffer.push(change);

                            // ส่ง batch ถ้าเกิน max batch size
                            if buffer.len() >= self.max_batch_size {
                                let batch = std::mem::take(&mut buffer);
                                window_start = tokio::time::Instant::now();
                                if self.batch_tx.send(batch).await.is_err() {
                                    error!("batch_tx send failed, stopping accumulator");
                                    break;
                                }
                            }
                        }
                        None => {
                            // Channel closed — ส่ง buffer ที่เหลือ
                            if !buffer.is_empty() {
                                let _ = self.batch_tx.send(buffer).await;
                            }
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep_until(window_start + self.batch_window), if !buffer.is_empty() => {
                    // Batch window expired — ส่ง buffer ปัจจุบัน
                    let batch = std::mem::take(&mut buffer);
                    window_start = tokio::time::Instant::now();
                    if self.batch_tx.send(batch).await.is_err() {
                        error!("batch_tx send failed, stopping accumulator");
                        break;
                    }
                }
            }
        }
    }
}

// ── SemanticIndexer ───────────────────────────────────────────────────────

/// ตัว indexer หลักที่ทำงานแบบ background task
/// รับ batched file changes แล้วสร้าง/อัปเดต index ใน Qdrant
pub struct SemanticIndexer {
    /// base directory ของไฟล์
    base_dir: PathBuf,
    /// ตัวจัดการ Qdrant vector store
    semantic_store: Arc<SemanticStore>,
    /// manifest store สำหรับติดตามสถานะ indexing
    manifest: Arc<ManifestStore>,
    /// change detector
    detector: Arc<ChangeDetector>,
    /// ช่องรับ batched changes
    batch_rx: mpsc::Receiver<Vec<FileChange>>,
    /// ช่องส่ง file change events (สำหรับส่งต่อให้ query cache invalidation)
    event_tx: mpsc::Sender<IndexerEvent>,
    /// มิติของเวกเตอร์ embedding
    vector_size: usize,
    /// ขนาดสูงสุดของไฟล์ที่จะ embedding ทั้งหมดใน vector เดียว
    max_embed_size: usize,
}

/// เหตุการณ์ที่ indexer ส่งออก
#[derive(Debug, Clone)]
pub enum IndexerEvent {
    /// มีไฟล์ถูก index ใหม่
    FileIndexed { paths: Vec<String> },
    /// มีไฟล์ถูกลบออก
    FileDeleted { path: String },
    /// Index ทั้งหมดเสร็จสมบูรณ์
    ScanComplete { total_files: usize, indexed: usize },
}

impl SemanticIndexer {
    /// สร้าง SemanticIndexer ใหม่
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_dir: PathBuf,
        semantic_store: Arc<SemanticStore>,
        manifest: Arc<ManifestStore>,
        batch_rx: mpsc::Receiver<Vec<FileChange>>,
        event_tx: mpsc::Sender<IndexerEvent>,
        vector_size: usize,
    ) -> Self {
        let detector = Arc::new(ChangeDetector::new(manifest.clone()));
        Self {
            base_dir,
            semantic_store,
            manifest,
            detector,
            batch_rx,
            event_tx,
            vector_size,
            max_embed_size: MAX_SINGLE_EMBED_SIZE,
        }
    }

    /// เริ่มต้น indexer loop
    pub async fn run(mut self) {
        info!("incremental semantic indexer started");

        while let Some(batch) = self.batch_rx.recv().await {
            self.process_batch(batch).await;
        }

        info!("incremental semantic indexer stopped");
    }

    /// ประมวลผล batch ของ file changes
    #[instrument(skip(self, batch), fields(count = batch.len()))]
    async fn process_batch(&self, batch: Vec<FileChange>) {
        let mut indexed_paths = Vec::new();

        for change in batch {
            match change {
                FileChange::Created { path } | FileChange::Modified { path } => {
                    match self.index_file(&path).await {
                        Ok(()) => {
                            indexed_paths.push(path);
                        }
                        Err(e) => {
                            warn!(path = %path, error = %e, "failed to index file");
                        }
                    }
                }
                FileChange::Deleted { path } => match self.delete_file_index(&path).await {
                    Ok(()) => {
                        let _ = self
                            .event_tx
                            .send(IndexerEvent::FileDeleted { path: path.clone() })
                            .await;
                    }
                    Err(e) => {
                        warn!(path = %path, error = %e, "failed to delete file index");
                    }
                },
            }
        }

        // Flush manifest หลังจาก index ทั้งหมดเสร็จ
        if let Err(e) = self.manifest.flush().await {
            error!(error = %e, "failed to flush manifest after batch");
        }

        // ส่ง event
        if !indexed_paths.is_empty() {
            let _ = self
                .event_tx
                .send(IndexerEvent::FileIndexed {
                    paths: indexed_paths,
                })
                .await;
        }
    }

    /// Index ไฟล์เดียวลง Qdrant
    #[instrument(skip(self), fields(path))]
    async fn index_file(&self, relative_path: &str) -> Result<()> {
        let file_path = self.base_dir.join(relative_path);

        // อ่านเนื้อหาไฟล์
        let content = timeout(IO_TIMEOUT, tokio::fs::read_to_string(&file_path))
            .await
            .context("file read timeout during indexing")?
            .context("failed to read file for indexing")?;

        // คำนวณ hash
        let content_hash = ChangeDetector::compute_hash(content.as_bytes());

        // ดึง mtime
        let metadata = timeout(IO_TIMEOUT, tokio::fs::metadata(&file_path))
            .await
            .context("metadata timeout")?
            .context("metadata read failed")?;
        let mtime = metadata.modified().unwrap_or(SystemTime::now());

        // ลบ index เดิม (ถ้ามี) เพื่อป้องกัน duplicate points
        if let Some(old_entry) = self.manifest.get(relative_path).await {
            if !old_entry.point_ids.is_empty() {
                if let Err(e) = self.semantic_store.delete_batch(&old_entry.point_ids).await {
                    warn!(
                        path = %relative_path,
                        error = %e,
                        "failed to delete old index points"
                    );
                }
            }
        }

        // Index ลง Qdrant
        let mut point_ids = Vec::new();

        if content.len() <= self.max_embed_size {
            // ไฟล์เล็ก — index ทั้งหมดในจุดเดียว
            let vector = self.generate_embedding(&content);
            let mut payload = HashMap::new();
            payload.insert(
                "path".to_string(),
                qdrant_client::qdrant::Value::from(relative_path),
            );
            payload.insert(
                "content_preview".to_string(),
                qdrant_client::qdrant::Value::from(content.chars().take(200).collect::<String>()),
            );
            payload.insert(
                "size".to_string(),
                qdrant_client::qdrant::Value::from(content.len() as i64),
            );

            let ext = Path::new(relative_path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            payload.insert(
                "extension".to_string(),
                qdrant_client::qdrant::Value::from(ext),
            );

            let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, relative_path.as_bytes())
                .to_string();

            self.retry_upsert(&point_id, vector, payload).await?;
            point_ids.push(point_id);
        } else {
            // ไฟล์ใหญ่ — แบ่งเป็น chunks
            let chunks: Vec<&str> = content
                .as_bytes()
                .chunks(self.max_embed_size)
                .filter_map(|chunk| std::str::from_utf8(chunk).ok())
                .collect();

            info!(
                path = %relative_path,
                total_size = content.len(),
                chunk_count = chunks.len(),
                "large file chunked for incremental indexing"
            );

            let mut points = Vec::new();
            for (i, chunk) in chunks.iter().enumerate() {
                let chunk_key = format!("{relative_path}#chunk_{i}");
                let vector = self.generate_embedding(chunk);

                let mut payload = HashMap::new();
                payload.insert(
                    "path".to_string(),
                    qdrant_client::qdrant::Value::from(relative_path),
                );
                payload.insert(
                    "chunk_index".to_string(),
                    qdrant_client::qdrant::Value::from(i as i64),
                );
                payload.insert(
                    "content_preview".to_string(),
                    qdrant_client::qdrant::Value::from(chunk.chars().take(200).collect::<String>()),
                );
                payload.insert(
                    "size".to_string(),
                    qdrant_client::qdrant::Value::from(content.len() as i64),
                );

                let ext = Path::new(relative_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                payload.insert(
                    "extension".to_string(),
                    qdrant_client::qdrant::Value::from(ext),
                );

                let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, chunk_key.as_bytes())
                    .to_string();

                points.push(qdrant_client::qdrant::PointStruct::new(
                    point_id.clone(),
                    vector,
                    payload,
                ));
                point_ids.push(point_id);
            }

            self.retry_upsert_batch(points).await?;
        }

        // อัปเดต manifest
        let entry = IndexManifestEntry {
            path: relative_path.to_string(),
            content_hash,
            last_indexed_mtime: mtime,
            chunk_count: point_ids.len() as u32,
            point_ids,
            file_size: content.len() as u64,
        };

        self.manifest.upsert(entry).await;

        debug!(path = %relative_path, "file indexed successfully");
        Ok(())
    }

    /// ลบ index ของไฟล์ออกจาก Qdrant
    #[instrument(skip(self), fields(path))]
    async fn delete_file_index(&self, relative_path: &str) -> Result<()> {
        if let Some(entry) = self.manifest.get(relative_path).await {
            if !entry.point_ids.is_empty() {
                self.semantic_store
                    .delete_batch(&entry.point_ids)
                    .await
                    .context("failed to delete points from Qdrant")?;
            }
            self.manifest.remove(relative_path).await;
            debug!(path = %relative_path, "file index deleted");
        }
        Ok(())
    }

    /// Scan all files and index changed ones (initial sync)
    #[instrument(skip(self))]
    pub async fn initial_scan(&self) -> Result<(usize, usize)> {
        info!("starting initial scan for incremental indexing");

        let changes = self.detector.scan_all(&self.base_dir).await?;
        let total = changes.len();

        let mut indexed = 0;
        for change in changes {
            match change {
                FileChange::Created { path } | FileChange::Modified { path } => {
                    if let Err(e) = self.index_file(&path).await {
                        warn!(path = %path, error = %e, "failed to index during initial scan");
                    } else {
                        indexed += 1;
                    }
                }
                FileChange::Deleted { path } => {
                    if let Err(e) = self.delete_file_index(&path).await {
                        warn!(path = %path, error = %e, "failed to delete during initial scan");
                    }
                }
            }
        }

        // ตรวจสอบไฟล์ที่ถูกลบ (อยู่ใน manifest แต่ไม่มีในดิสก์)
        let deleted = self.detector.find_deleted(&self.base_dir).await;
        for path in &deleted {
            if let Err(e) = self.delete_file_index(path).await {
                warn!(path = %path, error = %e, "failed to delete stale index");
            }
        }

        // Flush manifest
        self.manifest.flush().await?;

        info!(
            total_scanned = total,
            indexed = indexed,
            deleted = deleted.len(),
            "initial scan complete"
        );

        let _ = self
            .event_tx
            .send(IndexerEvent::ScanComplete {
                total_files: indexed + deleted.len(),
                indexed,
            })
            .await;

        Ok((total, indexed))
    }

    /// Retry upsert with exponential backoff
    async fn retry_upsert(
        &self,
        id: &str,
        vector: Vec<f32>,
        payload: HashMap<String, qdrant_client::qdrant::Value>,
    ) -> Result<()> {
        let mut last_err = None;

        for attempt in 0..MAX_RETRIES {
            match self
                .semantic_store
                .upsert(id, vector.clone(), payload.clone())
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        error = %e,
                        "Qdrant upsert failed, retrying"
                    );
                    last_err = Some(e);
                    if attempt + 1 < MAX_RETRIES {
                        let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry_upsert: no attempts made")))
    }

    /// Retry batch upsert with exponential backoff
    async fn retry_upsert_batch(
        &self,
        points: Vec<qdrant_client::qdrant::PointStruct>,
    ) -> Result<()> {
        let mut last_err = None;

        for attempt in 0..MAX_RETRIES {
            match self.semantic_store.upsert_batch(points.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        attempt = attempt + 1,
                        max_retries = MAX_RETRIES,
                        error = %e,
                        "Qdrant batch upsert failed, retrying"
                    );
                    last_err = Some(e);
                    if attempt + 1 < MAX_RETRIES {
                        let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry_upsert_batch: no attempts made")))
    }

    /// Word-Hash Embedding (same algorithm as fs.rs and nlp.rs)
    fn generate_embedding(&self, text: &str) -> Vec<f32> {
        let mut vector = vec![0.0f32; self.vector_size];
        if text.is_empty() {
            return vector;
        }

        for (i, word) in text.split_whitespace().enumerate() {
            let hash = word.bytes().fold(5381u64, |acc, b| {
                acc.wrapping_shl(5).wrapping_add(acc).wrapping_add(b as u64)
            });
            let idx = (hash as usize) % self.vector_size;
            vector[idx] += 1.0 / (i as f32 + 1.0).sqrt();
        }

        let sum_sq: f32 = vector.iter().map(|x| x * x).sum();
        if sum_sq > 0.0 {
            let norm = sum_sq.sqrt();
            for val in &mut vector {
                *val /= norm;
            }
        }
        vector
    }
}

// ── IncrementalIndexer (main entry point) ─────────────────────────────────

/// ตัวจัดการหลักสำหรับ Incremental Semantic Indexing
/// รวม file watcher, change detector, batch accumulator, และ indexer
pub struct IncrementalIndexer {
    /// manifest store
    manifest: Arc<ManifestStore>,
    /// change channel sender
    change_tx: mpsc::Sender<FileChange>,
    /// event channel receiver
    event_rx: mpsc::Receiver<IndexerEvent>,
    /// task handles สำหรับ cancel
    handles: Vec<JoinHandle<()>>,
}

impl IncrementalIndexer {
    /// สร้าง IncrementalIndexer ใหม่และเริ่มต้น background tasks
    #[instrument(skip(semantic_store))]
    pub async fn start(
        base_dir: &Path,
        semantic_store: Arc<SemanticStore>,
        vector_size: usize,
        batch_window_ms: u64,
        max_batch_size: usize,
    ) -> Result<Self> {
        let manifest = Arc::new(ManifestStore::new(base_dir).await?);

        let (change_tx, change_rx) = mpsc::channel(max_batch_size * 2);
        let (batch_tx, batch_rx) = mpsc::channel(max_batch_size * 2);
        let (event_tx, event_rx) = mpsc::channel(64);

        // Batch accumulator
        let accumulator =
            BatchAccumulator::new(change_rx, batch_tx, batch_window_ms, max_batch_size);

        // Semantic indexer
        let indexer = SemanticIndexer::new(
            base_dir.to_path_buf(),
            semantic_store,
            manifest.clone(),
            batch_rx,
            event_tx,
            vector_size,
        );

        // File watcher
        let watcher_base = base_dir.to_path_buf();
        let watcher_tx = change_tx.clone();

        let mut handles = Vec::new();
        handles.push(tokio::spawn(async move { accumulator.run().await }));
        handles.push(tokio::spawn(async move { indexer.run().await }));
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_file_watcher(&watcher_base, watcher_tx).await {
                error!(error = %e, "file watcher failed");
            }
        }));

        info!(
            base_dir = %base_dir.display(),
            batch_window_ms,
            max_batch_size,
            "incremental indexer started"
        );

        Ok(Self {
            manifest,
            change_tx,
            event_rx,
            handles,
        })
    }

    /// ส่ง file change event เข้าไปใน pipeline
    pub async fn notify_change(&self, change: FileChange) -> Result<()> {
        self.change_tx
            .send(change)
            .await
            .context("failed to send change event")
    }

    /// รับ indexer event ถัดไป
    pub async fn recv_event(&mut self) -> Option<IndexerEvent> {
        self.event_rx.recv().await
    }

    /// คืน reference ถึง manifest store
    #[must_use]
    pub fn manifest(&self) -> &Arc<ManifestStore> {
        &self.manifest
    }

    /// หยุด indexer ทั้งหมด
    pub async fn shutdown(self) {
        // ปิด change channel เพื่อให้ batch accumulator หยุด
        drop(self.change_tx);

        // รอให้ tasks หยุด
        for handle in self.handles {
            handle.abort();
        }

        // Flush manifest
        if let Err(e) = self.manifest.flush().await {
            error!(error = %e, "failed to flush manifest on shutdown");
        }

        info!("incremental indexer shut down");
    }
}

// ── File Watcher ──────────────────────────────────────────────────────────

/// เริ่มต้น file watcher โดยใช้ notify crate (inotify on Linux)
async fn run_file_watcher(base_dir: &Path, change_tx: mpsc::Sender<FileChange>) -> Result<()> {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

    let mut watcher =
        RecommendedWatcher::new(tx, Config::default()).context("failed to create file watcher")?;

    watcher
        .watch(base_dir, RecursiveMode::Recursive)
        .context("failed to watch base directory")?;

    info!(path = %base_dir.display(), "file watcher started");

    // Spawn blocking task for file watcher events
    let tokio_tx = change_tx.clone();
    let base = base_dir.to_path_buf();

    tokio::task::spawn_blocking(move || {
        while let Ok(event_result) = rx.recv() {
            match event_result {
                Ok(event) => {
                    let change = match event.kind {
                        EventKind::Create(_) => {
                            // หา path ที่เกี่ยวข้อง
                            if let Some(path) = event.paths.first() {
                                let relative = path
                                    .strip_prefix(&base)
                                    .unwrap_or(path)
                                    .to_string_lossy()
                                    .into_owned();

                                // ข้ามไฟล์ manifest และไฟล์ temp
                                if relative.ends_with(".json.tmp")
                                    || relative.contains("index_manifest")
                                {
                                    continue;
                                }

                                Some(FileChange::Created { path: relative })
                            } else {
                                None
                            }
                        }
                        EventKind::Modify(_) => {
                            if let Some(path) = event.paths.first() {
                                let relative = path
                                    .strip_prefix(&base)
                                    .unwrap_or(path)
                                    .to_string_lossy()
                                    .into_owned();

                                if relative.ends_with(".json.tmp")
                                    || relative.contains("index_manifest")
                                {
                                    continue;
                                }

                                Some(FileChange::Modified { path: relative })
                            } else {
                                None
                            }
                        }
                        EventKind::Remove(_) => {
                            if let Some(path) = event.paths.first() {
                                let relative = path
                                    .strip_prefix(&base)
                                    .unwrap_or(path)
                                    .to_string_lossy()
                                    .into_owned();

                                Some(FileChange::Deleted { path: relative })
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some(change) = change {
                        if let Err(e) = tokio_tx.blocking_send(change) {
                            warn!(error = %e, "failed to send change from watcher");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "file watcher event error");
                }
            }
        }
    });

    // Keep watcher alive
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_hash_deterministic() {
        let content = b"hello world";
        let hash1 = ChangeDetector::compute_hash(content);
        let hash2 = ChangeDetector::compute_hash(content);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn compute_hash_different_for_different_content() {
        let hash1 = ChangeDetector::compute_hash(b"content A");
        let hash2 = ChangeDetector::compute_hash(b"content B");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn manifest_entry_serialization_roundtrip() {
        let entry = IndexManifestEntry {
            path: "test/file.rs".to_string(),
            content_hash: [1u8; 32],
            last_indexed_mtime: SystemTime::now(),
            chunk_count: 2,
            point_ids: vec!["id-1".to_string(), "id-2".to_string()],
            file_size: 1024,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: IndexManifestEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.path, entry.path);
        assert_eq!(parsed.content_hash, entry.content_hash);
        assert_eq!(parsed.chunk_count, entry.chunk_count);
        assert_eq!(parsed.point_ids, entry.point_ids);
        assert_eq!(parsed.file_size, entry.file_size);
    }

    #[tokio::test]
    async fn manifest_store_operations() {
        let temp_dir =
            std::env::temp_dir().join(format!("ank-manifest-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let store = ManifestStore::new(&temp_dir).await.unwrap();

        // Upsert
        let entry = IndexManifestEntry {
            path: "test.rs".to_string(),
            content_hash: [2u8; 32],
            last_indexed_mtime: SystemTime::now(),
            chunk_count: 1,
            point_ids: vec!["point-1".to_string()],
            file_size: 512,
        };
        store.upsert(entry.clone()).await;

        // Get
        let retrieved = store.get("test.rs").await.unwrap();
        assert_eq!(retrieved.path, "test.rs");
        assert_eq!(retrieved.content_hash, [2u8; 32]);

        // All paths
        let paths = store.all_paths().await;
        assert!(paths.contains(&"test.rs".to_string()));

        // Remove
        store.remove("test.rs").await;
        assert!(store.get("test.rs").await.is_none());

        // Flush
        store.flush().await.unwrap();

        // Reload from disk
        let reloaded = ManifestStore::new(&temp_dir).await.unwrap();
        assert!(reloaded.get("test.rs").await.is_none());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn manifest_store_flush_and_reload() {
        let temp_dir =
            std::env::temp_dir().join(format!("ank-manifest-flush-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        {
            let store = ManifestStore::new(&temp_dir).await.unwrap();
            let entry = IndexManifestEntry {
                path: "persist.rs".to_string(),
                content_hash: [3u8; 32],
                last_indexed_mtime: SystemTime::now(),
                chunk_count: 1,
                point_ids: vec!["p-1".to_string()],
                file_size: 256,
            };
            store.upsert(entry).await;
            store.flush().await.unwrap();
        }

        // Reload
        let store2 = ManifestStore::new(&temp_dir).await.unwrap();
        let entry = store2.get("persist.rs").await.unwrap();
        assert_eq!(entry.path, "persist.rs");
        assert_eq!(entry.content_hash, [3u8; 32]);

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[test]
    fn generate_embedding_produces_unit_vector() {
        let temp_dir =
            std::env::temp_dir().join(format!("ank-indexer-emb-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SemanticStore::test_instance("test"));
        let manifest = Arc::new(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(ManifestStore::new(&temp_dir))
                .unwrap(),
        );

        let indexer = SemanticIndexer::new(
            temp_dir.clone(),
            store,
            manifest,
            mpsc::channel(1).1,
            mpsc::channel(1).0,
            32,
        );

        let v = indexer.generate_embedding("hello world test");
        let sum_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!(
            (sum_sq - 1.0).abs() < 1e-5,
            "embedding should be unit vector, got norm² = {sum_sq}"
        );

        let _ = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(tokio::fs::remove_dir_all(&temp_dir));
    }

    #[tokio::test]
    async fn batch_accumulator_collects_and_batches() {
        let (change_tx, change_rx) = mpsc::channel(16);
        let (batch_tx, mut batch_rx) = mpsc::channel(16);

        let accumulator = BatchAccumulator::new(change_rx, batch_tx, 100, 5);

        tokio::spawn(async move { accumulator.run().await });

        // Send changes
        for i in 0..3 {
            change_tx
                .send(FileChange::Created {
                    path: format!("file-{i}.txt"),
                })
                .await
                .unwrap();
        }

        // Wait for batch window
        tokio::time::sleep(Duration::from_millis(150)).await;

        let batch = batch_rx.recv().await.unwrap();
        assert_eq!(batch.len(), 3);
    }

    #[tokio::test]
    async fn batch_accumulator_triggers_on_max_size() {
        let (change_tx, change_rx) = mpsc::channel(16);
        let (batch_tx, mut batch_rx) = mpsc::channel(16);

        let accumulator = BatchAccumulator::new(change_rx, batch_tx, 5000, 3);

        tokio::spawn(async move { accumulator.run().await });

        // Send changes up to max batch size
        for i in 0..3 {
            change_tx
                .send(FileChange::Created {
                    path: format!("file-{i}.txt"),
                })
                .await
                .unwrap();
        }

        // Should get batch immediately (no need to wait for window)
        let batch = batch_rx.recv().await.unwrap();
        assert_eq!(batch.len(), 3);
    }
}
