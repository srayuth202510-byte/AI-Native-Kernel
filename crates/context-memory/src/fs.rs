use crate::semantic::SemanticStore;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::time::timeout;
use tracing::{info, instrument, warn};

const SFS_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// ขนาดสูงสุดของไฟล์ที่จะ embedding ทั้งหมดใน vector เดียว (bytes)
/// ไฟล์ที่ใหญ่กว่าจะถูกแบ่งเป็น chunks
const MAX_SINGLE_EMBED_SIZE: usize = 8192;

/// ตัวแทนของข้อมูลไฟล์ในระบบ Semantic File System
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticFile {
    /// ที่อยู่ไฟล์สัมพันธ์กับ base_dir (e.g., "docs/ai_kernel.txt")
    pub path: String,
    /// เนื้อหาในไฟล์
    pub content: String,
    /// ขนาดไฟล์ในหน่วยไบต์
    pub size: u64,
}

/// ข้อมูล metadata ของไฟล์ (ไม่รวม content)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// พาธเต็มของไฟล์
    pub path: String,
    /// ขนาดไฟล์ในหน่วยไบต์
    pub size: u64,
    /// นามสกุลไฟล์ (ไม่รวมจุด)
    pub extension: String,
}

/// ระบบจัดการไฟล์อัจฉริยะ (Semantic File System)
/// จัดเก็บไฟล์ลงดิสก์จริงและทำดัชนี (Indexing) ใน Qdrant Vector Store เพื่อค้นหาตามความหมาย
pub struct SemanticFileSystem {
    /// ไดเรกทอรีหลักในการจัดเก็บไฟล์จริง
    base_dir: PathBuf,
    /// ตัวจัดการพื้นที่เก็บเวกเตอร์
    semantic_store: Arc<SemanticStore>,
    /// มิติของเวกเตอร์จำลอง (Embedding size)
    vector_size: usize,
}

impl SemanticFileSystem {
    /// สร้างอินสแตนซ์ของ SemanticFileSystem
    #[instrument(skip(semantic_store), fields(base_dir = %base_dir.as_ref().display()))]
    pub async fn new<P: AsRef<Path>>(
        base_dir: P,
        semantic_store: Arc<SemanticStore>,
        vector_size: usize,
    ) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        timeout(SFS_IO_TIMEOUT, tokio_fs::create_dir_all(&base_dir))
            .await
            .context("SFS: base directory creation timeout")?
            .context("Failed to create base directory for SFS")?;

        Ok(Self {
            base_dir,
            semantic_store,
            vector_size,
        })
    }

    /// เขียนไฟล์ลงดิสก์โดยไม่ sync index (สำหรับ IncrementalIndexer)
    /// ไฟล์จะถูก index โดย background indexer เมื่อมี file change event
    #[instrument(skip(self, content), fields(path = %relative_path))]
    pub async fn write_file_async(&self, relative_path: &str, content: &str) -> Result<()> {
        let file_path = self.base_dir.join(relative_path);

        // 1. ตรวจสอบและสร้างโฟลเดอร์สำหรับไฟล์ย่อย
        if let Some(parent) = file_path.parent() {
            timeout(SFS_IO_TIMEOUT, tokio_fs::create_dir_all(parent))
                .await
                .context("SFS: parent directory creation timeout")?
                .context("Failed to create parent directories for file")?;
        }

        // 2. เขียนไฟล์จริงลงดิสก์ (ไม่ index — ปล่อยให้ IncrementalIndexer จัดการ)
        timeout(SFS_IO_TIMEOUT, tokio_fs::write(&file_path, content))
            .await
            .context("SFS: file write timeout")?
            .context("Failed to write physical file content")?;

        Ok(())
    }

    /// เขียนไฟล์ลงดิสก์และส่งข้อมูล Embedding ไปเก็บใน Qdrant
    /// สำหรับไฟล์ขนาดใหญ่ (> MAX_SINGLE_EMBED_SIZE) จะแบ่งเป็น chunks หลายจุด
    #[instrument(skip(self, content), fields(path = %relative_path))]
    pub async fn write_file(&self, relative_path: &str, content: &str) -> Result<()> {
        let file_path = self.base_dir.join(relative_path);

        // 1. ตรวจสอบและสร้างโฟลเดอร์สำหรับไฟล์ย่อย
        if let Some(parent) = file_path.parent() {
            timeout(SFS_IO_TIMEOUT, tokio_fs::create_dir_all(parent))
                .await
                .context("SFS: parent directory creation timeout")?
                .context("Failed to create parent directories for file")?;
        }

        // 2. เขียนไฟล์จริงลงดิสก์
        timeout(SFS_IO_TIMEOUT, tokio_fs::write(&file_path, content))
            .await
            .context("SFS: file write timeout")?
            .context("Failed to write physical file content")?;

        // 3. Index ลง Qdrant (รองรับ chunking สำหรับไฟล์ใหญ่)
        self.index_content(relative_path, content).await?;

        Ok(())
    }

    /// อ่านเนื้อหาไฟล์เต็มจากดิสก์
    #[instrument(skip(self), fields(path = %relative_path))]
    pub async fn read_file(&self, relative_path: &str) -> Result<String> {
        let file_path = self.base_dir.join(relative_path);
        let content = timeout(SFS_IO_TIMEOUT, tokio_fs::read_to_string(&file_path))
            .await
            .context("SFS: file read timeout")?
            .context("Failed to read file from disk")?;
        Ok(content)
    }

    /// ลบไฟล์ออกจากดิสก์ และลบจุดเชื่อมโยงใน Qdrant
    #[instrument(skip(self), fields(path = %relative_path))]
    pub async fn delete_file(&self, relative_path: &str) -> Result<()> {
        let file_path = self.base_dir.join(relative_path);
        if file_path.exists() {
            timeout(SFS_IO_TIMEOUT, tokio_fs::remove_file(&file_path))
                .await
                .context("SFS: file remove timeout")?
                .context("Failed to remove file from disk")?;
        }

        // ลบ Index ออกจาก Qdrant — log warning แต่ไม่ fail ถ้า Qdrant ไม่พร้อม
        let point_id =
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, relative_path.as_bytes()).to_string();
        if let Err(e) = self.semantic_store.delete(&point_id).await {
            warn!(
                path = relative_path,
                error = %e,
                "Failed to delete Qdrant index (file already removed from disk)"
            );
        }

        Ok(())
    }

    /// ค้นหาไฟล์ตามความหมายและคืนค่าผลลัพธ์เป็นรายการ Path ของไฟล์
    #[instrument(skip(self), fields(query_len = query_text.len()))]
    pub async fn search_paths(&self, query_text: &str, limit: usize) -> Result<Vec<String>> {
        let query_vector = self.generate_embedding(query_text);
        let results = self
            .semantic_store
            .search_metadata(query_vector, limit as u64)
            .await?;

        let mut paths = Vec::new();
        for (_id, metadata) in results {
            if let Some(path) = metadata.get("path") {
                paths.push(path.clone());
            }
        }
        Ok(paths)
    }

    /// ค้นหาไฟล์ตามความหมาย และดึงเนื้อหาจริงจากดิสก์มารวมไว้เป็นรายการ SemanticFile
    #[instrument(skip(self), fields(query_len = query_text.len()))]
    pub async fn search_files(&self, query_text: &str, limit: usize) -> Result<Vec<SemanticFile>> {
        let paths = self.search_paths(query_text, limit).await?;
        let mut files = Vec::new();

        for path in paths {
            if let Ok(content) = self.read_file(&path).await {
                let size = content.len() as u64;
                files.push(SemanticFile {
                    path,
                    content,
                    size,
                });
            }
        }

        Ok(files)
    }

    /// ค้นหาไฟล์แบบกรองตามนามสกุลไฟล์
    #[instrument(skip(self), fields(extension = %extension))]
    pub async fn search_by_extension(
        &self,
        extension: &str,
        limit: usize,
    ) -> Result<Vec<FileMetadata>> {
        let results = self
            .semantic_store
            .search_filtered(
                vec![0.0; self.vector_size], // dummy vector — filter only
                limit as u64,
                "extension",
                extension,
            )
            .await?;

        let mut files = Vec::new();
        for (_id, metadata) in super::semantic::extract_metadata_from_points(results) {
            if let Some(path) = metadata.get("path") {
                let size = metadata
                    .get("size")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let ext = metadata.get("extension").cloned().unwrap_or_default();
                files.push(FileMetadata {
                    path: path.clone(),
                    size,
                    extension: ext,
                });
            }
        }
        Ok(files)
    }

    /// แสดงรายการไฟล์ทั้งหมดในไดเรกทอรี (recursive)
    #[instrument(skip(self))]
    pub async fn list_files(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();
        self.walk_dir(&self.base_dir, &mut files).await?;
        // Convert to relative paths
        let relative: Vec<String> = files
            .iter()
            .filter_map(|p| p.strip_prefix(&self.base_dir).ok())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        Ok(relative)
    }

    /// แสดงรายการไฟล์ในไดเรกทอรีย่อย (ไม่ recursive)
    #[instrument(skip(self), fields(dir = %relative_dir))]
    pub async fn list_dir(&self, relative_dir: &str) -> Result<Vec<String>> {
        let dir_path = self.base_dir.join(relative_dir);
        let mut entries = Vec::new();

        let mut dir = timeout(SFS_IO_TIMEOUT, tokio_fs::read_dir(&dir_path))
            .await
            .context("SFS: read_dir timeout")?
            .context("Failed to read directory")?;

        while let Some(entry) = dir.next_entry().await.context("SFS: next_entry timeout")? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry
                .file_type()
                .await
                .context("SFS: file_type timeout")?
                .is_dir()
            {
                entries.push(format!("{name}/"));
            } else {
                entries.push(name);
            }
        }

        entries.sort();
        Ok(entries)
    }

    /// นับจำนวนไฟล์ทั้งหมด
    pub async fn count_files(&self) -> Result<usize> {
        let files = self.list_files().await?;
        Ok(files.len())
    }

    /// Index content ลง Qdrant — รองรับ chunking สำหรับไฟล์ใหญ่
    async fn index_content(&self, relative_path: &str, content: &str) -> Result<()> {
        if content.len() <= MAX_SINGLE_EMBED_SIZE {
            // ไฟล์เล็ก — index ทั้งหมดในจุดเดียว
            let vector = self.generate_embedding(content);
            let mut payload: HashMap<String, qdrant_client::qdrant::Value> = HashMap::new();
            payload.insert("path".to_string(), relative_path.to_string().into());
            payload.insert(
                "content_preview".to_string(),
                content.chars().take(200).collect::<String>().into(),
            );
            payload.insert("size".to_string(), (content.len() as i64).into());

            let ext = Path::new(relative_path)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");
            payload.insert("extension".to_string(), ext.to_string().into());

            let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, relative_path.as_bytes())
                .to_string();
            self.semantic_store
                .upsert(&point_id, vector, payload)
                .await
                .context("Failed to upsert file index to Qdrant")?;
        } else {
            // ไฟล์ใหญ่ — แบ่งเป็น chunks
            let chunks: Vec<&str> = content
                .as_bytes()
                .chunks(MAX_SINGLE_EMBED_SIZE)
                .filter_map(|chunk| std::str::from_utf8(chunk).ok())
                .collect();

            info!(
                path = relative_path,
                total_size = content.len(),
                chunk_count = chunks.len(),
                "Large file chunked for semantic indexing"
            );

            let mut points = Vec::new();
            for (i, chunk) in chunks.iter().enumerate() {
                let chunk_key = format!("{relative_path}#chunk_{i}");
                let vector = self.generate_embedding(chunk);

                let mut payload: HashMap<String, qdrant_client::qdrant::Value> = HashMap::new();
                payload.insert("path".to_string(), relative_path.to_string().into());
                payload.insert("chunk_index".to_string(), (i as i64).into());
                payload.insert(
                    "content_preview".to_string(),
                    chunk.chars().take(200).collect::<String>().into(),
                );
                payload.insert("size".to_string(), (content.len() as i64).into());

                let ext = Path::new(relative_path)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                payload.insert("extension".to_string(), ext.to_string().into());

                let point_id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, chunk_key.as_bytes())
                    .to_string();

                points.push(qdrant_client::qdrant::PointStruct::new(
                    point_id, vector, payload,
                ));
            }

            self.semantic_store
                .upsert_batch(points)
                .await
                .context("Failed to batch upsert file chunks to Qdrant")?;
        }
        Ok(())
    }

    /// Recursive directory walker
    async fn walk_dir(&self, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        let mut entries = timeout(SFS_IO_TIMEOUT, tokio_fs::read_dir(dir))
            .await
            .context("SFS: walk_dir read_dir timeout")?
            .context("Failed to read directory for walking")?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .context("SFS: walk_dir next_entry timeout")?
        {
            let path = entry.path();
            if entry
                .file_type()
                .await
                .context("SFS: walk_dir file_type timeout")?
                .is_dir()
            {
                Box::pin(self.walk_dir(&path, files)).await?;
            } else {
                files.push(path);
            }
        }
        Ok(())
    }

    /// อัลกอริทึม Word-Hash Embedding อย่างง่ายเพื่อแปลงข้อความเป็นเวกเตอร์มิติคงที่ (Unit Vector)
    fn generate_embedding(&self, text: &str) -> Vec<f32> {
        let mut vector = vec![0.0f32; self.vector_size];
        if text.is_empty() {
            return vector;
        }

        for (i, word) in text.split_whitespace().enumerate() {
            // djb2 hash algorithm
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn qdrant_url() -> String {
        env::var("QDRANT_URL").unwrap_or_else(|_| "http://localhost:6334".to_string())
    }

    fn qdrant_host_port() -> (String, u16) {
        if let Ok(url) = env::var("QDRANT_URL") {
            let trimmed = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let host_port = trimmed.split('/').next().unwrap_or("localhost:6334");
            let mut parts = host_port.split(':');
            let host = parts.next().unwrap_or("localhost").to_string();
            let port = parts
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(6334);
            return (host, port);
        }

        let host = env::var("QDRANT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env::var("QDRANT_PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(6334);
        (host, port)
    }

    async fn check_qdrant_online() -> bool {
        let (host, port) = qdrant_host_port();
        tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .is_ok()
    }

    // ── SemanticFile unit tests ────────────────────────────────────

    #[test]
    fn semantic_file_construction() {
        let f = SemanticFile {
            path: "docs/test.txt".into(),
            content: "hello world".into(),
            size: 11,
        };
        assert_eq!(f.path, "docs/test.txt");
        assert_eq!(f.content, "hello world");
        assert_eq!(f.size, 11);
    }

    #[test]
    fn semantic_file_ordering_independent() {
        let a = SemanticFile {
            path: "a.txt".into(),
            content: "aaa".into(),
            size: 3,
        };
        let b = SemanticFile {
            path: "b.txt".into(),
            content: "bbb".into(),
            size: 3,
        };
        assert_ne!(a, b);
        assert_eq!(a, a.clone());
    }

    // ── generate_embedding unit tests (pure, no Qdrant) ────────────
    fn make_sfs(vector_size: usize) -> SemanticFileSystem {
        let temp_dir = std::env::temp_dir().join(format!("ank-sfs-emb-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SemanticStore::test_instance("test"));
        SemanticFileSystem {
            base_dir: temp_dir,
            semantic_store: store,
            vector_size,
        }
    }

    #[tokio::test]
    async fn new_creates_base_directory() {
        let temp_dir = std::env::temp_dir().join(format!("ank-sfs-new-{}", uuid::Uuid::new_v4()));
        assert!(!temp_dir.exists(), "temp dir should not exist yet");
        let store = Arc::new(SemanticStore::test_instance("test"));
        let sfs = SemanticFileSystem::new(&temp_dir, store, 4).await.unwrap();
        assert!(temp_dir.exists(), "base_dir should be created by new()");
        assert_eq!(sfs.vector_size, 4);
        let _ = tokio_fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn generate_embedding_has_correct_length() {
        let sfs = make_sfs(8);
        let v = sfs.generate_embedding("hello world");
        assert_eq!(v.len(), 8);
    }

    #[tokio::test]
    async fn generate_embedding_empty_text_returns_zeros() {
        let sfs = make_sfs(4);
        let v = sfs.generate_embedding("");
        assert_eq!(v, vec![0.0f32; 4]);
    }

    #[tokio::test]
    async fn generate_embedding_single_word_is_unit_vector() {
        let sfs = make_sfs(16);
        let v = sfs.generate_embedding("rust");
        let sum_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!(
            (sum_sq - 1.0).abs() < 1e-5,
            "norm squared should be 1.0, got {sum_sq}"
        );
    }

    #[tokio::test]
    async fn generate_embedding_multi_word_is_unit_vector() {
        let sfs = make_sfs(16);
        let v = sfs.generate_embedding("the quick brown fox");
        let sum_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!(
            (sum_sq - 1.0).abs() < 1e-5,
            "norm squared should be 1.0, got {sum_sq}"
        );
    }

    #[tokio::test]
    async fn generate_embedding_deterministic() {
        let sfs = make_sfs(32);
        let text = "same text every time";
        let v1 = sfs.generate_embedding(text);
        let v2 = sfs.generate_embedding(text);
        assert_eq!(v1, v2, "embedding should be deterministic");
    }

    #[tokio::test]
    async fn generate_embedding_different_texts_differ() {
        let sfs = make_sfs(32);
        let v1 = sfs.generate_embedding("hello world");
        let v2 = sfs.generate_embedding("goodbye world");
        assert_ne!(
            v1, v2,
            "different texts should produce different embeddings"
        );
    }

    #[tokio::test]
    async fn generate_embedding_large_text() {
        let sfs = make_sfs(64);
        let text = "word ".repeat(1000);
        let v = sfs.generate_embedding(&text);
        let sum_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!(
            (sum_sq - 1.0).abs() < 1e-5,
            "norm should be 1.0 even for large text"
        );
    }

    // ── list_dir unit test (no Qdrant) ─────────────────────────────

    #[tokio::test]
    async fn list_dir_returns_sorted_entries() {
        let temp_dir = std::env::temp_dir().join(format!("ank-sfs-list-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SemanticStore::test_instance("test"));
        let sfs = SemanticFileSystem::new(&temp_dir, store, 8).await.unwrap();

        // Create some files
        tokio_fs::write(temp_dir.join("beta.txt"), "b")
            .await
            .unwrap();
        tokio_fs::write(temp_dir.join("alpha.txt"), "a")
            .await
            .unwrap();
        tokio_fs::create_dir(temp_dir.join("subdir")).await.unwrap();

        let entries = sfs.list_dir(".").await.unwrap();
        assert_eq!(entries, vec!["alpha.txt", "beta.txt", "subdir/"]);

        let _ = tokio_fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn list_files_returns_all_files_recursive() {
        let temp_dir = std::env::temp_dir().join(format!("ank-sfs-walk-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SemanticStore::test_instance("test"));
        let sfs = SemanticFileSystem::new(&temp_dir, store, 8).await.unwrap();

        tokio_fs::write(temp_dir.join("root.txt"), "r")
            .await
            .unwrap();
        tokio_fs::create_dir(temp_dir.join("sub")).await.unwrap();
        tokio_fs::write(temp_dir.join("sub/nested.txt"), "n")
            .await
            .unwrap();

        let mut files = sfs.list_files().await.unwrap();
        files.sort();
        assert_eq!(files, vec!["root.txt", "sub/nested.txt"]);

        let _ = tokio_fs::remove_dir_all(&temp_dir).await;
    }

    // ── Integration tests (require Qdrant) ─────────────────────────

    #[tokio::test]
    #[ignore = "requires a reachable Qdrant endpoint"]
    async fn test_semantic_file_system_operations() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping SFS test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let temp_dir = std::env::temp_dir().join(format!("ank-sfs-{}", uuid::Uuid::new_v4()));
        let store = Arc::new(SemanticStore::new(&qdrant_url(), "ank_sfs_test", 128).await?);
        let sfs = SemanticFileSystem::new(&temp_dir, store, 128).await?;

        sfs.write_file(
            "notes/ai.txt",
            "Artificial Intelligence and Kernel integration rules",
        )
        .await?;
        sfs.write_file(
            "notes/recipes.txt",
            "Delicious chocolate cake recipe ingredients",
        )
        .await?;

        let paths = sfs
            .search_paths("deep neural networks and OS design", 1)
            .await?;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "notes/ai.txt");

        let content = sfs.read_file("notes/recipes.txt").await?;
        assert!(content.contains("chocolate"));

        sfs.delete_file("notes/recipes.txt").await?;
        let search_res = sfs.search_paths("cake", 2).await?;
        assert!(!search_res.contains(&"notes/recipes.txt".to_string()));

        let _ = tokio_fs::remove_dir_all(temp_dir).await;
        Ok(())
    }
}
