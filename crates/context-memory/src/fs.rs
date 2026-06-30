use crate::semantic::SemanticStore;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs as tokio_fs;
use tokio::time::timeout;

const SFS_IO_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// เขียนไฟล์ลงดิสก์และส่งข้อมูล Embedding ไปเก็บใน Qdrant
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

        // 3. คำนวณ Embedding เวกเตอร์อย่างง่ายจากคำศัพท์ (Simple Keyword Hash Embedder)
        let vector = self.generate_embedding(content);

        // 4. เตรียม Payload ข้อมูลไฟล์
        let mut payload = HashMap::new();
        payload.insert("path".to_string(), relative_path.to_string().into());
        payload.insert(
            "content_preview".to_string(),
            content.chars().take(200).collect::<String>().into(),
        );
        payload.insert("size".to_string(), (content.len() as i64).into());

        // 5. บันทึก/อัปเดตเวกเตอร์ลงใน Qdrant
        let point_id =
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, relative_path.as_bytes()).to_string();
        self.semantic_store
            .upsert(&point_id, vector, payload)
            .await
            .context("Failed to upsert file index to Qdrant")?;

        Ok(())
    }

    /// อ่านเนื้อหาไฟล์เต็มจากดิสก์
    pub async fn read_file(&self, relative_path: &str) -> Result<String> {
        let file_path = self.base_dir.join(relative_path);
        let content = timeout(SFS_IO_TIMEOUT, tokio_fs::read_to_string(&file_path))
            .await
            .context("SFS: file read timeout")?
            .context("Failed to read file from disk")?;
        Ok(content)
    }

    /// ลบไฟล์ออกจากดิสก์ และลบจุดเชื่อมโยงใน Qdrant
    pub async fn delete_file(&self, relative_path: &str) -> Result<()> {
        let file_path = self.base_dir.join(relative_path);
        if file_path.exists() {
            timeout(SFS_IO_TIMEOUT, tokio_fs::remove_file(&file_path))
                .await
                .context("SFS: file remove timeout")?
                .context("Failed to remove file from disk")?;
        }

        // ลบ Index ออกจาก Qdrant
        let point_id =
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, relative_path.as_bytes()).to_string();
        let _ = self.semantic_store.delete(&point_id).await;

        Ok(())
    }

    /// ค้นหาไฟล์ตามความหมายและคืนค่าผลลัพธ์เป็นรายการ Path ของไฟล์
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
        // PartialEq/Eq — different paths should not be equal
        assert_ne!(a, b);
        // Clone should produce equal copy
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
        // Should be ≈ 1.0 (normalized)
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

    // ── Integration tests (require Qdrant) ─────────────────────────

    #[tokio::test]
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

        // 1. เขียนไฟล์
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

        // 2. ค้นหาไฟล์ตามความหมาย
        let paths = sfs
            .search_paths("deep neural networks and OS design", 1)
            .await?;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "notes/ai.txt");

        // 3. อ่านไฟล์
        let content = sfs.read_file("notes/recipes.txt").await?;
        assert!(content.contains("chocolate"));

        // 4. ลบไฟล์และดัชนี
        sfs.delete_file("notes/recipes.txt").await?;
        let search_res = sfs.search_paths("cake", 2).await?;
        // ค้นหาเจอแค่ ai.txt หรือไม่เจออะไรที่เกี่ยวกับเค้กแล้ว
        assert!(!search_res.contains(&"notes/recipes.txt".to_string()));

        // เคลียร์ directory
        let _ = tokio_fs::remove_dir_all(temp_dir).await;
        Ok(())
    }
}
