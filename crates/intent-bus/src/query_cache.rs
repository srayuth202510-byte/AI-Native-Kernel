#![deny(unsafe_code)]

//! Semantic Query Cache — แคชผลลัพธ์จากข้อคำถามภาษาธรรมชาติ (NL)
//! จดจำและจัดเก็บผลลัพธ์จากข้อคำถามที่มีเจตนาคล้ายคลึงกัน
//! เพื่อลดภาระการวิเคราะห์ Intent ของ Agent Scheduler

use crate::{Intent, IntentType};
use lru::LruCache;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

/// ขนาดเริ่มต้นของ Query Cache (จำนวน entries สูงสุด)
const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// TTL เริ่มต้นของ cache entries (5 นาที)
const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// ค่า threshold สำหรับ similarity detection (cosine similarity)
const DEFAULT_SIMILARITY_THRESHOLD: f32 = 0.85;

/// มิติของเวกเตอร์สำหรับ similarity detection
const VECTOR_SIZE: usize = 128;

/// รายการ stopwords ที่ถูกตัดออกระหว่าง normalization
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can", "to",
    "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "out", "off", "over", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why", "how", "all", "each",
    "every", "both", "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only",
    "own", "same", "so", "than", "too", "very", "just", "because", "but", "and", "or", "if",
    "while", "that", "this", "it", "its", "i", "me", "my", "we", "our", "you", "your", "he", "him",
    "his", "she", "her", "they", "them", "their", "what", "which", "who", "whom",
];

/// คีย์สำหรับ Query Cache — ประกอบด้วย normalized text และ intent type
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct QueryCacheKey {
    /// ข้อความที่ผ่านการ normalization แล้ว (lowercase, stopwords removed)
    pub normalized_text: String,
    /// ประเภทของ Intent
    pub intent_type: IntentType,
}

impl QueryCacheKey {
    /// สร้าง CacheKey จาก NL text และ intent type
    pub fn new(text: &str, intent_type: IntentType) -> Self {
        Self {
            normalized_text: normalize_query(text),
            intent_type,
        }
    }

    /// สร้าง SHA-256 hash ของ key สำหรับ efficient comparison
    pub fn hash_bytes(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.normalized_text.as_bytes());
        hasher.update([self.intent_type as u8]);
        hasher.finalize().into()
    }
}

/// ผลลัพธ์ที่ถูก cache ไว้
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Intent ที่ถูก parse แล้ว (command intent ที่ Resolver สร้างขึ้น)
    pub parsed_intent: Intent,
    /// ข้อมูลผลลัพธ์ (serialized search results)
    pub response_data: Vec<u8>,
    /// เวลาที่สร้าง entry นี้
    pub created_at: Instant,
    /// จำนวนครั้งที่ถูก hit
    pub hit_count: Arc<AtomicU64>,
}

impl CacheEntry {
    /// ตรวจสอบว่า entry หมดอายุหรือยัง
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }

    /// เพิ่ม hit count
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Relaxed);
    }

    /// คืนค่า hit count ปัจจุบัน
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hit_count.load(Ordering::Relaxed)
    }
}

/// สถานะของ Query Cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// จำนวน entries ปัจจุบัน
    pub size: usize,
    /// ความจุสูงสุด
    pub capacity: usize,
    /// จำนวนครั้งที่ hit
    pub total_hits: u64,
    /// จำนวนครั้งที่ miss
    pub total_misses: u64,
    /// อัตรา hit ratio
    pub hit_ratio: f64,
}

/// ข้อผิดพลาดที่เกี่ยวข้องกับ Query Cache
#[derive(Debug, thiserror::Error)]
pub enum QueryCacheError {
    /// ไม่พบ entry สำหรับ query นี้ใน cache
    #[error("cache entry not found")]
    NotFound,

    /// cache เต็มและไม่สามารถ evict เพื่อรับ entry ใหม่ได้
    #[error("cache is full and cannot accept new entries")]
    CacheFull,

    /// cache ถูกปิดการใช้งานอยู่
    #[error("cache is disabled")]
    Disabled,
}

/// เหตุการณ์การ invalidation ของ cache
#[derive(Debug, Clone)]
pub enum CacheInvalidation {
    /// มีไฟล์ถูก index ใหม่ — ต้องลบ cache entries ที่เกี่ยวข้อง
    FileIndexed {
        /// รายการพาธของไฟล์ที่ถูก index ใหม่
        paths: Vec<String>,
    },
    /// มีไฟล์ถูกลบ — ต้องลบ cache entries ที่มีผลลัพธ์อ้างอิงไฟล์นี้
    FileDeleted {
        /// พาธของไฟล์ที่ถูกลบ
        path: String,
    },
    /// ล้าง cache ทั้งหมด
    FullClear,
}

/// Semantic Query Cache — ระบบแคชผลลัพธ์จากข้อคำถามภาษาธรรมชาติ
///
/// จดจำและจัดเก็บผลลัพธ์จากข้อคำถามที่มีเจตนาคล้ายคลึงกัน
/// ใช้ LRU cache พร้อม TTL-based expiration และ similarity detection
pub struct SemanticQueryCache {
    /// LRU Cache หลัก
    cache: Arc<RwLock<LruCache<QueryCacheKey, CacheEntry>>>,
    /// TTL สำหรับ cache entries
    ttl: Duration,
    /// Similarity threshold สำหรับ finding similar cached queries
    similarity_threshold: f32,
    /// ตัวนับ hit/miss
    total_hits: Arc<AtomicU64>,
    total_misses: Arc<AtomicU64>,
}

impl SemanticQueryCache {
    /// สร้าง Semantic Query Cache ด้วยค่าเริ่มต้น
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CACHE_CAPACITY)
    }

    /// สร้าง Semantic Query Cache ด้วยความจุที่กำหนด
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_config(capacity, DEFAULT_TTL, DEFAULT_SIMILARITY_THRESHOLD)
    }

    /// สร้าง Semantic Query Cache ด้วยค่าที่กำหนดเองทั้งหมด
    #[must_use]
    pub fn with_config(capacity: usize, ttl: Duration, similarity_threshold: f32) -> Self {
        let cache_size = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            ttl,
            similarity_threshold,
            total_hits: Arc::new(AtomicU64::new(0)),
            total_misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// ดึงผลลัพธ์จาก cache ด้วย key ที่ตรงกัน
    ///
    /// คืน `Some(CacheEntry)` ถ้าพบ cache hit, `None` ถ้า cache miss
    #[instrument(skip(self), fields(key = %key.normalized_text))]
    pub async fn get(&self, key: &QueryCacheKey) -> Option<CacheEntry> {
        let mut cache = self.cache.write().await;

        // ตรวจสอบ TTL ก่อน
        if let Some(entry) = cache.peek(key) {
            if entry.is_expired(self.ttl) {
                // Entry หมดอายุ — ลบออก
                cache.pop(key);
                debug!("cache entry expired, removed");
                self.total_misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        // LRU get (promotes entry to most-recently-used)
        if let Some(entry) = cache.get(key) {
            entry.record_hit();
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            debug!(hits = entry.hits(), "cache hit");
            Some(entry.clone())
        } else {
            self.total_misses.fetch_add(1, Ordering::Relaxed);
            debug!("cache miss");
            None
        }
    }

    /// ดึงผลลัพธ์จาก cache โดยค้นหาข้อคำถามที่คล้ายคลึงกัน
    ///
    /// ใช้ cosine similarity บน djb2 word-hash embeddings
    /// คืน `Some((CacheEntry, similarity_score))` ถ้าพบความคล้ายคลึงเกิน threshold
    #[instrument(skip(self), fields(query_len = query.len()))]
    pub async fn get_similar(
        &self,
        query: &str,
        intent_type: IntentType,
    ) -> Option<(CacheEntry, f32)> {
        let query_normalized = normalize_query(query);
        if query_normalized.is_empty() {
            return None;
        }

        let query_vector = generate_embedding(&query_normalized);
        let cache = self.cache.read().await;

        let mut best_entry: Option<CacheEntry> = None;
        let mut best_score = 0.0f32;

        // ค้นหา cache entries ทั้งหมด
        for (key, entry) in cache.iter() {
            // ตรวจสอบ intent type ก่อน
            if key.intent_type != intent_type {
                continue;
            }

            // ตรวจสอบ TTL
            if entry.is_expired(self.ttl) {
                continue;
            }

            // คำนวณ similarity
            let entry_vector = generate_embedding(&key.normalized_text);
            let score = cosine_similarity(&query_vector, &entry_vector);

            if score > best_score && score >= self.similarity_threshold {
                best_score = score;
                best_entry = Some(entry.clone());
            }
        }

        if let Some(entry) = best_entry {
            entry.record_hit();
            self.total_hits.fetch_add(1, Ordering::Relaxed);
            debug!(score = best_score, "similar cache hit");
            Some((entry, best_score))
        } else {
            self.total_misses.fetch_add(1, Ordering::Relaxed);
            debug!("no similar cache entry found");
            None
        }
    }

    /// บันทึกผลลัพธ์ลงใน cache
    #[instrument(skip(self, entry), fields(key = %key.normalized_text))]
    pub async fn put(&self, key: QueryCacheKey, entry: CacheEntry) {
        let mut cache = self.cache.write().await;

        // ตรวจสอบ TTL ของ entries ที่หมดอายุ
        let expired_keys: Vec<QueryCacheKey> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired(self.ttl))
            .map(|(key, _)| key.clone())
            .collect();

        for expired_key in expired_keys {
            cache.pop(&expired_key);
            debug!("cleaned expired cache entry during put");
        }

        cache.put(key, entry);
    }

    /// ลบ cache entries ที่เกี่ยวข้องกับไฟล์ที่ระบุ
    #[instrument(skip(self))]
    pub async fn invalidate_for_file(&self, path: &str) {
        let mut cache = self.cache.write().await;
        let keys_to_remove: Vec<QueryCacheKey> = cache
            .iter()
            .filter(|(_, _entry)| {
                // ตรวจสอบว่า response_data มีการอ้างอิงถึง path นี้หรือไม่
                // (ในอนาคตสามารถเก็บ metadata เพิ่มเติมเพื่อตรวจสอบได้แม่นยำกว่า)
                // ตอนนี้ใช้วิธีลบ cache ทั้งหมดเมื่อมีการเปลี่ยนแปลงไฟล์
                true
            })
            .map(|(key, _)| key.clone())
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            cache.pop(&key);
        }

        if count > 0 {
            info!(
                path = path,
                entries_removed = count,
                "invalidated cache entries for file"
            );
        }
    }

    /// ล้าง cache ทั้งหมด
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        let count = cache.len();
        cache.clear();
        info!(entries_cleared = count, "query cache cleared");
    }

    /// ประมวลผลเหตุการณ์ invalidation
    pub async fn handle_invalidation(&self, event: CacheInvalidation) {
        match event {
            CacheInvalidation::FileIndexed { paths } => {
                for path in &paths {
                    self.invalidate_for_file(path).await;
                }
            }
            CacheInvalidation::FileDeleted { path } => {
                self.invalidate_for_file(&path).await;
            }
            CacheInvalidation::FullClear => {
                self.clear().await;
            }
        }
    }

    /// คืนสถานะของ cache
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let hits = self.total_hits.load(Ordering::Relaxed);
        let misses = self.total_misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            size: cache.len(),
            capacity: cache.cap().get(),
            total_hits: hits,
            total_misses: misses,
            hit_ratio: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }

    /// ลบ entries ที่หมดอายุออก (garbage collection)
    pub async fn gc(&self) -> usize {
        let mut cache = self.cache.write().await;
        let expired_keys: Vec<QueryCacheKey> = cache
            .iter()
            .filter(|(_, entry)| entry.is_expired(self.ttl))
            .map(|(key, _)| key.clone())
            .collect();

        let count = expired_keys.len();
        for key in expired_keys {
            cache.pop(&key);
        }

        if count > 0 {
            debug!(entries_cleaned = count, "gc completed");
        }
        count
    }
}

impl Default for SemanticQueryCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Query Normalizer ──────────────────────────────────────────────────────

/// ทำการ normalization ข้อความ query
///
/// 1. แปลงเป็น lowercase
/// 2. ลบเครื่องหมายวรรคตอน
/// 3. ลบ stopwords
pub fn normalize_query(text: &str) -> String {
    let lower = text.to_lowercase();
    // ลบเครื่องหมายวรรคตอน (เก็บเฉพาะ a-z, 0-9, space)
    let cleaned: String = lower
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace())
        .collect();

    let words: Vec<&str> = cleaned
        .split_whitespace()
        .filter(|w| !STOPWORDS.contains(w))
        .filter(|w| !w.is_empty())
        .collect();

    words.join(" ")
}

// ── Embedding Functions (djb2 word-hash) ─────────────────────────────────

/// อัลกอริทึม Word-Hash Embedding อย่างง่าย
/// ใช้ djb2 hash algorithm เหมือนกับ nlp.rs
fn generate_embedding(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0f32; VECTOR_SIZE];
    if text.is_empty() {
        return vector;
    }

    for (i, word) in text.split_whitespace().enumerate() {
        let hash = word.bytes().fold(5381u64, |acc, b| {
            acc.wrapping_shl(5).wrapping_add(acc).wrapping_add(b as u64)
        });
        let idx = (hash as usize) % VECTOR_SIZE;
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

/// คำนวณ Cosine Similarity (Dot Product ของ Unit Vectors)
fn cosine_similarity(v1: &[f32], v2: &[f32]) -> f32 {
    v1.iter().zip(v2.iter()).map(|(x, y)| x * y).sum()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_query_removes_stopwords() {
        let result = normalize_query("the quick brown fox jumps over the lazy dog");
        assert_eq!(result, "quick brown fox jumps lazy dog");
    }

    #[test]
    fn normalize_query_lowercases() {
        let result = normalize_query("NEURAL NETWORK DESIGN");
        assert_eq!(result, "neural network design");
    }

    #[test]
    fn normalize_query_removes_punctuation() {
        let result = normalize_query("find files of AI, ML, and deep learning!");
        assert_eq!(result, "find files ai ml deep learning");
    }

    #[test]
    fn normalize_query_empty_returns_empty() {
        let result = normalize_query("");
        assert_eq!(result, "");
    }

    #[test]
    fn normalize_query_all_stopwords_returns_empty() {
        let result = normalize_query("the is a an");
        assert_eq!(result, "");
    }

    #[test]
    fn cache_key_deterministic() {
        let key1 = QueryCacheKey::new(
            "search files for neural network",
            IntentType::NaturalLanguage,
        );
        let key2 = QueryCacheKey::new(
            "search files for neural network",
            IntentType::NaturalLanguage,
        );
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_key_differs_by_intent_type() {
        let key1 = QueryCacheKey::new("search files", IntentType::NaturalLanguage);
        let key2 = QueryCacheKey::new("search files", IntentType::Command);
        assert_ne!(key1, key2);
    }

    #[test]
    fn cache_key_normalizes_text() {
        let key1 = QueryCacheKey::new("The Quick Brown Fox", IntentType::NaturalLanguage);
        let key2 = QueryCacheKey::new("quick brown fox", IntentType::NaturalLanguage);
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_entry_not_expired_immediately() {
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        assert!(!entry.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn cache_entry_expired_after_ttl() {
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now() - Duration::from_secs(301),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        assert!(entry.is_expired(Duration::from_secs(300)));
    }

    #[test]
    fn cache_entry_hit_count() {
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        assert_eq!(entry.hits(), 0);
        entry.record_hit();
        entry.record_hit();
        assert_eq!(entry.hits(), 2);
    }

    #[test]
    fn cosine_similarity_identical_vectors() {
        let v = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&v, &v) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_orthogonal_vectors() {
        let v1 = vec![1.0, 0.0, 0.0];
        let v2 = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&v1, &v2) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn generate_embedding_deterministic() {
        let v1 = generate_embedding("hello world");
        let v2 = generate_embedding("hello world");
        assert_eq!(v1, v2);
    }

    #[test]
    fn generate_embedding_unit_vector() {
        let v = generate_embedding("test text here");
        let sum_sq: f32 = v.iter().map(|x| x * x).sum();
        assert!((sum_sq - 1.0).abs() < 1e-5, "norm should be 1.0");
    }

    #[test]
    fn generate_embedding_empty_text() {
        let v = generate_embedding("");
        assert_eq!(v, vec![0.0f32; VECTOR_SIZE]);
    }

    #[tokio::test]
    async fn cache_put_and_get() {
        let cache = SemanticQueryCache::with_capacity(10);
        let key = QueryCacheKey::new("search neural network", IntentType::NaturalLanguage);

        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![1, 2, 3],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key.clone(), entry.clone()).await;

        let result = cache.get(&key).await;
        assert!(result.is_some());
        let cached = result.unwrap();
        assert_eq!(cached.response_data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn cache_miss_returns_none() {
        let cache = SemanticQueryCache::with_capacity(10);
        let key = QueryCacheKey::new("nonexistent query", IntentType::NaturalLanguage);

        let result = cache.get(&key).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn cache_evicts_lru_when_full() {
        let cache = SemanticQueryCache::with_capacity(2);

        let key1 = QueryCacheKey::new("query one", IntentType::NaturalLanguage);
        let key2 = QueryCacheKey::new("query two", IntentType::NaturalLanguage);
        let key3 = QueryCacheKey::new("query three", IntentType::NaturalLanguage);

        let make_entry = || CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key1.clone(), make_entry()).await;
        cache.put(key2.clone(), make_entry()).await;
        cache.put(key3.clone(), make_entry()).await;

        // key1 should be evicted (LRU)
        assert!(cache.get(&key1).await.is_none());
        assert!(cache.get(&key2).await.is_some());
        assert!(cache.get(&key3).await.is_some());
    }

    #[tokio::test]
    async fn cache_clear_removes_all() {
        let cache = SemanticQueryCache::with_capacity(10);

        let key = QueryCacheKey::new("test query", IntentType::NaturalLanguage);
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key.clone(), entry).await;
        assert!(cache.get(&key).await.is_some());

        cache.clear().await;
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn cache_stats_tracking() {
        let cache = SemanticQueryCache::with_capacity(10);
        let key = QueryCacheKey::new("test", IntentType::NaturalLanguage);

        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key.clone(), entry).await;
        cache.get(&key).await; // hit
        cache
            .get(&QueryCacheKey::new("missing", IntentType::NaturalLanguage))
            .await; // miss

        let stats = cache.stats().await;
        assert_eq!(stats.size, 1);
        assert_eq!(stats.total_hits, 1);
        assert_eq!(stats.total_misses, 1);
        assert!((stats.hit_ratio - 0.5).abs() < 0.01);
    }

    #[tokio::test]
    async fn cache_gc_removes_expired() {
        let cache = SemanticQueryCache::with_capacity(10);

        let key = QueryCacheKey::new("test", IntentType::NaturalLanguage);
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![],
            created_at: Instant::now() - Duration::from_secs(301),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key.clone(), entry).await;
        let cleaned = cache.gc().await;
        assert_eq!(cleaned, 1);
    }

    #[tokio::test]
    async fn get_similar_finds_close_match() {
        // ใช้ similarity threshold ที่ต่ำกว่าสำหรับ djb2 word-hash embedding
        let cache = SemanticQueryCache::with_config(10, Duration::from_secs(300), 0.5);

        let key = QueryCacheKey::new("neural network design", IntentType::NaturalLanguage);
        let entry = CacheEntry {
            parsed_intent: Intent::new(
                "test",
                IntentType::Command,
                "search-file",
                crate::IntentPriority::High,
                "test",
            ),
            response_data: vec![1, 2, 3],
            created_at: Instant::now(),
            hit_count: Arc::new(AtomicU64::new(0)),
        };

        cache.put(key, entry).await;

        // Query ที่คล้ายคลึงกัน — ควรพบ cache hit
        let result = cache
            .get_similar("neural network architecture", IntentType::NaturalLanguage)
            .await;

        assert!(result.is_some());
        let (cached, score) = result.unwrap();
        assert!(score > 0.5, "similarity score should be > 0.5, got {score}");
        assert_eq!(cached.response_data, vec![1, 2, 3]);
    }

    #[test]
    fn query_cache_key_hash_deterministic() {
        let key1 = QueryCacheKey::new("test query", IntentType::NaturalLanguage);
        let key2 = QueryCacheKey::new("test query", IntentType::NaturalLanguage);
        assert_eq!(key1.hash_bytes(), key2.hash_bytes());
    }
}
