#![deny(unsafe_code)]

//! ระบบจำแนกความต้องการภาษาธรรมชาติอย่างง่าย (Lightweight Intent Classifier)
//! ใช้ cosine similarity บน djb2 word-hash embeddings เพื่อค้นหาความต้องการที่ใกล้เคียงที่สุด

use intent_bus::query_cache::{CacheEntry, QueryCacheKey, SemanticQueryCache};
use intent_bus::{Intent, IntentPriority, IntentType};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

/// เวกเตอร์แทนความหมายจำลอง (128 dimensions)
const VECTOR_SIZE: usize = 128;

/// อัลกอริทึม Word-Hash Embedding อย่างง่ายเพื่อจำลองพฤติกรรมความเข้าใจภาษา
fn generate_embedding(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0f32; VECTOR_SIZE];
    if text.is_empty() {
        return vector;
    }

    for (i, word) in text.split_whitespace().enumerate() {
        // djb2 hash algorithm
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

/// ประมวลผลและจำแนก NaturalLanguage Intent ออกมาเป็น Command Intent
#[must_use]
pub fn parse_natural_language_intent(intent: &Intent) -> Option<Intent> {
    if intent.intent_type != IntentType::NaturalLanguage {
        return None;
    }

    let payload_lower = intent.payload.to_lowercase();

    // Check direct filesystem patterns first
    if payload_lower.starts_with("write file ") {
        let rest = &intent.payload["write file ".len()..];
        let parts: Vec<&str> = rest.splitn(2, " containing ").collect();
        if parts.len() == 2 {
            let path = parts[0].trim().to_string();
            let content = parts[1].trim().to_string();
            let mut metadata = HashMap::new();
            metadata.insert("path".to_string(), path);
            metadata.insert("content".to_string(), content);

            let mut cmd = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::Command,
                "write-file".to_string(),
                IntentPriority::High,
                "nlp-router".to_string(),
            );
            cmd.metadata = metadata;
            return Some(cmd);
        }
    } else if payload_lower.starts_with("read file ") {
        let path = intent.payload["read file ".len()..].trim().to_string();
        if !path.is_empty() {
            let mut metadata = HashMap::new();
            metadata.insert("path".to_string(), path);

            let mut cmd = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::Command,
                "read-file".to_string(),
                IntentPriority::High,
                "nlp-router".to_string(),
            );
            cmd.metadata = metadata;
            return Some(cmd);
        }
    } else if payload_lower.starts_with("search file ")
        || payload_lower.starts_with("search files for ")
    {
        let prefix = if payload_lower.starts_with("search files for ") {
            "search files for "
        } else {
            "search file "
        };
        let query = intent.payload[prefix.len()..].trim().to_string();
        if !query.is_empty() {
            let mut metadata = HashMap::new();
            metadata.insert("query".to_string(), query);

            let mut cmd = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::Command,
                "search-file".to_string(),
                IntentPriority::High,
                "nlp-router".to_string(),
            );
            cmd.metadata = metadata;
            return Some(cmd);
        }
    } else if payload_lower.starts_with("delete file ") {
        let path = intent.payload["delete file ".len()..].trim().to_string();
        if !path.is_empty() {
            let mut metadata = HashMap::new();
            metadata.insert("path".to_string(), path);

            let mut cmd = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::Command,
                "delete-file".to_string(),
                IntentPriority::High,
                "nlp-router".to_string(),
            );
            cmd.metadata = metadata;
            return Some(cmd);
        }
    }

    let query_vector = generate_embedding(&intent.payload);

    // กำหนดโปรโตไทป์ความหมายของคำสั่งต่างๆ
    let prototypes = vec![
        (
            "small",
            "spawn agent running small llm model on cpu or npu edge inference battery low resource parameters",
        ),
        (
            "large",
            "run large reasoning model inference on high performance gpu cluster cloud server deep heavy",
        ),
        (
            "vector",
            "vector indexing semantic search database file document ingestion chunking qdrant metadata store",
        ),
    ];

    let mut best_class = None;
    let mut best_score = 0.0f32;

    for (class_name, prototype_text) in prototypes {
        let proto_vector = generate_embedding(prototype_text);
        let score = cosine_similarity(&query_vector, &proto_vector);
        if score > best_score {
            best_score = score;
            best_class = Some(class_name);
        }
    }

    // 定กำหนดความคล้ายคลึงขั้นต่ำ (Threshold) เพื่อความถูกต้อง
    if best_score > 0.22 {
        if let Some(class_name) = best_class {
            let mut metadata = HashMap::new();
            metadata.insert("workload".to_string(), class_name.to_string());

            let mut command_intent = Intent::new(
                uuid::Uuid::new_v4().to_string(),
                IntentType::Command,
                "spawn-agent".to_string(),
                IntentPriority::High,
                "nlp-router".to_string(),
            );
            command_intent.metadata = metadata;
            return Some(command_intent);
        }
    }

    None
}

/// จำแนก Intent ภาษาธรรมชาติด้วย Query Cache
///
/// ตรวจสอบ cache ก่อน ถ้าพบ cache hit จะคืนผลลัพธ์ที่ cache ไว้
/// ถ้าไม่พบ จะเรียก `parse_natural_language_intent` แล้วเก็บผลลัพธ์ลง cache
///
/// # Arguments
/// * `intent` - NaturalLanguage intent ที่ต้องการจำแนก
/// * `cache` - Semantic Query Cache
/// * `response_data` - ข้อมูลผลลัพธ์ (ถ้ามี) สำหรับเก็บใน cache
///
/// # Returns
/// `Some(Intent)` Command intent ที่จำแนกแล้ว หรือ `None` ถ้าไม่สามารถจำแนกได้
pub async fn classify_with_cache(
    intent: &Intent,
    cache: &SemanticQueryCache,
    response_data: Option<Vec<u8>>,
) -> Option<Intent> {
    if intent.intent_type != IntentType::NaturalLanguage {
        return None;
    }

    let cache_key = QueryCacheKey::new(&intent.payload, intent.intent_type);

    // 1. ตรวจสอบ cache (exact match)
    if let Some(entry) = cache.get(&cache_key).await {
        debug!(
            query = %intent.payload,
            hits = entry.hits(),
            "query cache hit (exact)"
        );
        return Some(entry.parsed_intent.clone());
    }

    // 2. ตรวจสอบ cache แบบ similarity (near-miss)
    if let Some((entry, score)) = cache.get_similar(&intent.payload, intent.intent_type).await {
        debug!(
            query = %intent.payload,
            score = score,
            hits = entry.hits(),
            "query cache hit (similar)"
        );
        return Some(entry.parsed_intent.clone());
    }

    // 3. Cache miss — จำแนก intent ด้วย NLP
    let parsed = parse_natural_language_intent(intent)?;

    // 4. เก็บผลลัพธ์ลง cache
    let entry = CacheEntry {
        parsed_intent: parsed.clone(),
        response_data: response_data.unwrap_or_default(),
        created_at: Instant::now(),
        hit_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
    };
    cache.put(cache_key, entry).await;

    debug!(query = %intent.payload, "query cache miss — parsed and cached");
    Some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_large_llm_intent() {
        let intent = Intent::new(
            "id-1",
            IntentType::NaturalLanguage,
            "run reasoning model on high speed gpu",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse successfully");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "spawn-agent");
        assert_eq!(
            parsed.metadata.get("workload").map(|s| s.as_str()),
            Some("large")
        );
    }

    #[test]
    fn test_parse_vector_indexing_intent() {
        let intent = Intent::new(
            "id-2",
            IntentType::NaturalLanguage,
            "index database vectors for semantic search query",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse successfully");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "spawn-agent");
        assert_eq!(
            parsed.metadata.get("workload").map(|s| s.as_str()),
            Some("vector")
        );
    }

    #[test]
    fn test_parse_garbage_intent_ignored() {
        let intent = Intent::new(
            "id-3",
            IntentType::NaturalLanguage,
            "hello world this is completely unrelated",
            IntentPriority::Low,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent);
        assert!(parsed.is_none(), "unrelated text should be ignored");
    }

    #[test]
    fn test_parse_fs_write_intent() {
        let intent = Intent::new(
            "id-fs-1",
            IntentType::NaturalLanguage,
            "write file secrets.txt containing very-private-data",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "write-file");
        assert_eq!(
            parsed.metadata.get("path").map(|s| s.as_str()),
            Some("secrets.txt")
        );
        assert_eq!(
            parsed.metadata.get("content").map(|s| s.as_str()),
            Some("very-private-data")
        );
    }

    #[test]
    fn test_parse_fs_read_intent() {
        let intent = Intent::new(
            "id-fs-2",
            IntentType::NaturalLanguage,
            "read file secrets.txt",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "read-file");
        assert_eq!(
            parsed.metadata.get("path").map(|s| s.as_str()),
            Some("secrets.txt")
        );
    }

    #[test]
    fn test_parse_fs_search_intent() {
        let intent = Intent::new(
            "id-fs-3",
            IntentType::NaturalLanguage,
            "search files for neural network design",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "search-file");
        assert_eq!(
            parsed.metadata.get("query").map(|s| s.as_str()),
            Some("neural network design")
        );
    }

    #[test]
    fn test_parse_fs_delete_intent() {
        let intent = Intent::new(
            "id-fs-4",
            IntentType::NaturalLanguage,
            "delete file secrets.txt",
            IntentPriority::Medium,
            "user",
        );

        let parsed = parse_natural_language_intent(&intent).expect("should parse");
        assert_eq!(parsed.intent_type, IntentType::Command);
        assert_eq!(parsed.payload, "delete-file");
        assert_eq!(
            parsed.metadata.get("path").map(|s| s.as_str()),
            Some("secrets.txt")
        );
    }
}
