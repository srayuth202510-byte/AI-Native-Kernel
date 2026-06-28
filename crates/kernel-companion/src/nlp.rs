#![deny(unsafe_code)]

//! ระบบจำแนกความต้องการภาษาธรรมชาติอย่างง่าย (Lightweight Intent Classifier)
//! ใช้ cosine similarity บน djb2 word-hash embeddings เพื่อค้นหาความต้องการที่ใกล้เคียงที่สุด

use intent_bus::{Intent, IntentPriority, IntentType};
use std::collections::HashMap;

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
}
