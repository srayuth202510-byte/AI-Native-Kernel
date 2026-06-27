use anyhow::Result;
use qdrant_client::Qdrant;
use qdrant_client::qdrant::vectors_config::Config;
use qdrant_client::qdrant::{CreateCollection, Distance, VectorParams, VectorsConfig};
use qdrant_client::qdrant::{PointStruct, SearchPoints, UpsertPoints};
use std::collections::HashMap;

/// ตัวจัดการพื้นที่จัดเก็บและค้นหาตามความหมาย (Semantic Store)
/// ใช้ Qdrant สำหรับค้นหาด้วย Vector (Cosine Similarity)
pub struct SemanticStore {
    client: Qdrant,
    collection_name: String,
}

impl SemanticStore {
    /// สร้างอินสแตนซ์ใหม่โดยเชื่อมต่อไปยัง Qdrant Server และเตรียม Collection
    pub async fn new(url: &str, collection_name: &str, vector_size: u64) -> Result<Self> {
        let client = Qdrant::from_url(url).build()?;

        // เตรียมสร้าง Collection หากยังไม่มี (สำหรับ MVP)
        if !client.collection_exists(collection_name).await? {
            client
                .create_collection(CreateCollection {
                    collection_name: collection_name.to_string(),
                    vectors_config: Some(VectorsConfig {
                        config: Some(Config::Params(VectorParams {
                            size: vector_size,
                            distance: Distance::Cosine.into(),
                            ..Default::default()
                        })),
                    }),
                    ..Default::default()
                })
                .await?;
        }

        Ok(Self {
            client,
            collection_name: collection_name.to_string(),
        })
    }

    /// บันทึกหรืออัปเดตข้อมูลบริบท (Context) ในรูปแบบ Vector เข้าสู่ระบบ
    pub async fn upsert(
        &self,
        id: &str,
        vector: Vec<f32>,
        payload: HashMap<String, qdrant_client::qdrant::Value>,
    ) -> Result<()> {
        let point = PointStruct::new(id.to_string(), vector, payload);
        self.client
            .upsert_points(UpsertPoints {
                collection_name: self.collection_name.clone(),
                wait: Some(true),
                points: vec![point],
                ..Default::default()
            })
            .await?;
        Ok(())
    }

    /// ค้นหาบริบทที่ใกล้เคียงที่สุดตามความหมาย (Semantic Search)
    pub async fn search(
        &self,
        vector: Vec<f32>,
        limit: u64,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>> {
        let result = self
            .client
            .search_points(SearchPoints {
                collection_name: self.collection_name.clone(),
                vector,
                limit,
                with_payload: Some(true.into()),
                ..Default::default()
            })
            .await?;
        Ok(result.result)
    }

    /// ค้นหาบริบทและส่งคืนเฉพาะ ID และ Metadata เป็น String Map เพื่อลดความซับซ้อนของโครงสร้างข้อมูล
    pub async fn search_metadata(
        &self,
        vector: Vec<f32>,
        limit: u64,
    ) -> Result<Vec<(String, HashMap<String, String>)>> {
        let results = self.search(vector, limit).await?;
        let mut extracted = Vec::new();

        for point in results {
            let id = match point
                .id
                .as_ref()
                .and_then(|id| id.point_id_options.as_ref())
            {
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u)) => u.clone(),
                Some(qdrant_client::qdrant::point_id::PointIdOptions::Num(n)) => n.to_string(),
                None => continue,
            };

            let mut metadata = HashMap::new();
            for (key, val) in point.payload {
                if let Some(qdrant_client::qdrant::value::Kind::StringValue(s)) = val.kind {
                    metadata.insert(key, s);
                } else if let Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) = val.kind {
                    metadata.insert(key, i.to_string());
                }
            }
            extracted.push((id, metadata));
        }

        Ok(extracted)
    }

    /// ลบข้อมูลบริบท (Context) ออกจากระบบ Qdrant ด้วย ID
    pub async fn delete(&self, id: &str) -> Result<()> {
        use qdrant_client::qdrant::{
            DeletePoints, PointsIdsList, PointsSelector, points_selector::PointsSelectorOneOf,
        };

        self.client
            .delete_points(DeletePoints {
                collection_name: self.collection_name.clone(),
                wait: Some(true),
                points: Some(PointsSelector {
                    points_selector_one_of: Some(PointsSelectorOneOf::Points(PointsIdsList {
                        ids: vec![id.to_string().into()],
                    })),
                }),
                ..Default::default()
            })
            .await?;
        Ok(())
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

    #[tokio::test]
    #[ignore = "Requires a running Qdrant instance; override with QDRANT_URL/QDRANT_HOST/QDRANT_PORT"]
    async fn test_qdrant_semantic_store() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context", 128).await?;

        let vector1 = vec![0.1; 128]; // Mock embedding
        let mut payload1 = HashMap::new();
        payload1.insert("intent".to_string(), "open browser".into());

        store.upsert("doc-1", vector1.clone(), payload1).await?;

        // Search for nearest neighbor
        let results = store.search(vector1, 1).await?;
        assert_eq!(results.len(), 1);

        let point = &results[0];
        let id_val = match point
            .id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing ID"))?
            .point_id_options
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing point options"))?
        {
            qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u) => u.clone(),
            qdrant_client::qdrant::point_id::PointIdOptions::Num(n) => n.to_string(),
        };
        assert_eq!(id_val, "doc-1");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "Requires a running Qdrant instance; override with QDRANT_URL/QDRANT_HOST/QDRANT_PORT"]
    async fn test_qdrant_semantic_store_multiple_points() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context_multi", 64).await?;

        // เตรียมข้อมูล 3 จุด
        let vec1 = vec![1.0; 64];
        let vec2 = vec![-1.0; 64];
        let vec3 = vec![0.0; 64];

        let mut payload1 = HashMap::new();
        payload1.insert("tag".to_string(), "positive".into());
        let mut payload2 = HashMap::new();
        payload2.insert("tag".to_string(), "negative".into());
        let mut payload3 = HashMap::new();
        payload3.insert("tag".to_string(), "neutral".into());

        store.upsert("doc-p", vec1.clone(), payload1).await?;
        store.upsert("doc-n", vec2.clone(), payload2).await?;
        store.upsert("doc-z", vec3.clone(), payload3).await?;

        // ค้นหาแบบใกล้เคียง vec1 มากที่สุด (cosine similarity)
        // ควรจะได้ doc-p เป็นอันดับ 1
        let results = store.search(vec1, 2).await?;
        assert_eq!(results.len(), 2);

        let first_id = match results[0]
            .id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing ID"))?
            .point_id_options
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing point options"))?
        {
            qdrant_client::qdrant::point_id::PointIdOptions::Uuid(u) => u.clone(),
            qdrant_client::qdrant::point_id::PointIdOptions::Num(n) => n.to_string(),
        };
        assert_eq!(first_id, "doc-p");

        Ok(())
    }

    #[tokio::test]
    #[ignore = "Requires a running Qdrant instance; override with QDRANT_URL/QDRANT_HOST/QDRANT_PORT"]
    async fn test_qdrant_semantic_store_empty_search() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context_empty", 32).await?;

        // ค้นหาใน collection เปล่า หรือไม่ได้ใส่ข้อมูล
        let results = store.search(vec![0.5; 32], 5).await?;
        assert!(results.len() <= 5);

        Ok(())
    }
}
