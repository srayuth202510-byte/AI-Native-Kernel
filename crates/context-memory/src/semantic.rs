use anyhow::{Context, Result};
use qdrant_client::Qdrant;
use qdrant_client::qdrant::vectors_config::Config;
use qdrant_client::qdrant::{CreateCollection, Distance, VectorParams, VectorsConfig};
use qdrant_client::qdrant::{PointStruct, SearchPoints, UpsertPoints};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info, instrument, warn};

/// Timeout สำหรับ Qdrant HTTP calls
const QDRANT_TIMEOUT: Duration = Duration::from_secs(10);

/// จำนวนครั้งสูงสุดสำหรับ retry
const MAX_RETRIES: u32 = 3;

/// ระยะเวลา wait ก่อน retry (_exponential backoff_)
const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// ตัวจัดการพื้นที่จัดเก็บและค้นหาตามความหมาย (Semantic Store)
/// ใช้ Qdrant สำหรับค้นหาด้วย Vector (Cosine Similarity)
/// รองรับ retry logic, batch operations, และ filtered search
pub struct SemanticStore {
    client: Qdrant,
    collection_name: String,
}

impl std::fmt::Debug for SemanticStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticStore")
            .field("collection", &self.collection_name)
            .finish()
    }
}

impl SemanticStore {
    /// สร้างอินสแตนซ์ใหม่โดยเชื่อมต่อไปยัง Qdrant Server และเตรียม Collection
    #[instrument(skip(vector_size), fields(collection = %collection_name))]
    pub async fn new(url: &str, collection_name: &str, vector_size: u64) -> Result<Self> {
        let client = Qdrant::from_url(url).build()?;

        let exists = retry(|| async {
            timeout(QDRANT_TIMEOUT, client.collection_exists(collection_name))
                .await
                .context("Qdrant: collection_exists timeout")?
                .context("Qdrant: collection_exists failed")
        })
        .await?;

        if !exists {
            retry(|| async {
                timeout(
                    QDRANT_TIMEOUT,
                    client.create_collection(CreateCollection {
                        collection_name: collection_name.to_string(),
                        vectors_config: Some(VectorsConfig {
                            config: Some(Config::Params(VectorParams {
                                size: vector_size,
                                distance: Distance::Cosine.into(),
                                ..Default::default()
                            })),
                        }),
                        ..Default::default()
                    }),
                )
                .await
                .context("Qdrant: create_collection timeout")?
                .context("Qdrant: create_collection failed")
            })
            .await?;

            info!(
                collection = collection_name,
                vector_size, "Qdrant collection created"
            );
        }

        Ok(Self {
            client,
            collection_name: collection_name.to_string(),
        })
    }

    /// บันทึกหรืออัปเดตข้อมูลบริบท (Context) ในรูปแบบ Vector เข้าสู่ระบบ
    #[instrument(skip(self, vector, payload), fields(id = %id))]
    pub async fn upsert(
        &self,
        id: &str,
        vector: Vec<f32>,
        payload: HashMap<String, qdrant_client::qdrant::Value>,
    ) -> Result<()> {
        let point = PointStruct::new(id.to_string(), vector, payload);
        retry(|| async {
            timeout(
                QDRANT_TIMEOUT,
                self.client.upsert_points(UpsertPoints {
                    collection_name: self.collection_name.clone(),
                    wait: Some(true),
                    points: vec![point.clone()],
                    ..Default::default()
                }),
            )
            .await
            .context("Qdrant: upsert_points timeout")?
            .context("Qdrant: upsert_points failed")
        })
        .await?;
        debug!(id = id, "Qdrant upsert completed");
        Ok(())
    }

    /// บันทึกข้อมูลหลายจุดพร้อมกัน (Batch Upsert)
    /// แบ่งเป็น batches ขนาด 100 จุดเพื่อป้องกัน request ขนาดใหญ่เกินไป
    #[instrument(skip(self, points), fields(count = points.len()))]
    pub async fn upsert_batch(&self, points: Vec<PointStruct>) -> Result<()> {
        const BATCH_SIZE: usize = 100;

        for chunk in points.chunks(BATCH_SIZE) {
            let batch = chunk.to_vec();
            let batch_len = batch.len();
            retry(|| async {
                timeout(
                    QDRANT_TIMEOUT,
                    self.client.upsert_points(UpsertPoints {
                        collection_name: self.collection_name.clone(),
                        wait: Some(true),
                        points: batch.clone(),
                        ..Default::default()
                    }),
                )
                .await
                .context("Qdrant: upsert_batch timeout")?
                .context("Qdrant: upsert_batch failed")
            })
            .await?;
            debug!(batch_size = batch_len, "Qdrant batch upsert completed");
        }
        Ok(())
    }

    /// ค้นหาบริบทที่ใกล้เคียงที่สุดตามความหมาย (Semantic Search)
    #[instrument(skip(self, vector), fields(limit))]
    pub async fn search(
        &self,
        vector: Vec<f32>,
        limit: u64,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>> {
        let result = retry(|| async {
            timeout(
                QDRANT_TIMEOUT,
                self.client.search_points(SearchPoints {
                    collection_name: self.collection_name.clone(),
                    vector: vector.clone(),
                    limit,
                    with_payload: Some(true.into()),
                    ..Default::default()
                }),
            )
            .await
            .context("Qdrant: search_points timeout")?
            .context("Qdrant: search_points failed")
        })
        .await?;
        debug!(
            result_count = result.result.len(),
            "Qdrant search completed"
        );
        Ok(result.result)
    }

    /// ค้นหาบริบทแบบมีเงื่อนไข (Filtered Search)
    /// ค้นหา vector ที่ใกล้เคียงที่สุดแต่กรองตาม payload key/value ที่กำหนด
    #[instrument(skip(self, vector), fields(limit, filter_key = %filter_key))]
    pub async fn search_filtered(
        &self,
        vector: Vec<f32>,
        limit: u64,
        filter_key: &str,
        filter_value: &str,
    ) -> Result<Vec<qdrant_client::qdrant::ScoredPoint>> {
        use qdrant_client::qdrant::{Condition, Filter};

        let result = retry(|| async {
            timeout(
                QDRANT_TIMEOUT,
                self.client.search_points(SearchPoints {
                    collection_name: self.collection_name.clone(),
                    vector: vector.clone(),
                    limit,
                    with_payload: Some(true.into()),
                    filter: Some(Filter {
                        must: vec![Condition::matches(
                            filter_key.to_string(),
                            filter_value.to_string(),
                        )],
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            )
            .await
            .context("Qdrant: search_filtered timeout")?
            .context("Qdrant: search_filtered failed")
        })
        .await?;
        debug!(
            result_count = result.result.len(),
            "Qdrant filtered search completed"
        );
        Ok(result.result)
    }

    /// ค้นหาบริบทและส่งคืนเฉพาะ ID และ Metadata เป็น String Map
    #[instrument(skip(self, vector), fields(limit))]
    pub async fn search_metadata(
        &self,
        vector: Vec<f32>,
        limit: u64,
    ) -> Result<Vec<(String, HashMap<String, String>)>> {
        let results = self.search(vector, limit).await?;
        Ok(extract_metadata_from_points(results))
    }

    /// ลบข้อมูลบริบท (Context) ออกจากระบบ Qdrant ด้วย ID
    #[instrument(skip(self), fields(id = %id))]
    pub async fn delete(&self, id: &str) -> Result<()> {
        use qdrant_client::qdrant::{
            DeletePoints, PointsIdsList, PointsSelector, points_selector::PointsSelectorOneOf,
        };

        retry(|| async {
            timeout(
                QDRANT_TIMEOUT,
                self.client.delete_points(DeletePoints {
                    collection_name: self.collection_name.clone(),
                    wait: Some(true),
                    points: Some(PointsSelector {
                        points_selector_one_of: Some(PointsSelectorOneOf::Points(PointsIdsList {
                            ids: vec![id.to_string().into()],
                        })),
                    }),
                    ..Default::default()
                }),
            )
            .await
            .context("Qdrant: delete_points timeout")?
            .map_err(|e| anyhow::anyhow!(e))
            .context("Qdrant: delete_points failed")
        })
        .await?;
        debug!(id = id, "Qdrant delete completed");
        Ok(())
    }

    /// ลบหลายจุดพร้อมกัน (Batch Delete)
    #[instrument(skip(self), fields(count = ids.len()))]
    pub async fn delete_batch(&self, ids: &[String]) -> Result<()> {
        use qdrant_client::qdrant::{
            DeletePoints, PointsIdsList, PointsSelector, points_selector::PointsSelectorOneOf,
        };

        let point_ids: Vec<_> = ids.iter().map(|id| id.to_string().into()).collect();
        retry(|| async {
            timeout(
                QDRANT_TIMEOUT,
                self.client.delete_points(DeletePoints {
                    collection_name: self.collection_name.clone(),
                    wait: Some(true),
                    points: Some(PointsSelector {
                        points_selector_one_of: Some(PointsSelectorOneOf::Points(PointsIdsList {
                            ids: point_ids.clone(),
                        })),
                    }),
                    ..Default::default()
                }),
            )
            .await
            .context("Qdrant: delete_batch timeout")?
            .map_err(|e| anyhow::anyhow!(e))
            .context("Qdrant: delete_batch failed")
        })
        .await?;
        debug!(count = ids.len(), "Qdrant batch delete completed");
        Ok(())
    }
}

/// ช่วยดึง metadata จาก ScoredPoint results
pub(crate) fn extract_metadata_from_points(
    results: Vec<qdrant_client::qdrant::ScoredPoint>,
) -> Vec<(String, HashMap<String, String>)> {
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
            } else if let Some(qdrant_client::qdrant::value::Kind::DoubleValue(d)) = val.kind {
                metadata.insert(key, d.to_string());
            } else if let Some(qdrant_client::qdrant::value::Kind::BoolValue(b)) = val.kind {
                metadata.insert(key, b.to_string());
            }
        }
        extracted.push((id, metadata));
    }

    extracted
}

/// Retry with exponential backoff — ใช้สำหรับ Qdrant calls ที่อาจ fail ชั่วคราว
async fn retry<F, Fut, T>(mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_err = None;

    for attempt in 0..MAX_RETRIES {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                warn!(
                    attempt = attempt + 1,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    "Qdrant call failed, retrying"
                );
                last_err = Some(e);
                if attempt + 1 < MAX_RETRIES {
                    let delay = RETRY_BASE_DELAY * 2u32.pow(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry: no attempts made")))
}

#[cfg(test)]
impl SemanticStore {
    /// Create an instance without connecting to Qdrant (test-only)
    pub fn test_instance(collection_name: &str) -> Self {
        let client = Qdrant::from_url("http://127.0.0.1:1").build().unwrap();
        Self {
            client,
            collection_name: collection_name.to_string(),
        }
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

    #[test]
    fn extract_metadata_from_points_works() {
        use qdrant_client::qdrant::{
            PointId, ScoredPoint, Value, point_id::PointIdOptions, value::Kind,
        };

        let mut payload = HashMap::new();
        payload.insert(
            "path".to_string(),
            Value {
                kind: Some(Kind::StringValue("test.txt".into())),
            },
        );
        payload.insert(
            "size".to_string(),
            Value {
                kind: Some(Kind::IntegerValue(42)),
            },
        );
        payload.insert(
            "score_val".to_string(),
            Value {
                kind: Some(Kind::DoubleValue(2.71)),
            },
        );

        let points = vec![ScoredPoint {
            id: Some(PointId {
                point_id_options: Some(PointIdOptions::Uuid("test-uuid".into())),
            }),
            payload,
            score: 0.95,
            version: 1,
            vectors: None,
            order_value: None,
            shard_key: None,
        }];

        let result = extract_metadata_from_points(points);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test-uuid");
        assert_eq!(result[0].1.get("path").unwrap(), "test.txt");
        assert_eq!(result[0].1.get("size").unwrap(), "42");
        assert_eq!(result[0].1.get("score_val").unwrap(), "2.71");
    }

    #[tokio::test]
    #[ignore = "requires a reachable Qdrant endpoint"]
    async fn test_qdrant_semantic_store() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context", 128).await?;

        let vector1 = vec![0.1; 128];
        let mut payload1 = HashMap::new();
        payload1.insert("intent".to_string(), "open browser".into());

        store
            .upsert(
                "550e8400-e29b-41d4-a716-446655440000",
                vector1.clone(),
                payload1,
            )
            .await?;

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
        assert_eq!(id_val, "550e8400-e29b-41d4-a716-446655440000");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires a reachable Qdrant endpoint"]
    async fn test_qdrant_semantic_store_multiple_points() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context_multi", 64).await?;

        let vec1 = vec![1.0; 64];
        let vec2 = vec![-1.0; 64];
        let vec3 = vec![0.0; 64];

        let mut payload1 = HashMap::new();
        payload1.insert("tag".to_string(), "positive".into());
        let mut payload2 = HashMap::new();
        payload2.insert("tag".to_string(), "negative".into());
        let mut payload3 = HashMap::new();
        payload3.insert("tag".to_string(), "neutral".into());

        store
            .upsert(
                "550e8400-e29b-41d4-a716-446655440001",
                vec1.clone(),
                payload1,
            )
            .await?;
        store
            .upsert(
                "550e8400-e29b-41d4-a716-446655440002",
                vec2.clone(),
                payload2,
            )
            .await?;
        store
            .upsert(
                "550e8400-e29b-41d4-a716-446655440003",
                vec3.clone(),
                payload3,
            )
            .await?;

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
        assert_eq!(first_id, "550e8400-e29b-41d4-a716-446655440001");

        Ok(())
    }

    #[tokio::test]
    #[ignore = "requires a reachable Qdrant endpoint"]
    async fn test_qdrant_semantic_store_empty_search() -> Result<()> {
        if !check_qdrant_online().await {
            println!(
                "Skipping test: Qdrant server is not reachable at {}",
                qdrant_url()
            );
            return Ok(());
        }

        let store = SemanticStore::new(&qdrant_url(), "ank_context_empty", 32).await?;

        let results = store.search(vec![0.5; 32], 5).await?;
        assert!(results.len() <= 5);

        Ok(())
    }

    #[test]
    fn test_retry_success_on_first_attempt() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(retry(|| async { Ok::<_, anyhow::Error>(42) }));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_retry_eventually_succeeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(retry(|| {
            let cc = call_count_clone.clone();
            async move {
                let count = cc.fetch_add(1, Ordering::Relaxed);
                if count < 2 {
                    Err(anyhow::anyhow!("transient error"))
                } else {
                    Ok(99)
                }
            }
        }));
        assert_eq!(result.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::Relaxed), 3);
    }
}
