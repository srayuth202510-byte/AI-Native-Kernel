use ::qdrant_client::qdrant::collections_server::{Collections, CollectionsServer};
use ::qdrant_client::qdrant::points_server::{Points, PointsServer};
use ::qdrant_client::qdrant::qdrant_server::{Qdrant, QdrantServer};
use ::qdrant_client::qdrant::*;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, async_trait, transport::Server};

#[derive(Clone, Default)]
struct StoredPoint {
    vector: Vec<f32>,
    payload: HashMap<String, Value>,
}

#[derive(Clone, Default)]
struct MockState {
    collections: Arc<RwLock<HashMap<String, HashMap<String, StoredPoint>>>>,
}

#[derive(Clone, Default)]
struct MockQdrant {
    state: MockState,
}

impl MockQdrant {
    async fn ensure_collection(&self, name: &str) {
        self.state
            .collections
            .write()
            .await
            .entry(name.to_string())
            .or_default();
    }

    async fn collection_exists_inner(&self, name: &str) -> bool {
        self.state.collections.read().await.contains_key(name)
    }

    async fn insert_points(&self, collection: &str, points: Vec<PointStruct>) {
        let mut collections = self.state.collections.write().await;
        let entries = collections.entry(collection.to_string()).or_default();
        for point in points {
            if let Some(id) = point_id_to_string(point.id.as_ref()) {
                entries.insert(
                    id,
                    StoredPoint {
                        vector: extract_vector(point.vectors.as_ref()).unwrap_or_default(),
                        payload: point.payload,
                    },
                );
            }
        }
    }

    async fn delete_selected(&self, collection: &str, selector: Option<PointsSelector>) {
        let Some(selector) = selector else {
            return;
        };
        let mut collections = self.state.collections.write().await;
        let Some(entries) = collections.get_mut(collection) else {
            return;
        };
        if let Some(points_selector::PointsSelectorOneOf::Points(ids)) =
            selector.points_selector_one_of
        {
            for id in ids.ids {
                if let Some(point_id) = point_id_to_string(Some(&id)) {
                    entries.remove(&point_id);
                }
            }
        }
    }

    async fn search_inner(&self, request: SearchPoints) -> Vec<ScoredPoint> {
        let with_payload = request
            .with_payload
            .as_ref()
            .is_some_and(with_payload_enabled);
        let limit = request.limit as usize;
        let query = request.vector;

        let collections = self.state.collections.read().await;
        let Some(entries) = collections.get(&request.collection_name) else {
            return Vec::new();
        };

        let mut scored: Vec<ScoredPoint> = entries
            .iter()
            .map(|(id, stored)| ScoredPoint {
                id: Some(string_to_point_id(id)),
                payload: if with_payload {
                    stored.payload.clone()
                } else {
                    HashMap::new()
                },
                score: cosine_similarity(&query, &stored.vector),
                version: 1,
                vectors: None,
                shard_key: None,
                order_value: None,
            })
            .collect();

        scored.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(Ordering::Equal)
        });
        scored.truncate(limit);
        scored
    }
}

fn with_payload_enabled(selector: &WithPayloadSelector) -> bool {
    use ::qdrant_client::qdrant::with_payload_selector::SelectorOptions;

    match selector.selector_options.as_ref() {
        Some(SelectorOptions::Enable(enable)) => *enable,
        Some(SelectorOptions::Include(_)) => true,
        Some(SelectorOptions::Exclude(_)) => false,
        None => false,
    }
}

fn point_id_to_string(point_id: Option<&PointId>) -> Option<String> {
    match point_id?.point_id_options.as_ref()? {
        point_id::PointIdOptions::Uuid(value) => Some(value.clone()),
        point_id::PointIdOptions::Num(value) => Some(value.to_string()),
    }
}

fn string_to_point_id(id: &str) -> PointId {
    PointId {
        point_id_options: Some(point_id::PointIdOptions::Uuid(id.to_string())),
    }
}

fn extract_vector(vectors_value: Option<&Vectors>) -> Option<Vec<f32>> {
    let vectors = vectors_value?;
    match vectors.vectors_options.as_ref()? {
        vectors::VectorsOptions::Vector(vector) => match vector.vector.as_ref()? {
            vector::Vector::Dense(DenseVector { data }) => Some(data.clone()),
            _ => None,
        },
        vectors::VectorsOptions::Vectors(named) => {
            named
                .vectors
                .values()
                .next()
                .and_then(|v| match v.vector.as_ref()? {
                    vector::Vector::Dense(DenseVector { data }) => Some(data.clone()),
                    _ => None,
                })
        }
    }
}

fn cosine_similarity(left: &[f32], right: &[f32]) -> f32 {
    if left.is_empty() || right.is_empty() || left.len() != right.len() {
        return 0.0;
    }

    let mut dot = 0.0f32;
    let mut left_norm = 0.0f32;
    let mut right_norm = 0.0f32;
    for (a, b) in left.iter().zip(right.iter()) {
        dot += a * b;
        left_norm += a * a;
        right_norm += b * b;
    }

    if left_norm <= f32::EPSILON || right_norm <= f32::EPSILON {
        0.0
    } else {
        dot / (left_norm.sqrt() * right_norm.sqrt())
    }
}

fn ok_collection_response() -> CollectionOperationResponse {
    CollectionOperationResponse {
        result: true,
        time: 0.0,
    }
}

fn ok_points_response() -> PointsOperationResponse {
    PointsOperationResponse {
        result: Some(UpdateResult {
            operation_id: Some(1),
            status: UpdateStatus::Completed as i32,
        }),
        time: 0.0,
        usage: None,
    }
}

fn unsupported<T>() -> Result<Response<T>, Status> {
    Err(Status::unimplemented("not required by ANK qdrant mock"))
}

#[async_trait]
impl Qdrant for MockQdrant {
    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckReply>, Status> {
        Ok(Response::new(HealthCheckReply {
            title: "qdrant mock".to_string(),
            version: "1.18.0".to_string(),
            commit: Some("ank-mock".to_string()),
        }))
    }
}

#[async_trait]
impl Collections for MockQdrant {
    async fn get(
        &self,
        _request: Request<GetCollectionInfoRequest>,
    ) -> Result<Response<GetCollectionInfoResponse>, Status> {
        unsupported()
    }

    async fn list(
        &self,
        _request: Request<ListCollectionsRequest>,
    ) -> Result<Response<ListCollectionsResponse>, Status> {
        Ok(Response::new(ListCollectionsResponse::default()))
    }

    async fn create(
        &self,
        request: Request<CreateCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        self.ensure_collection(&request.into_inner().collection_name)
            .await;
        Ok(Response::new(ok_collection_response()))
    }

    async fn update(
        &self,
        _request: Request<UpdateCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        unsupported()
    }

    async fn delete(
        &self,
        request: Request<DeleteCollection>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        self.state
            .collections
            .write()
            .await
            .remove(&request.into_inner().collection_name);
        Ok(Response::new(ok_collection_response()))
    }

    async fn update_aliases(
        &self,
        _request: Request<ChangeAliases>,
    ) -> Result<Response<CollectionOperationResponse>, Status> {
        unsupported()
    }

    async fn list_collection_aliases(
        &self,
        _request: Request<ListCollectionAliasesRequest>,
    ) -> Result<Response<ListAliasesResponse>, Status> {
        Ok(Response::new(ListAliasesResponse::default()))
    }

    async fn list_aliases(
        &self,
        _request: Request<ListAliasesRequest>,
    ) -> Result<Response<ListAliasesResponse>, Status> {
        Ok(Response::new(ListAliasesResponse::default()))
    }

    async fn collection_cluster_info(
        &self,
        _request: Request<CollectionClusterInfoRequest>,
    ) -> Result<Response<CollectionClusterInfoResponse>, Status> {
        unsupported()
    }

    async fn collection_exists(
        &self,
        request: Request<CollectionExistsRequest>,
    ) -> Result<Response<CollectionExistsResponse>, Status> {
        let exists = self
            .collection_exists_inner(&request.into_inner().collection_name)
            .await;
        Ok(Response::new(CollectionExistsResponse {
            result: Some(CollectionExists { exists }),
            time: 0.0,
        }))
    }

    async fn update_collection_cluster_setup(
        &self,
        _request: Request<UpdateCollectionClusterSetupRequest>,
    ) -> Result<Response<UpdateCollectionClusterSetupResponse>, Status> {
        unsupported()
    }

    async fn create_shard_key(
        &self,
        _request: Request<CreateShardKeyRequest>,
    ) -> Result<Response<CreateShardKeyResponse>, Status> {
        unsupported()
    }

    async fn delete_shard_key(
        &self,
        _request: Request<DeleteShardKeyRequest>,
    ) -> Result<Response<DeleteShardKeyResponse>, Status> {
        unsupported()
    }

    async fn list_shard_keys(
        &self,
        _request: Request<ListShardKeysRequest>,
    ) -> Result<Response<ListShardKeysResponse>, Status> {
        unsupported()
    }
}

#[async_trait]
impl Points for MockQdrant {
    async fn upsert(
        &self,
        request: Request<UpsertPoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        let request = request.into_inner();
        self.insert_points(&request.collection_name, request.points)
            .await;
        Ok(Response::new(ok_points_response()))
    }

    async fn delete(
        &self,
        request: Request<DeletePoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        let request = request.into_inner();
        self.delete_selected(&request.collection_name, request.points)
            .await;
        Ok(Response::new(ok_points_response()))
    }

    async fn get(&self, _request: Request<GetPoints>) -> Result<Response<GetResponse>, Status> {
        unsupported()
    }

    async fn update_vectors(
        &self,
        _request: Request<UpdatePointVectors>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn delete_vectors(
        &self,
        _request: Request<DeletePointVectors>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn set_payload(
        &self,
        _request: Request<SetPayloadPoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn overwrite_payload(
        &self,
        _request: Request<SetPayloadPoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn delete_payload(
        &self,
        _request: Request<DeletePayloadPoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn clear_payload(
        &self,
        _request: Request<ClearPayloadPoints>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn create_field_index(
        &self,
        _request: Request<CreateFieldIndexCollection>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn delete_field_index(
        &self,
        _request: Request<DeleteFieldIndexCollection>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn create_vector_name(
        &self,
        _request: Request<CreateVectorNameRequest>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn delete_vector_name(
        &self,
        _request: Request<DeleteVectorNameRequest>,
    ) -> Result<Response<PointsOperationResponse>, Status> {
        unsupported()
    }

    async fn search(
        &self,
        request: Request<SearchPoints>,
    ) -> Result<Response<SearchResponse>, Status> {
        Ok(Response::new(SearchResponse {
            result: self.search_inner(request.into_inner()).await,
            time: 0.0,
            usage: None,
        }))
    }

    async fn search_batch(
        &self,
        _request: Request<SearchBatchPoints>,
    ) -> Result<Response<SearchBatchResponse>, Status> {
        unsupported()
    }

    async fn search_groups(
        &self,
        _request: Request<SearchPointGroups>,
    ) -> Result<Response<SearchGroupsResponse>, Status> {
        unsupported()
    }

    async fn scroll(
        &self,
        _request: Request<ScrollPoints>,
    ) -> Result<Response<ScrollResponse>, Status> {
        unsupported()
    }

    async fn recommend(
        &self,
        _request: Request<RecommendPoints>,
    ) -> Result<Response<RecommendResponse>, Status> {
        unsupported()
    }

    async fn recommend_batch(
        &self,
        _request: Request<RecommendBatchPoints>,
    ) -> Result<Response<RecommendBatchResponse>, Status> {
        unsupported()
    }

    async fn recommend_groups(
        &self,
        _request: Request<RecommendPointGroups>,
    ) -> Result<Response<RecommendGroupsResponse>, Status> {
        unsupported()
    }

    async fn discover(
        &self,
        _request: Request<DiscoverPoints>,
    ) -> Result<Response<DiscoverResponse>, Status> {
        unsupported()
    }

    async fn discover_batch(
        &self,
        _request: Request<DiscoverBatchPoints>,
    ) -> Result<Response<DiscoverBatchResponse>, Status> {
        unsupported()
    }

    async fn count(
        &self,
        _request: Request<CountPoints>,
    ) -> Result<Response<CountResponse>, Status> {
        unsupported()
    }

    async fn update_batch(
        &self,
        _request: Request<UpdateBatchPoints>,
    ) -> Result<Response<UpdateBatchResponse>, Status> {
        unsupported()
    }

    async fn query(
        &self,
        _request: Request<QueryPoints>,
    ) -> Result<Response<QueryResponse>, Status> {
        unsupported()
    }

    async fn query_batch(
        &self,
        _request: Request<QueryBatchPoints>,
    ) -> Result<Response<QueryBatchResponse>, Status> {
        unsupported()
    }

    async fn query_groups(
        &self,
        _request: Request<QueryPointGroups>,
    ) -> Result<Response<QueryGroupsResponse>, Status> {
        unsupported()
    }

    async fn facet(
        &self,
        _request: Request<FacetCounts>,
    ) -> Result<Response<FacetResponse>, Status> {
        unsupported()
    }

    async fn search_matrix_pairs(
        &self,
        _request: Request<SearchMatrixPoints>,
    ) -> Result<Response<SearchMatrixPairsResponse>, Status> {
        unsupported()
    }

    async fn search_matrix_offsets(
        &self,
        _request: Request<SearchMatrixPoints>,
    ) -> Result<Response<SearchMatrixOffsetsResponse>, Status> {
        unsupported()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = "127.0.0.1:6334".parse()?;
    let service = MockQdrant::default();

    println!("qdrant mock listening on {addr}");

    Server::builder()
        .add_service(QdrantServer::new(service.clone()))
        .add_service(CollectionsServer::new(service.clone()))
        .add_service(PointsServer::new(service))
        .serve_with_shutdown(addr, async {
            let _ = signal::ctrl_c().await;
        })
        .await?;

    Ok(())
}
