//! Test utilities for context-memory integration tests
//!
//! Provides testcontainers-based Qdrant instance for running integration tests
//! without requiring external Qdrant endpoint.

use std::time::Duration;
use testcontainers::{
    ContainerAsync, GenericImage, core::ContainerPort, core::WaitFor, runners::AsyncRunner,
};
use tracing::info;

/// Qdrant test container image
const QDRANT_IMAGE: &str = "qdrant/qdrant";
const QDRANT_TAG: &str = "v1.12.2";
/// Default Qdrant HTTP port
const QDRANT_PORT: u16 = 6334;
/// Default gRPC port
const QDRANT_GRPC_PORT: u16 = 6333;

/// A handle to a running Qdrant test container
pub struct QdrantTestContainer {
    container: ContainerAsync<GenericImage>,
    http_port: u16,
}

impl QdrantTestContainer {
    /// Start a new Qdrant test container
    ///
    /// This will pull the Qdrant image if not present locally and start a container
    /// with HTTP and gRPC ports mapped to random host ports.
    ///
    /// Returns an error if Docker is not available (e.g., in environments without Docker).
    pub async fn start() -> anyhow::Result<Self> {
        let image = GenericImage::new(QDRANT_IMAGE, QDRANT_TAG)
            .with_exposed_port(ContainerPort::Tcp(QDRANT_PORT))
            .with_exposed_port(ContainerPort::Tcp(QDRANT_GRPC_PORT))
            .with_wait_for(WaitFor::message_on_stdout("Qdrant is ready"));

        info!("Starting Qdrant test container...");

        let container = match image.start().await {
            Ok(c) => c,
            Err(e) => {
                if e.to_string().contains("Socket not found") || e.to_string().contains("docker") {
                    return Err(anyhow::anyhow!(
                        "Docker not available: {}. Set QDRANT_URL to use external Qdrant instead.",
                        e
                    ));
                }
                return Err(e.into());
            }
        };

        let http_port = container.get_host_port_ipv4(QDRANT_PORT).await?;

        info!("Qdrant test container started on port {}", http_port);

        // Give Qdrant a moment to fully initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        Ok(Self {
            container,
            http_port,
        })
    }

    /// Get the HTTP URL for the Qdrant instance
    pub fn http_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http_port)
    }

    /// Get the gRPC URL for the Qdrant instance
    pub async fn grpc_url(&self) -> String {
        let grpc_port = self
            .container
            .get_host_port_ipv4(QDRANT_GRPC_PORT)
            .await
            .unwrap_or(6333);
        format!("http://127.0.0.1:{}", grpc_port)
    }

    /// Get the underlying container for advanced operations
    pub fn container(&self) -> &ContainerAsync<GenericImage> {
        &self.container
    }
}

impl Drop for QdrantTestContainer {
    fn drop(&mut self) {
        // Container will be stopped when dropped
        info!("Qdrant test container stopping...");
    }
}

/// Test helper to run a test with a fresh Qdrant instance
///
/// Usage:
/// ```rust
/// #[tokio::test]
/// async fn my_qdrant_test() {
///     with_qdrant(|url| async move {
///         let store = SemanticStore::new(url, "test_collection", 128).await?;
///         // ... test logic
///         Ok(())
///     }).await;
/// }
/// ```
pub async fn with_qdrant<F, Fut, T>(test_fn: F) -> T
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let container = QdrantTestContainer::start()
        .await
        .expect("Failed to start Qdrant container");
    let url = container.http_url();
    test_fn(url).await
}

/// Test helper that keeps the container alive for multiple operations
///
/// Usage:
/// ```rust
/// #[tokio::test]
/// async fn my_qdrant_test() {
///     let container = QdrantTestContainer::start().await.unwrap();
///     let url = container.http_url();
///
///     let store1 = SemanticStore::new(&url, "coll1", 128).await.unwrap();
///     // ... test with store1
///
///     let store2 = SemanticStore::new(&url, "coll2", 64).await.unwrap();
///     // ... test with store2
///
///     // Container auto-stops when dropped
/// }
/// ```
pub async fn qdrant_container() -> anyhow::Result<QdrantTestContainer> {
    QdrantTestContainer::start().await
}
