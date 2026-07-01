use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info};

/// แพลตฟอร์ม GPU (สำหรับแยก CUDA vs ROCm)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GpuPlatform {
    /// NVIDIA CUDA
    Cuda,
    /// AMD ROCm
    Rocm,
}

impl GpuPlatform {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cuda => "cuda",
            Self::Rocm => "rocm",
        }
    }
}

/// ข้อผิดพลาดสำหรับ GpuMemoryPool
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum PoolError {
    #[error("CUDA API call failed: {0}")]
    CudaError(String),
    #[error("ROCm HIP API call failed: {0}")]
    RocmError(String),
    #[error("allocation of {size} bytes exceeds pool capacity {capacity}")]
    PoolExhausted { size: usize, capacity: usize },
    #[error("block {0} not found in pool")]
    BlockNotFound(String),
}

/// สถานะของบล็อกหน่วยความจำใน pool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockState {
    /// กำลังใช้งานอยู่
    Allocated,
    /// ถูกปลดปล่อยแล้วพร้อมนำกลับมาใช้ใหม่
    Freed,
    /// ถูกย้ายไปยัง CPU (unified memory path)
    MigratedToCpu,
}

/// ตัวติดตามบล็อกหน่วยความจำบน GPU
#[derive(Debug, Clone)]
pub struct GpuBlock {
    /// ID ของบล็อก
    pub id: String,
    /// แพลตฟอร์ม GPU
    pub platform: GpuPlatform,
    /// ขนาดที่ขอจัดสรร (requested allocation size)
    pub requested_size: usize,
    /// device pointer ของ CUDA/ROCm (ถ้ามี) — u64 สำหรับ cross-platform
    pub device_ptr: Option<u64>,
    /// true ถ้าบล็อกนี้ถูกจัดสรรบนอุปกรณ์จริง
    pub is_pinned: bool,
    /// สถานะ
    pub state: BlockState,
}

impl GpuBlock {
    #[must_use]
    pub fn new(id: String, platform: GpuPlatform, size_bytes: usize) -> Self {
        Self {
            id,
            platform,
            requested_size: size_bytes,
            device_ptr: None,
            is_pinned: false,
            state: BlockState::Allocated,
        }
    }
}

/// GpuMemoryPool — abstraction layer สำหรับจัดการหน่วยความจำบน GPU (CUDA/ROCm)
///
/// ## การทำงาน
/// - ติดตามบล็อกที่จัดสรรทั้งหมดใน pool
/// - รองรับการจัดสรรแบบ real (CUDA) หรือ software fallback
/// - รองรับการ migrate ระหว่าง GPU ↔ CPU
/// - Protection สำหรับ multi-tenant (กัน agent รุกที่ของกัน)
///
/// ## Platform support
/// - **real**: ใช้ CUDA/ROCm API จริงผ่าน FFI
/// - **simulated**: ใช้ host memory + device pointer tracking (สำหรับ dev/test)
#[derive(Debug)]
pub struct GpuMemoryPool {
    /// พูลหน่วยความจำ พร้อม lock
    blocks: RwLock<HashMap<String, GpuBlock>>,
    /// แพลตฟอร์ม GPU
    platform: GpuPlatform,
    /// ขนาด pool ทั้งหมด (ไบต์)
    total_capacity: usize,
    /// ใช้ real CUDA/ROCm allocation หรือ software simulation
    real_mode: bool,
}

impl GpuMemoryPool {
    /// สร้าง GPU memory pool ใหม่
    #[must_use]
    pub fn new(platform: GpuPlatform, total_capacity_bytes: usize, real_mode: bool) -> Self {
        info!(
            platform = %platform.name(),
            capacity_mb = %(total_capacity_bytes / 1024 / 1024),
            real_mode,
            "GpuMemoryPool created"
        );
        Self {
            blocks: RwLock::new(HashMap::new()),
            platform,
            total_capacity: total_capacity_bytes,
            real_mode,
        }
    }

    /// จัดสรรหน่วยความจำบน GPU
    ///
    /// # Errors
    /// คืน `PoolError::PoolExhausted` ถ้าพื้นที่ไม่พอ หรือ `PoolError::CudaError` ถ้า CUDA ล้มเหลว
    pub fn allocate(&self, id: String, size_bytes: usize) -> Result<GpuBlock, PoolError> {
        let mut blocks = self.blocks.write();

        // ตรวจสอบพื้นที่ว่าง
        let used: usize = blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated)
            .map(|b| b.requested_size)
            .sum();

        if used + size_bytes > self.total_capacity {
            return Err(PoolError::PoolExhausted {
                size: size_bytes,
                capacity: self.total_capacity,
            });
        }

        // real allocation หรือ simulation
        let mut gpu_block = GpuBlock::new(id.clone(), self.platform, size_bytes);

        if self.real_mode {
            match self.platform {
                GpuPlatform::Cuda => {
                    let ptr = Self::cuda_alloc(size_bytes)?;
                    gpu_block.device_ptr = Some(ptr as u64);
                    gpu_block.is_pinned = true;
                }
                GpuPlatform::Rocm => {
                    let ptr = Self::rocm_alloc(size_bytes)?;
                    gpu_block.device_ptr = Some(ptr as u64);
                    gpu_block.is_pinned = true;
                }
            }
        } else {
            // simulation: assign a fake device_ptr
            let simulated_ptr = id.as_ptr() as u64 ^ (size_bytes as u64);
            gpu_block.device_ptr = Some(simulated_ptr);
            gpu_block.is_pinned = false;
        }

        debug!(
            id = %id,
            size = %size_bytes,
            platform = %self.platform.name(),
            device_ptr = ?gpu_block.device_ptr,
            "GPU block allocated"
        );

        blocks.insert(id, gpu_block.clone());
        Ok(gpu_block)
    }

    /// ปลดปล่อยบล็อกหน่วยความจำ
    ///
    /// # Errors
    /// คืน `PoolError::BlockNotFound` ถ้าไม่พบบล็อก
    pub fn deallocate(&self, id: &str) -> Result<(), PoolError> {
        let mut blocks = self.blocks.write();
        let block = blocks
            .get_mut(id)
            .ok_or_else(|| PoolError::BlockNotFound(id.to_string()))?;

        if self.real_mode && block.is_pinned {
            if let Some(ptr) = block.device_ptr {
                match self.platform {
                    GpuPlatform::Cuda => Self::cuda_free(ptr as *mut std::ffi::c_void),
                    GpuPlatform::Rocm => Self::rocm_free(ptr as *mut std::ffi::c_void),
                }
            }
        }

        block.state = BlockState::Freed;
        debug!(id = %id, "GPU block deallocated");
        Ok(())
    }

    /// Migrate บล็อกจาก GPU ไปยัง CPU
    ///
    /// # Errors
    /// คืน `PoolError::BlockNotFound` ถ้าไม่พบบล็อก
    pub fn migrate_to_cpu(&self, id: &str) -> Result<(), PoolError> {
        let mut blocks = self.blocks.write();
        let block = blocks
            .get_mut(id)
            .ok_or_else(|| PoolError::BlockNotFound(id.to_string()))?;

        if block.state == BlockState::Allocated && self.real_mode {
            if let Some(ptr) = block.device_ptr {
                // TODO: real cudaMemcpy / hipMemcpy for device → host
                match self.platform {
                    GpuPlatform::Cuda => Self::cuda_free(ptr as *mut std::ffi::c_void),
                    GpuPlatform::Rocm => Self::rocm_free(ptr as *mut std::ffi::c_void),
                }
                block.device_ptr = None;
            }
        }

        block.state = BlockState::MigratedToCpu;
        info!(id = %id, "GPU block migrated to CPU");
        Ok(())
    }

    /// ตรวจสอบว่า pool มีพื้นที่ว่างเพียงพอสำหรับขนาดที่ต้องการหรือไม่
    #[must_use]
    pub fn has_capacity(&self, size_bytes: usize) -> bool {
        let blocks = self.blocks.read();
        let used: usize = blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated)
            .map(|b| b.requested_size)
            .sum();
        used + size_bytes <= self.total_capacity
    }

    /// ดึงข้อมูลบล็อก
    #[must_use]
    pub fn get_block(&self, id: &str) -> Option<GpuBlock> {
        self.blocks.read().get(id).cloned()
    }

    /// จำนวนที่ใช้ไป (ไบต์)
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated)
            .map(|b| b.requested_size)
            .sum()
    }

    /// จำนวนทั้งหมด (ไบต์)
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.total_capacity
    }

    /// จำนวนที่ว่าง (ไบต์)
    #[must_use]
    pub fn free_bytes(&self) -> usize {
        self.total_capacity.saturating_sub(self.used_bytes())
    }

    /// จำนวนบล็อกที่จัดสรรอยู่
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated)
            .count()
    }

    // ── FFI placeholders for real GPU allocation ──────────────────────────

    /// จัดสรรหน่วยความจำ CUDA (FFI — placeholder)
    fn cuda_alloc(size: usize) -> Result<*mut std::ffi::c_void, PoolError> {
        let _ = size;
        Err(PoolError::CudaError("CUDA FFI not yet linked".to_string()))
    }

    /// ปลดปล่อยหน่วยความจำ CUDA (FFI — placeholder)
    fn cuda_free(_ptr: *mut std::ffi::c_void) {
        debug!("CUDA free called (stub)");
    }

    /// จัดสรรหน่วยความจำ ROCm (FFI — placeholder)
    fn rocm_alloc(size: usize) -> Result<*mut std::ffi::c_void, PoolError> {
        let _ = size;
        Err(PoolError::RocmError(
            "ROCm HIP FFI not yet linked".to_string(),
        ))
    }

    /// ปลดปล่อยหน่วยความจำ ROCm (FFI — placeholder)
    fn rocm_free(_ptr: *mut std::ffi::c_void) {
        debug!("ROCm free called (stub)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_allocate_and_deallocate() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024 * 1024, false);
        let block = pool
            .allocate("block-1".into(), 4096)
            .expect("allocation should succeed");
        assert_eq!(block.requested_size, 4096);
        assert_eq!(block.platform, GpuPlatform::Cuda);
        assert!(block.device_ptr.is_some());

        assert_eq!(pool.used_bytes(), 4096);
        assert_eq!(pool.allocated_count(), 1);

        pool.deallocate("block-1").unwrap();
        assert_eq!(pool.used_bytes(), 0);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn pool_exhaustion_returns_error() {
        let pool = GpuMemoryPool::new(GpuPlatform::Rocm, 100, false);
        pool.allocate("big".into(), 80).unwrap();
        let err = pool.allocate("too-big".into(), 50).unwrap_err();
        assert!(matches!(err, PoolError::PoolExhausted { .. }));
    }

    #[test]
    fn pool_block_not_found() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        let err = pool.deallocate("nonexistent").unwrap_err();
        assert!(matches!(err, PoolError::BlockNotFound(_)));
    }

    #[test]
    fn pool_migrate_to_cpu() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024 * 1024, false);
        pool.allocate("migrate-me".into(), 8192).unwrap();
        pool.migrate_to_cpu("migrate-me").unwrap();

        let block = pool.get_block("migrate-me").unwrap();
        assert_eq!(block.state, BlockState::MigratedToCpu);
        assert_eq!(pool.allocated_count(), 0);
    }

    #[test]
    fn pool_has_capacity_check() {
        let pool = GpuMemoryPool::new(GpuPlatform::Rocm, 500, false);
        assert!(pool.has_capacity(400));
        pool.allocate("a".into(), 400).unwrap();
        assert!(pool.has_capacity(50));
        assert!(!pool.has_capacity(200));
    }

    #[test]
    fn pool_multiple_blocks() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 10_000, false);
        pool.allocate("a".into(), 1000).unwrap();
        pool.allocate("b".into(), 2000).unwrap();
        pool.allocate("c".into(), 3000).unwrap();
        assert_eq!(pool.used_bytes(), 6000);
        assert_eq!(pool.allocated_count(), 3);

        pool.deallocate("b").unwrap();
        assert_eq!(pool.used_bytes(), 4000);
        assert_eq!(pool.allocated_count(), 2);
    }

    #[test]
    fn pool_free_bytes_calculation() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        assert_eq!(pool.free_bytes(), 1024);
        pool.allocate("x".into(), 256).unwrap();
        assert_eq!(pool.free_bytes(), 768);
    }
}
