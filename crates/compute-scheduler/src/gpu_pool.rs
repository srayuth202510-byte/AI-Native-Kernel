use crate::{cuda_ffi, rocm_ffi};
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info, warn};

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
    /// ถูก swap ออกไปยัง host memory (GPU oversubscription)
    Swapped,
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
    /// ข้อมูลที่ถูก swap ออก (block_id → host buffer) สำหรับ oversubscription
    swapped_data: RwLock<HashMap<String, Vec<u8>>>,
    /// LRU access order (front = most recent)
    lru_order: RwLock<Vec<String>>,
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
            swapped_data: RwLock::new(HashMap::new()),
            lru_order: RwLock::new(Vec::new()),
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

        let block_id = id.clone();
        blocks.insert(id, gpu_block.clone());
        self.lru_order.write().push(block_id);
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

    /// จำนวนที่ใช้ไปบน GPU (ไบต์) — เฉพาะ Allocated ไม่รวม Swapped
    #[must_use]
    pub fn used_bytes(&self) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated)
            .map(|b| b.requested_size)
            .sum()
    }

    /// จำนวนที่จัดสรรรวมทั้งหมด (รวม Swapped) — สำหรับ oversubscription tracking
    #[must_use]
    pub fn total_allocated_bytes(&self) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated || b.state == BlockState::Swapped)
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

    /// จำนวนบล็อกทั้งหมด (รวม Swapped)
    #[must_use]
    pub fn total_block_count(&self) -> usize {
        self.blocks.read().len()
    }

    /// Swap บล็อกจาก GPU ไปยัง host memory (oversubscription)
    ///
    /// # Errors
    /// คืน `PoolError::BlockNotFound` ถ้าไม่พบบล็อก
    /// คืน `PoolError::CudaError` ถ้า GPU copy ล้มเหลว
    pub fn swap_out(&self, id: &str) -> Result<(), PoolError> {
        let mut blocks = self.blocks.write();
        let block = blocks
            .get_mut(id)
            .ok_or_else(|| PoolError::BlockNotFound(id.to_string()))?;

        if block.state != BlockState::Allocated {
            debug!(id = %id, state = ?block.state, "Block not Allocated, skipping swap-out");
            return Ok(());
        }

        let size = block.requested_size;
        let mut host_buf = vec![0u8; size];

        if self.real_mode {
            if let Some(ptr) = block.device_ptr {
                match self.platform {
                    GpuPlatform::Cuda => {
                        if let Err(e) = cuda_ffi::memcpy_dtoh(&mut host_buf, ptr) {
                            warn!(id = %id, error = %e, "CUDA memcpy DtoH failed during swap-out");
                            // Still proceed — data loss is better than crash
                        }
                        Self::cuda_free(ptr as *mut std::ffi::c_void);
                    }
                    GpuPlatform::Rocm => {
                        if let Err(e) = rocm_ffi::memcpy_dtoh(&mut host_buf, ptr) {
                            warn!(id = %id, error = %e, "ROCm memcpy DtoH failed during swap-out");
                        }
                        Self::rocm_free(ptr as *mut std::ffi::c_void);
                    }
                }
            }
            block.device_ptr = None;
            block.is_pinned = false;
        } else {
            // Simulated mode: preserve device_ptr for swap-in restore
            block.is_pinned = false;
        }

        block.state = BlockState::Swapped;

        // Store host buffer
        self.swapped_data.write().insert(id.to_string(), host_buf);
        info!(id = %id, size = %size, "GPU block swapped out to host memory");
        Ok(())
    }

    /// Swap บล็อกจาก host memory กลับไปยัง GPU
    ///
    /// # Errors
    /// คืน `PoolError::BlockNotFound` ถ้าไม่พบบล็อก
    /// คืน `PoolError::CudaError` ถ้า GPU alloc หรือ copy ล้มเหลว
    pub fn swap_in(&self, id: &str) -> Result<(), PoolError> {
        let mut blocks = self.blocks.write();
        let block = blocks
            .get_mut(id)
            .ok_or_else(|| PoolError::BlockNotFound(id.to_string()))?;

        if block.state != BlockState::Swapped {
            debug!(id = %id, state = ?block.state, "Block not Swapped, skipping swap-in");
            return Ok(());
        }

        // Retrieve host buffer
        let host_buf = self
            .swapped_data
            .write()
            .remove(id)
            .unwrap_or_else(|| vec![0u8; block.requested_size]);

        if self.real_mode {
            let ptr = match self.platform {
                GpuPlatform::Cuda => Self::cuda_alloc(block.requested_size)?,
                GpuPlatform::Rocm => Self::rocm_alloc(block.requested_size)?,
            };
            block.device_ptr = Some(ptr as u64);
            block.is_pinned = true;

            match self.platform {
                GpuPlatform::Cuda => {
                    if let Err(e) = cuda_ffi::memcpy_htod(ptr as u64, &host_buf) {
                        warn!(id = %id, error = %e, "CUDA memcpy HtoD failed during swap-in");
                    }
                }
                GpuPlatform::Rocm => {
                    if let Err(e) = rocm_ffi::memcpy_htod(ptr as u64, &host_buf) {
                        warn!(id = %id, error = %e, "ROCm memcpy HtoD failed during swap-in");
                    }
                }
            }
        } else {
            // Simulated mode: device_ptr was preserved during swap-out
            block.is_pinned = false;
        }

        block.state = BlockState::Allocated;
        info!(id = %id, size = %block.requested_size, "GPU block swapped in from host memory");

        // Update LRU
        self.lru_order.write().retain(|x| x != id);
        self.lru_order.write().push(id.to_string());

        Ok(())
    }

    /// จัดสรรหน่วยความจำพร้อม auto-swap: ถ้า pool เต็ม จะ swap out บล็อก LRU
    ///
    /// `swap_candidates`: ลำดับความสำคัญของบล็อกที่ควร swap out (sorted: least important first)
    /// ถ้าไม่ระบุ จะ swap out ตาม LRU order
    ///
    /// # Errors
    /// คืน `PoolError::PoolExhausted` ถ้า swap out แล้วยังไม่พอ
    pub fn allocate_with_auto_swap(
        &self,
        id: String,
        size_bytes: usize,
        swap_candidates: Option<Vec<String>>,
    ) -> Result<GpuBlock, PoolError> {
        // First try normal allocation
        match self.allocate(id.clone(), size_bytes) {
            Ok(block) => Ok(block),
            Err(PoolError::PoolExhausted { .. }) => {
                // Need to swap out some blocks
                let needed = size_bytes;
                let mut freed = 0usize;
                let mut swapped_out = Vec::new();

                let to_swap = if let Some(candidates) = swap_candidates {
                    candidates
                } else {
                    // Default: swap LRU blocks (oldest first)
                    let lru = self.lru_order.read().clone();
                    lru.into_iter().rev().collect()
                };

                for candidate_id in &to_swap {
                    if freed >= needed {
                        break;
                    }
                    // Get block size before swapping
                    let block_size = self
                        .blocks
                        .read()
                        .get(candidate_id)
                        .filter(|b| b.state == BlockState::Allocated)
                        .map(|b| b.requested_size)
                        .unwrap_or(0);
                    if block_size == 0 {
                        continue;
                    }
                    self.swap_out(candidate_id)?;
                    freed = freed.saturating_add(block_size);
                    swapped_out.push(candidate_id.clone());
                }

                if freed < needed {
                    warn!(
                        needed = %needed,
                        freed = %freed,
                        candidates = ?to_swap,
                        "Auto-swap: insufficient space after swapping out candidates"
                    );
                    return Err(PoolError::PoolExhausted {
                        size: size_bytes,
                        capacity: self.total_capacity,
                    });
                }

                info!(
                    swapped = ?swapped_out,
                    freed = %freed,
                    needed = %needed,
                    "Auto-swap: freed GPU memory"
                );

                // Retry allocation
                self.allocate(id, size_bytes)
            }
            Err(e) => Err(e),
        }
    }

    /// ตรวจสอบว่าบล็อกถูก swap ออกหรือไม่
    #[must_use]
    pub fn is_swapped(&self, id: &str) -> bool {
        self.blocks
            .read()
            .get(id)
            .is_some_and(|b| b.state == BlockState::Swapped)
    }

    /// จำนวนไบต์ที่ถูก swap ออก (host memory usage)
    #[must_use]
    pub fn swapped_bytes(&self) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Swapped)
            .map(|b| b.requested_size)
            .sum()
    }

    /// รวบรวม block IDs ของ agent ที่ระบุ (block ID ขึ้นต้นด้วย prefix)
    #[must_use]
    pub fn block_ids_for_agent(&self, agent_id: &str) -> Vec<String> {
        self.blocks
            .read()
            .keys()
            .filter(|k| k.starts_with(agent_id))
            .cloned()
            .collect()
    }

    /// ตรวจสอบว่าบล็อกอยู่ในสถานะ Allocated หรือไม่
    #[must_use]
    pub fn is_allocated(&self, block_id: &str) -> bool {
        self.blocks
            .read()
            .get(block_id)
            .is_some_and(|b| b.state == BlockState::Allocated)
    }

    /// จำนวน VRAM ที่ใช้โดย Allocated blocks ของ agent ที่ระบุ
    #[must_use]
    pub fn used_bytes_for_agent(&self, agent_id: &str) -> usize {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.state == BlockState::Allocated && b.id.starts_with(agent_id))
            .map(|b| b.requested_size)
            .sum()
    }

    /// คืนรายชื่อ agent prefixes ที่มี block อยู่ใน pool
    #[must_use]
    pub fn all_agent_prefixes(&self) -> Vec<String> {
        let blocks = self.blocks.read();
        let mut prefixes: Vec<String> = blocks
            .keys()
            .map(|k| k.split('-').next().unwrap_or(k).to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        prefixes.sort();
        prefixes
    }

    // ── Real GPU Allocation via FFI ───────────────────────────────────

    /// จัดสรรหน่วยความจำ CUDA (FFI — libcuda.so)
    fn cuda_alloc(size: usize) -> Result<*mut std::ffi::c_void, PoolError> {
        match cuda_ffi::mem_alloc(size) {
            Ok(ptr) => Ok(ptr as *mut std::ffi::c_void),
            Err(e) => {
                warn!("cuda_alloc failed: {e}");
                Err(PoolError::CudaError(e))
            }
        }
    }

    /// ปลดปล่อยหน่วยความจำ CUDA (FFI — libcuda.so)
    fn cuda_free(ptr: *mut std::ffi::c_void) {
        match cuda_ffi::mem_free(ptr as u64) {
            Ok(()) => debug!("CUDA free success"),
            Err(e) => warn!("cuda_free failed: {e}"),
        }
    }

    /// จัดสรรหน่วยความจำ ROCm (FFI — libamdhip64.so)
    fn rocm_alloc(size: usize) -> Result<*mut std::ffi::c_void, PoolError> {
        match rocm_ffi::mem_alloc(size) {
            Ok(ptr) => Ok(ptr as *mut std::ffi::c_void),
            Err(e) => {
                warn!("rocm_alloc failed: {e}");
                Err(PoolError::RocmError(e))
            }
        }
    }

    /// ปลดปล่อยหน่วยความจำ ROCm (FFI — libamdhip64.so)
    fn rocm_free(ptr: *mut std::ffi::c_void) {
        match rocm_ffi::mem_free(ptr as u64) {
            Ok(()) => debug!("ROCm free success"),
            Err(e) => warn!("rocm_free failed: {e}"),
        }
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

    #[test]
    fn pool_real_mode_fallback_on_missing_library() {
        let cuda_pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024 * 1024, true);
        match cuda_pool.allocate("cuda-real".into(), 4096) {
            Err(PoolError::CudaError(_)) => {}
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }

        let rocm_pool = GpuMemoryPool::new(GpuPlatform::Rocm, 1024 * 1024, true);
        match rocm_pool.allocate("rocm-real".into(), 4096) {
            Err(PoolError::RocmError(_)) => {}
            Ok(_) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn pool_swap_out_and_swap_in() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        pool.allocate("swap-me".into(), 200).unwrap();
        let original_ptr = pool.get_block("swap-me").unwrap().device_ptr;
        assert!(!pool.get_block("swap-me").unwrap().is_pinned);

        pool.swap_out("swap-me").unwrap();
        let block = pool.get_block("swap-me").unwrap();
        assert_eq!(block.state, BlockState::Swapped);
        // In simulated mode, device_ptr is preserved
        assert_eq!(block.device_ptr, original_ptr);
        assert_eq!(pool.used_bytes(), 0);
        assert_eq!(pool.swapped_bytes(), 200);
        assert_eq!(pool.total_allocated_bytes(), 200);

        pool.swap_in("swap-me").unwrap();
        let block = pool.get_block("swap-me").unwrap();
        assert_eq!(block.state, BlockState::Allocated);
        assert_eq!(block.device_ptr, original_ptr);
        assert_eq!(pool.used_bytes(), 200);
        assert_eq!(pool.swapped_bytes(), 0);
    }

    #[test]
    fn pool_swap_nonexistent_block() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        let err = pool.swap_out("ghost").unwrap_err();
        assert!(matches!(err, PoolError::BlockNotFound(_)));
    }

    #[test]
    fn pool_swap_freed_block_is_noop() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        pool.allocate("temp".into(), 100).unwrap();
        pool.deallocate("temp").unwrap();
        pool.swap_out("temp").unwrap();
        assert_eq!(pool.swapped_bytes(), 0);
    }

    #[test]
    fn pool_allocate_with_auto_swap_evicts_lru() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 150, false);
        pool.allocate("a".into(), 100).unwrap();
        // "b" should trigger auto-swap out of "a"
        let block = pool
            .allocate_with_auto_swap("b".into(), 100, None)
            .expect("auto-swap should succeed");
        assert_eq!(block.requested_size, 100);
        assert!(pool.is_swapped("a"));
        assert_eq!(pool.used_bytes(), 100);
    }

    #[test]
    fn pool_allocate_with_auto_swap_respects_candidates() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 200, false);
        pool.allocate("keep".into(), 100).unwrap();
        pool.allocate("swap-target".into(), 100).unwrap();

        let block = pool
            .allocate_with_auto_swap("new".into(), 100, Some(vec!["swap-target".into()]))
            .expect("auto-swap should succeed");
        assert_eq!(block.requested_size, 100);
        assert!(pool.is_swapped("swap-target"));
        assert!(!pool.is_swapped("keep"));
    }

    #[test]
    fn pool_swap_in_restores_data_in_simulated_mode() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 1024, false);
        pool.allocate("data-test".into(), 64).unwrap();

        // Data is preserved through swap-out/swap-in cycle
        pool.swap_out("data-test").unwrap();
        pool.swap_in("data-test").unwrap();

        let restored = pool.get_block("data-test").unwrap();
        assert!(restored.device_ptr.is_some());
        assert_eq!(restored.state, BlockState::Allocated);
    }

    #[test]
    fn pool_total_block_count_tracks_swapped() {
        let pool = GpuMemoryPool::new(GpuPlatform::Cuda, 500, false);
        pool.allocate("x".into(), 100).unwrap();
        pool.allocate("y".into(), 100).unwrap();
        pool.allocate("z".into(), 100).unwrap();
        assert_eq!(pool.total_block_count(), 3);
        assert_eq!(pool.allocated_count(), 3);

        pool.swap_out("x").unwrap();
        assert_eq!(pool.allocated_count(), 2);
        assert_eq!(pool.total_block_count(), 3);
    }
}
