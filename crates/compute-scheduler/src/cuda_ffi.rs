use libloading::{Library, Symbol};
use std::sync::OnceLock;
use tracing::debug;

/// CUDA Driver API return code indicating success.
const CUDA_SUCCESS: u32 = 0;

/// สถานะการโหลด CUDA library
struct CudaContext {
    lib: Library,
}

static CUDA_CTX: OnceLock<Result<CudaContext, String>> = OnceLock::new();

fn get_cuda_ctx() -> Result<&'static CudaContext, &'static str> {
    CUDA_CTX
        .get_or_init(|| {
            debug!("Loading CUDA Driver API library (libcuda.so)");
            // Safety: libloading::Library::new is unsafe because loading a shared
            // library can execute arbitrary code in constructors. We accept this
            // risk since the user explicitly requests CUDA support.
            unsafe {
                Library::new("libcuda.so.1")
                    .or_else(|_| Library::new("libcuda.so"))
                    .map(|lib| CudaContext { lib })
                    .map_err(|e| format!("cannot load libcuda.so: {e}"))
            }
        })
        .as_ref()
        .map_err(|e| e.as_str())
}

/// จัดสรรหน่วยความจำบน GPU ด้วย CUDA Driver API (cuMemAlloc)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด CUDA library หรือ cuMemAlloc ล้มเหลว
pub fn mem_alloc(size: usize) -> Result<u64, String> {
    let ctx = get_cuda_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut u64, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"cuMemAlloc")
            .map_err(|e| format!("symbol cuMemAlloc not found: {e}"))?
    };
    let mut ptr: u64 = 0;
    let ret = unsafe { func(&mut ptr, size) };
    if ret == CUDA_SUCCESS {
        debug!(ptr = %ptr, size = %size, "CUDA cuMemAlloc success");
        Ok(ptr)
    } else {
        Err(format!("cuMemAlloc failed with error code {ret}"))
    }
}

/// ปลดปล่อยหน่วยความจำบน GPU ด้วย CUDA Driver API (cuMemFree)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด CUDA library หรือ cuMemFree ล้มเหลว
pub fn mem_free(ptr: u64) -> Result<(), String> {
    let ctx = get_cuda_ctx()?;
    let func: Symbol<unsafe extern "C" fn(u64) -> u32> = unsafe {
        ctx.lib
            .get(b"cuMemFree")
            .map_err(|e| format!("symbol cuMemFree not found: {e}"))?
    };
    let ret = unsafe { func(ptr) };
    if ret == CUDA_SUCCESS {
        debug!(ptr = %ptr, "CUDA cuMemFree success");
        Ok(())
    } else {
        Err(format!("cuMemFree failed with error code {ret}"))
    }
}

/// ตรวจสอบว่า CUDA runtime พร้อมใช้งานหรือไม่
#[must_use]
pub fn is_available() -> bool {
    get_cuda_ctx().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cuda_ffi_check_available() {
        // This may return false on machines without CUDA — just verify it doesn't panic
        let _ = is_available();
    }
}
