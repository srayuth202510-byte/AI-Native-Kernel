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

/// คัดลอกข้อมูลจาก GPU device → host (cuMemcpyDtoH)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด CUDA library หรือ cuMemcpyDtoH ล้มเหลว
pub fn memcpy_dtoh(dst: &mut [u8], src_ptr: u64) -> Result<(), String> {
    let ctx = get_cuda_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, u64, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"cuMemcpyDtoH")
            .map_err(|e| format!("symbol cuMemcpyDtoH not found: {e}"))?
    };
    let ret = unsafe { func(dst.as_mut_ptr() as *mut std::ffi::c_void, src_ptr, dst.len()) };
    if ret == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(format!("cuMemcpyDtoH failed with error code {ret}"))
    }
}

/// คัดลอกข้อมูลจาก host → GPU device (cuMemcpyHtoD)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด CUDA library หรือ cuMemcpyHtoD ล้มเหลว
pub fn memcpy_htod(dst_ptr: u64, src: &[u8]) -> Result<(), String> {
    let ctx = get_cuda_ctx()?;
    let func: Symbol<unsafe extern "C" fn(u64, *const std::ffi::c_void, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"cuMemcpyHtoD")
            .map_err(|e| format!("symbol cuMemcpyHtoD not found: {e}"))?
    };
    let ret = unsafe { func(dst_ptr, src.as_ptr() as *const std::ffi::c_void, src.len()) };
    if ret == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(format!("cuMemcpyHtoD failed with error code {ret}"))
    }
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
