use libloading::{Library, Symbol};
use std::sync::OnceLock;
use tracing::debug;

/// HIP error code indicating success.
const HIP_SUCCESS: u32 = 0;

/// สถานะการโหลด ROCm HIP library
struct HipContext {
    lib: Library,
}

static HIP_CTX: OnceLock<Result<HipContext, String>> = OnceLock::new();

fn get_hip_ctx() -> Result<&'static HipContext, &'static str> {
    HIP_CTX
        .get_or_init(|| {
            debug!("Loading ROCm HIP library (libamdhip64.so)");
            // Safety: libloading::Library::new is unsafe because loading a shared
            // library can execute arbitrary code in constructors. We accept this
            // risk since the user explicitly requests ROCm support.
            unsafe {
                Library::new("libamdhip64.so.6")
                    .or_else(|_| Library::new("libamdhip64.so.5"))
                    .or_else(|_| Library::new("libamdhip64.so"))
                    .map(|lib| HipContext { lib })
                    .map_err(|e| format!("cannot load libamdhip64.so: {e}"))
            }
        })
        .as_ref()
        .map_err(|e| e.as_str())
}

/// จัดสรรหน่วยความจำบน GPU ด้วย ROCm HIP API (hipMalloc)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด HIP library หรือ hipMalloc ล้มเหลว
pub fn mem_alloc(size: usize) -> Result<u64, String> {
    let ctx = get_hip_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut *mut std::ffi::c_void, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"hipMalloc")
            .map_err(|e| format!("symbol hipMalloc not found: {e}"))?
    };
    let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let ret = unsafe { func(&mut ptr, size) };
    if ret == HIP_SUCCESS {
        let addr = ptr as u64;
        debug!(ptr = %addr, size = %size, "ROCm hipMalloc success");
        Ok(addr)
    } else {
        Err(format!("hipMalloc failed with error code {ret}"))
    }
}

/// ปลดปล่อยหน่วยความจำบน GPU ด้วย ROCm HIP API (hipFree)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด HIP library หรือ hipFree ล้มเหลว
pub fn mem_free(ptr: u64) -> Result<(), String> {
    let ctx = get_hip_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut std::ffi::c_void) -> u32> = unsafe {
        ctx.lib
            .get(b"hipFree")
            .map_err(|e| format!("symbol hipFree not found: {e}"))?
    };
    let ret = unsafe { func(ptr as *mut std::ffi::c_void) };
    if ret == HIP_SUCCESS {
        debug!(ptr = %ptr, "ROCm hipFree success");
        Ok(())
    } else {
        Err(format!("hipFree failed with error code {ret}"))
    }
}

/// ตรวจสอบว่า ROCm HIP runtime พร้อมใช้งานหรือไม่
#[must_use]
pub fn is_available() -> bool {
    get_hip_ctx().is_ok()
}

/// คัดลอกข้อมูลระหว่าง host ↔ device ด้วย ROCm HIP API (hipMemcpy)
///
/// `kind`: 0 = HostToDevice, 1 = DeviceToHost, 2 = DeviceToDevice
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด HIP library หรือ hipMemcpy ล้มเหลว
pub fn memcpy(dst: u64, src: u64, size: usize, kind: i32) -> Result<(), String> {
    let ctx = get_hip_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, *const std::ffi::c_void, usize, i32) -> u32> = unsafe {
        ctx.lib
            .get(b"hipMemcpy")
            .map_err(|e| format!("symbol hipMemcpy not found: {e}"))?
    };
    let ret = unsafe { func(dst as *mut std::ffi::c_void, src as *const std::ffi::c_void, size, kind) };
    if ret == HIP_SUCCESS {
        Ok(())
    } else {
        Err(format!("hipMemcpy failed with error code {ret}"))
    }
}

/// คัดลอกข้อมูลจาก host → device (hipMemcpyHtoD wrapper)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด HIP library หรือ hipMemcpy ล้มเหลว
pub fn memcpy_htod(dst_ptr: u64, src: &[u8]) -> Result<(), String> {
    let ctx = get_hip_ctx()?;
    let func: Symbol<unsafe extern "C" fn(u64, *const std::ffi::c_void, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"hipMemcpyHtoD")
            .map_err(|e| format!("symbol hipMemcpyHtoD not found: {e}"))?
    };
    let ret = unsafe { func(dst_ptr, src.as_ptr() as *const std::ffi::c_void, src.len()) };
    if ret == HIP_SUCCESS {
        Ok(())
    } else {
        Err(format!("hipMemcpyHtoD failed with error code {ret}"))
    }
}

/// คัดลอกข้อมูลจาก device → host (hipMemcpyDtoH wrapper)
///
/// # Errors
/// คืน `String` หากไม่สามารถโหลด HIP library หรือ hipMemcpy ล้มเหลว
pub fn memcpy_dtoh(dst: &mut [u8], src_ptr: u64) -> Result<(), String> {
    let ctx = get_hip_ctx()?;
    let func: Symbol<unsafe extern "C" fn(*mut std::ffi::c_void, u64, usize) -> u32> = unsafe {
        ctx.lib
            .get(b"hipMemcpyDtoH")
            .map_err(|e| format!("symbol hipMemcpyDtoH not found: {e}"))?
    };
    let ret = unsafe { func(dst.as_mut_ptr() as *mut std::ffi::c_void, src_ptr, dst.len()) };
    if ret == HIP_SUCCESS {
        Ok(())
    } else {
        Err(format!("hipMemcpyDtoH failed with error code {ret}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rocm_ffi_check_available() {
        // May return false on machines without ROCm — just verify no panic
        let _ = is_available();
    }
}
