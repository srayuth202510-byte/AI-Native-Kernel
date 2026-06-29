use std::ffi::{CString, c_char, c_void};
use std::ptr;

// Link against libdl on Linux for dynamic library loading
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: std::os::raw::c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> std::os::raw::c_int;
}

pub type OrtStatus = c_void;
pub type OrtEnv = c_void;
pub type OrtSession = c_void;
pub type OrtSessionOptions = c_void;

#[allow(non_snake_case)]
#[repr(C)]
pub struct OrtApi {
    // 0: CreateStatus
    pub CreateStatus: Option<unsafe extern "C" fn(code: i32, msg: *const c_char) -> *mut OrtStatus>,
    // 1: GetErrorCode
    pub GetErrorCode: Option<unsafe extern "C" fn(status: *const OrtStatus) -> i32>,
    // 2: GetErrorMessage
    pub GetErrorMessage: Option<unsafe extern "C" fn(status: *const OrtStatus) -> *const c_char>,
    // 3: CreateEnv
    pub CreateEnv: Option<
        unsafe extern "C" fn(
            log_severity_level: i32,
            logid: *const c_char,
            out: *mut *mut OrtEnv,
        ) -> *mut OrtStatus,
    >,

    // 4..6 (3 fields)
    _pad1: [*const c_void; 3],

    // 7: CreateSession
    pub CreateSession: Option<
        unsafe extern "C" fn(
            env: *const OrtEnv,
            model_path: *const c_char,
            options: *const OrtSessionOptions,
            out: *mut *mut OrtSession,
        ) -> *mut OrtStatus,
    >,

    // 8..9 (2 fields)
    _pad2: [*const c_void; 2],

    // 10: CreateSessionOptions
    pub CreateSessionOptions:
        Option<unsafe extern "C" fn(out: *mut *mut OrtSessionOptions) -> *mut OrtStatus>,

    // 11..91 (81 fields)
    _pad3: [*const c_void; 81],

    // 92: ReleaseEnv
    pub ReleaseEnv: Option<unsafe extern "C" fn(env: *mut OrtEnv)>,
    // 93: ReleaseStatus
    pub ReleaseStatus: Option<unsafe extern "C" fn(status: *mut OrtStatus)>,

    // 94 (1 field)
    _pad4: [*const c_void; 1],

    // 95: ReleaseSession
    pub ReleaseSession: Option<unsafe extern "C" fn(session: *mut OrtSession)>,

    // 96..99 (4 fields)
    _pad5: [*const c_void; 4],

    // 100: ReleaseSessionOptions
    pub ReleaseSessionOptions: Option<unsafe extern "C" fn(options: *mut OrtSessionOptions)>,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct OrtApiBase {
    pub GetApi: Option<unsafe extern "C" fn(api_version: u32) -> *const OrtApi>,
    pub GetVersionString: Option<unsafe extern "C" fn() -> *const c_char>,
}

pub struct OnnxRuntimeLib {
    handle: *mut c_void,
    pub api: &'static OrtApi,
}

impl OnnxRuntimeLib {
    pub fn load() -> Result<Self, String> {
        let paths = [
            "libonnxruntime.so",
            "libonnxruntime.so.1.23",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so.1.23",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ];

        let mut handle = ptr::null_mut();
        for path in &paths {
            let cpath = CString::new(*path).unwrap();
            // RTLD_NOW = 2
            handle = unsafe { dlopen(cpath.as_ptr(), 2) };
            if !handle.is_null() {
                break;
            }
        }

        if handle.is_null() {
            return Err("Failed to load libonnxruntime.so".to_string());
        }

        let symbol_name = CString::new("OrtGetApiBase").unwrap();
        let sym = unsafe { dlsym(handle, symbol_name.as_ptr()) };
        if sym.is_null() {
            unsafe { dlclose(handle) };
            return Err("Failed to find OrtGetApiBase symbol".to_string());
        }

        type GetApiBaseFn = unsafe extern "C" fn() -> *const OrtApiBase;
        let get_api_base: GetApiBaseFn = unsafe { std::mem::transmute(sym) };

        let api_base = unsafe { get_api_base() };
        if api_base.is_null() {
            unsafe { dlclose(handle) };
            return Err("OrtGetApiBase returned null".to_string());
        }

        let get_api = unsafe {
            (*api_base)
                .GetApi
                .ok_or_else(|| "GetApi function pointer is null".to_string())?
        };
        // ONNX Runtime API version 15 corresponds to v1.16+
        let api = unsafe { get_api(15) };
        if api.is_null() {
            unsafe { dlclose(handle) };
            return Err("GetApi(15) returned null".to_string());
        }

        Ok(Self {
            handle,
            api: unsafe { &*api },
        })
    }
}

impl Drop for OnnxRuntimeLib {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { dlclose(self.handle) };
        }
    }
}

pub struct OnnxEnvironment {
    _lib: OnnxRuntimeLib,
    env_ptr: *mut OrtEnv,
}

impl OnnxEnvironment {
    pub fn new(log_id: &str) -> Result<Self, String> {
        let lib = OnnxRuntimeLib::load()?;
        let c_log_id = CString::new(log_id).map_err(|e| e.to_string())?;
        let mut env_ptr = ptr::null_mut();

        let create_env = lib
            .api
            .CreateEnv
            .ok_or_else(|| "CreateEnv pointer is null".to_string())?;

        // severity level 0 = ORT_LOGGING_LEVEL_VERBOSE
        let status = unsafe { create_env(0, c_log_id.as_ptr(), &mut env_ptr) };
        if !status.is_null() {
            if let Some(get_err) = lib.api.GetErrorMessage {
                let err_msg = unsafe { std::ffi::CStr::from_ptr(get_err(status)) };
                let msg = err_msg.to_string_lossy().into_owned();
                if let Some(release_status) = lib.api.ReleaseStatus {
                    unsafe { release_status(status) };
                }
                return Err(format!("CreateEnv failed: {}", msg));
            }
            return Err("CreateEnv failed".to_string());
        }

        Ok(Self { _lib: lib, env_ptr })
    }

    #[must_use]
    pub fn env_ptr(&self) -> *mut OrtEnv {
        self.env_ptr
    }
}

impl Drop for OnnxEnvironment {
    fn drop(&mut self) {
        if !self.env_ptr.is_null() {
            if let Some(release_env) = self._lib.api.ReleaseEnv {
                unsafe { release_env(self.env_ptr) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_onnx_runtime() {
        match OnnxEnvironment::new("test_log") {
            Ok(env) => {
                assert!(!env.env_ptr().is_null());
                println!("Successfully created ONNX environment via dynamic loading FFI!");
            }
            Err(e) => {
                println!(
                    "ONNX Runtime load failed (expected if library not installed): {}",
                    e
                );
            }
        }
    }
}
