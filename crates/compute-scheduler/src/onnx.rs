use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;
use thiserror::Error;
use tracing::{debug, info};

// Link against libdl on Linux for dynamic library loading
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: std::os::raw::c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> std::os::raw::c_int;
}

/// opaque handle ของ ONNX Runtime: สถานะ/ข้อผิดพลาดจากการเรียก API
pub type OrtStatus = c_void;
/// opaque handle ของ ONNX Runtime: environment กลาง (สร้างครั้งเดียวต่อ process)
pub type OrtEnv = c_void;
/// opaque handle ของ ONNX Runtime: session ของโมเดลที่โหลดแล้ว
pub type OrtSession = c_void;
/// opaque handle ของ ONNX Runtime: ตัวเลือกการสร้าง session
pub type OrtSessionOptions = c_void;
/// opaque handle ของ ONNX Runtime: ค่า tensor/ข้อมูลเข้า-ออก
pub type OrtValue = c_void;
/// opaque handle ของ ONNX Runtime: ข้อมูลตำแหน่งหน่วยความจำ (CPU/GPU)
pub type OrtMemoryInfo = c_void;
/// opaque handle ของ ONNX Runtime: ตัวจัดสรรหน่วยความจำ
pub type OrtAllocator = c_void;
/// opaque handle ของ ONNX Runtime: ข้อมูลชนิดของ input/output
pub type OrtTypeInfo = c_void;
/// opaque handle ของ ONNX Runtime: ชนิดและ shape ของ tensor
pub type OrtTensorTypeAndShapeInfo = c_void;

/// ตาราง function pointer (vtable) ของ ONNX Runtime C API
///
/// โครงสร้างต้องเรียงตรงกับ `OrtApi` ใน onnxruntime_c_api.h ทุกช่อง —
/// ช่องที่ไม่ใช้แทนด้วย `_padN` เพื่อรักษา offset ให้ถูกต้อง
/// (หมายเลข slot ในคอมเมนต์คือ index ในตารางต้นฉบับ)
#[allow(non_snake_case)]
#[repr(C)]
pub struct OrtApi {
    /// FFI slot 0: CreateStatus
    pub CreateStatus: Option<unsafe extern "C" fn(code: i32, msg: *const c_char) -> *mut OrtStatus>,
    /// FFI slot 1: GetErrorCode
    pub GetErrorCode: Option<unsafe extern "C" fn(status: *const OrtStatus) -> i32>,
    /// FFI slot 2: GetErrorMessage
    pub GetErrorMessage: Option<unsafe extern "C" fn(status: *const OrtStatus) -> *const c_char>,
    /// FFI slot 3: CreateEnv
    pub CreateEnv: Option<
        unsafe extern "C" fn(
            log_severity_level: i32,
            logid: *const c_char,
            out: *mut *mut OrtEnv,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 4: CreateEnvWithCustomLogger
    _pad4: *const c_void,
    /// FFI slot 5: EnableTelemetryEvents
    _pad5: *const c_void,
    /// FFI slot 6: DisableTelemetryEvents
    _pad6: *const c_void,
    /// FFI slot 7: CreateSession
    pub CreateSession: Option<
        unsafe extern "C" fn(
            env: *const OrtEnv,
            model_path: *const c_char,
            options: *const OrtSessionOptions,
            out: *mut *mut OrtSession,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 8: CreateSessionFromArray
    pub CreateSessionFromArray: Option<
        unsafe extern "C" fn(
            env: *const OrtEnv,
            model_data: *const u8,
            model_data_len: usize,
            options: *const OrtSessionOptions,
            out: *mut *mut OrtSession,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 9: Run
    pub Run: Option<
        unsafe extern "C" fn(
            session: *mut OrtSession,
            run_options: *const c_void,
            input_names: *const *const c_char,
            inputs: *const *const OrtValue,
            input_len: usize,
            output_names: *const *const c_char,
            outputs: *mut *mut OrtValue,
            output_len: usize,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 10: CreateSessionOptions
    pub CreateSessionOptions:
        Option<unsafe extern "C" fn(out: *mut *mut OrtSessionOptions) -> *mut OrtStatus>,
    /// FFI slot 11: SetOptimizationLevel
    pub SetOptimizationLevel:
        Option<unsafe extern "C" fn(options: *mut OrtSessionOptions, level: i32) -> *mut OrtStatus>,
    /// FFI slot 12: SetIntraOpNumThreads
    pub SetIntraOpNumThreads:
        Option<unsafe extern "C" fn(options: *mut OrtSessionOptions, n: i32) -> *mut OrtStatus>,
    /// FFI slot 13..14
    _pad13: *const c_void,
    _pad14: *const c_void,
    /// FFI slot 15: CreateTensorAsOrtValue
    pub CreateTensorAsOrtValue: Option<
        unsafe extern "C" fn(
            allocator: *mut OrtAllocator,
            shape: *const i64,
            shape_len: usize,
            type_: i32,
            out: *mut *mut OrtValue,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 16: CreateTensorWithDataAsOrtValue
    pub CreateTensorWithDataAsOrtValue: Option<
        unsafe extern "C" fn(
            mem_info: *const OrtMemoryInfo,
            data: *mut c_void,
            data_len: usize,
            shape: *const i64,
            shape_len: usize,
            type_: i32,
            out: *mut *mut OrtValue,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 17: IsTensor
    pub IsTensor:
        Option<unsafe extern "C" fn(value: *const OrtValue, out: *mut bool) -> *mut OrtStatus>,
    /// FFI slot 18: GetTensorMutableData
    pub GetTensorMutableData:
        Option<unsafe extern "C" fn(value: *mut OrtValue, out: *mut *mut c_void) -> *mut OrtStatus>,
    /// FFI slot 19..26 (8 fields)
    _pad19: [*const c_void; 8],
    /// FFI slot 27: AllocatorAlloc
    pub AllocatorAlloc: Option<
        unsafe extern "C" fn(
            allocator: *mut OrtAllocator,
            size: usize,
            out: *mut *mut u8,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 28: AllocatorFree
    pub AllocatorFree:
        Option<unsafe extern "C" fn(allocator: *mut OrtAllocator, ptr: *mut u8) -> *mut OrtStatus>,
    /// FFI slot 29: GetAllocatorWithDefaultOptions
    pub GetAllocatorWithDefaultOptions:
        Option<unsafe extern "C" fn(out: *mut *mut OrtAllocator) -> *mut OrtStatus>,
    /// FFI slot 30..34 (5 fields)
    _pad30: [*const c_void; 5],
    /// FFI slot 35: SessionGetInputCount
    pub SessionGetInputCount:
        Option<unsafe extern "C" fn(session: *const OrtSession, out: *mut usize) -> *mut OrtStatus>,
    /// FFI slot 36: SessionGetOutputCount
    pub SessionGetOutputCount:
        Option<unsafe extern "C" fn(session: *const OrtSession, out: *mut usize) -> *mut OrtStatus>,
    /// FFI slot 37: SessionGetInputName
    pub SessionGetInputName: Option<
        unsafe extern "C" fn(
            session: *const OrtSession,
            index: usize,
            allocator: *mut OrtAllocator,
            out: *mut *mut c_char,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 38: SessionGetOutputName
    pub SessionGetOutputName: Option<
        unsafe extern "C" fn(
            session: *const OrtSession,
            index: usize,
            allocator: *mut OrtAllocator,
            out: *mut *mut c_char,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 39: SessionGetInputTypeInfo
    pub SessionGetInputTypeInfo: Option<
        unsafe extern "C" fn(
            session: *const OrtSession,
            index: usize,
            out: *mut *mut OrtTypeInfo,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 40: SessionGetOutputTypeInfo
    pub SessionGetOutputTypeInfo: Option<
        unsafe extern "C" fn(
            session: *const OrtSession,
            index: usize,
            out: *mut *mut OrtTypeInfo,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 41..44 (4 fields)
    _pad41: [*const c_void; 4],
    /// FFI slot 45: CreateMemoryInfo
    pub CreateMemoryInfo: Option<
        unsafe extern "C" fn(
            name: *const c_char,
            type_: i32,
            id: i32,
            mem_type: i32,
            out: *mut *mut OrtMemoryInfo,
        ) -> *mut OrtStatus,
    >,
    /// FFI slot 46..89 (44 fields)
    _pad46: [*const c_void; 44],
    /// FFI slot 90: ReleaseStatus
    pub ReleaseStatus: Option<unsafe extern "C" fn(status: *mut OrtStatus)>,
    /// FFI slot 91: ReleaseMemoryInfo
    _pad91: *const c_void,
    /// FFI slot 92: ReleaseTensorTypeAndShapeInfo
    pub ReleaseTensorTypeAndShapeInfo:
        Option<unsafe extern "C" fn(info: *mut OrtTensorTypeAndShapeInfo)>,
    /// FFI slot 93: ReleaseTypeInfo
    pub ReleaseTypeInfo: Option<unsafe extern "C" fn(info: *mut OrtTypeInfo)>,
    /// FFI slot 94: ReleaseSession
    pub ReleaseSession: Option<unsafe extern "C" fn(session: *mut OrtSession)>,
    /// FFI slot 95: ReleaseSessionOptions
    pub ReleaseSessionOptions: Option<unsafe extern "C" fn(options: *mut OrtSessionOptions)>,
    /// FFI slot 96: ReleaseValue
    pub ReleaseValue: Option<unsafe extern "C" fn(ptr: *mut OrtValue)>,
    /// FFI slot 97: ReleaseAllocator
    pub ReleaseAllocator: Option<unsafe extern "C" fn(allocator: *mut OrtAllocator)>,
    /// FFI slot 98..100
    _pad98: [*const c_void; 3],
    /// FFI slot 101: ReleaseEnv
    pub ReleaseEnv: Option<unsafe extern "C" fn(env: *mut OrtEnv)>,
}

/// จุดเข้า (entry point) ของ ONNX Runtime C API — ได้จาก symbol `OrtGetApiBase`
#[allow(non_snake_case)]
#[repr(C)]
pub struct OrtApiBase {
    /// ขอ vtable [`OrtApi`] ตามเวอร์ชัน API ที่ระบุ
    pub GetApi: Option<unsafe extern "C" fn(api_version: u32) -> *const OrtApi>,
    /// อ่าน string เวอร์ชันของไลบรารี ONNX Runtime
    pub GetVersionString: Option<unsafe extern "C" fn() -> *const c_char>,
}

/// ข้อผิดพลาดจากการใช้งาน ONNX Runtime ผ่าน FFI
#[derive(Debug, Error)]
pub enum OnnxError {
    /// หา libonnxruntime.so ไม่พบบนระบบ
    #[error("ONNX Runtime library not found: {0}")]
    LibraryNotFound(String),
    /// การเรียก C API ล้มเหลว (สถานะไม่เป็น null)
    #[error("ONNX API error: {0}")]
    ApiError(String),
    /// สร้างหรือใช้งาน session ไม่สำเร็จ
    #[error("ONNX session error: {0}")]
    SessionError(String),
    /// การรัน inference ล้มเหลว
    #[error("ONNX inference error: {0}")]
    InferenceError(String),
}

/// ไลบรารี ONNX Runtime ที่โหลดผ่าน dlopen พร้อม vtable ที่ resolve แล้ว
pub struct OnnxRuntimeLib {
    handle: *mut c_void,
    /// vtable ของ C API (อายุ static — ชี้เข้า memory ของไลบรารีที่โหลดค้างไว้)
    pub api: &'static OrtApi,
}

fn make_cstring(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("CString input contains interior NUL: {value:?}"))
}

impl OnnxRuntimeLib {
    /// โหลด libonnxruntime.so จากพาธมาตรฐานแล้ว resolve vtable ของ C API
    pub fn load() -> Result<Self, String> {
        let paths = [
            "libonnxruntime.so",
            "libonnxruntime.so.1.23",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so.1.23",
            "/usr/lib/x86_64-linux-gnu/libonnxruntime.so",
        ];

        let mut handle = ptr::null_mut();
        for path in &paths {
            let cpath = make_cstring(path)?;
            handle = unsafe { dlopen(cpath.as_ptr(), 2) };
            if !handle.is_null() {
                break;
            }
        }

        if handle.is_null() {
            return Err("Failed to load libonnxruntime.so".to_string());
        }

        let symbol_name = make_cstring("OrtGetApiBase")?;
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

/// ONNX Runtime Environment — จัดการ lifecycle ของ ONNX Runtime library
pub struct OnnxEnvironment {
    lib: OnnxRuntimeLib,
    env_ptr: *mut OrtEnv,
}

unsafe impl Send for OnnxEnvironment {}
unsafe impl Sync for OnnxEnvironment {}

impl OnnxEnvironment {
    /// สร้าง ONNX Runtime environment ใหม่ (โหลดไลบรารีและเรียก CreateEnv)
    pub fn new(log_id: &str) -> Result<Self, OnnxError> {
        let lib = OnnxRuntimeLib::load().map_err(OnnxError::LibraryNotFound)?;
        let c_log_id = CString::new(log_id).map_err(|e| OnnxError::ApiError(e.to_string()))?;
        let mut env_ptr = ptr::null_mut();

        let create_env = lib
            .api
            .CreateEnv
            .ok_or_else(|| OnnxError::ApiError("CreateEnv pointer is null".into()))?;

        let status = unsafe { create_env(2, c_log_id.as_ptr(), &mut env_ptr) };
        if !status.is_null() {
            let msg = Self::extract_error(&lib, status);
            return Err(OnnxError::ApiError(msg));
        }

        info!(log_id = log_id, "ONNX Runtime environment created");
        Ok(Self { lib, env_ptr })
    }

    /// pointer ดิบของ environment สำหรับส่งต่อให้ C API
    #[must_use]
    pub fn env_ptr(&self) -> *mut OrtEnv {
        self.env_ptr
    }

    /// vtable ของ C API ที่ environment นี้ใช้อยู่
    #[must_use]
    pub fn api(&self) -> &'static OrtApi {
        self.lib.api
    }

    fn extract_error(api: &OnnxRuntimeLib, status: *mut OrtStatus) -> String {
        if let Some(get_err) = api.api.GetErrorMessage {
            let err_msg = unsafe { CStr::from_ptr(get_err(status)) };
            let msg = err_msg.to_string_lossy().into_owned();
            if let Some(release) = api.api.ReleaseStatus {
                unsafe { release(status) };
            }
            msg
        } else {
            "unknown error (GetErrorMessage not available)".to_string()
        }
    }
}

impl Drop for OnnxEnvironment {
    fn drop(&mut self) {
        if !self.env_ptr.is_null() {
            if let Some(release_env) = self.lib.api.ReleaseEnv {
                unsafe { release_env(self.env_ptr) };
            }
        }
    }
}

/// ONNX Session Options — ตั้งค่า optimization level และ thread count
pub struct OnnxSessionOptions {
    ptr: *mut OrtSessionOptions,
    api: &'static OrtApi,
}

unsafe impl Send for OnnxSessionOptions {}
unsafe impl Sync for OnnxSessionOptions {}

impl OnnxSessionOptions {
    /// สร้าง session options ใหม่จาก C API
    pub fn new(api: &'static OrtApi) -> Result<Self, OnnxError> {
        let mut ptr = ptr::null_mut();
        let create_opts = api
            .CreateSessionOptions
            .ok_or_else(|| OnnxError::ApiError("CreateSessionOptions not available".into()))?;

        let status = unsafe { create_opts(&mut ptr) };
        if !status.is_null() {
            return Err(OnnxError::ApiError("CreateSessionOptions failed".into()));
        }

        Ok(Self { ptr, api })
    }

    /// กำหนดจำนวน thread สำหรับ inference (intra-op parallelism)
    pub fn set_num_threads(&mut self, n: i32) -> Result<(), OnnxError> {
        if let Some(set_threads) = self.api.SetIntraOpNumThreads {
            let status = unsafe { set_threads(self.ptr, n) };
            if !status.is_null() {
                return Err(OnnxError::ApiError(format!(
                    "SetIntraOpNumThreads({n}) failed"
                )));
            }
        }
        Ok(())
    }

    /// ตั้งค่า optimization level (0=Disable, 1=Basic, 2=Extended, 99=All)
    pub fn set_optimization_level(&mut self, level: i32) -> Result<(), OnnxError> {
        if let Some(set_opt) = self.api.SetOptimizationLevel {
            let status = unsafe { set_opt(self.ptr, level) };
            if !status.is_null() {
                return Err(OnnxError::ApiError(format!(
                    "SetOptimizationLevel({level}) failed"
                )));
            }
        }
        Ok(())
    }

    /// pointer ดิบของ options สำหรับส่งต่อให้ C API
    #[must_use]
    pub fn as_ptr(&self) -> *const OrtSessionOptions {
        self.ptr
    }
}

impl Drop for OnnxSessionOptions {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            if let Some(release) = self.api.ReleaseSessionOptions {
                unsafe { release(self.ptr) };
            }
        }
    }
}

/// ONNX Session — โหลดโมเดลและรัน inference
pub struct OnnxSession {
    ptr: *mut OrtSession,
    api: &'static OrtApi,
    input_names: Vec<String>,
    output_names: Vec<String>,
}

unsafe impl Send for OnnxSession {}
unsafe impl Sync for OnnxSession {}

impl OnnxSession {
    /// โหลดโมเดลจากไฟล์
    pub fn from_file(
        env: &OnnxEnvironment,
        model_path: &str,
        options: &OnnxSessionOptions,
    ) -> Result<Self, OnnxError> {
        let c_path =
            CString::new(model_path).map_err(|e| OnnxError::SessionError(e.to_string()))?;

        let mut session_ptr = ptr::null_mut();
        let create_session = env
            .api()
            .CreateSession
            .ok_or_else(|| OnnxError::SessionError("CreateSession not available".into()))?;

        let status = unsafe {
            create_session(
                env.env_ptr(),
                c_path.as_ptr(),
                options.as_ptr(),
                &mut session_ptr,
            )
        };

        if !status.is_null() {
            return Err(OnnxError::SessionError(format!(
                "Failed to load model: {model_path}"
            )));
        }

        info!(model = model_path, "ONNX model loaded");

        let mut session = Self {
            ptr: session_ptr,
            api: env.api(),
            input_names: Vec::new(),
            output_names: Vec::new(),
        };

        // Query input/output names
        session.query_io_names()?;

        Ok(session)
    }

    /// โหลดโมเดลจาก byte array (ในหน่วยความจำ)
    pub fn from_bytes(
        env: &OnnxEnvironment,
        model_data: &[u8],
        options: &OnnxSessionOptions,
    ) -> Result<Self, OnnxError> {
        let mut session_ptr = ptr::null_mut();
        let create_from_array = env.api().CreateSessionFromArray.ok_or_else(|| {
            OnnxError::SessionError("CreateSessionFromArray not available".into())
        })?;

        let status = unsafe {
            create_from_array(
                env.env_ptr(),
                model_data.as_ptr(),
                model_data.len(),
                options.as_ptr(),
                &mut session_ptr,
            )
        };

        if !status.is_null() {
            return Err(OnnxError::SessionError(
                "Failed to create session from bytes".into(),
            ));
        }

        let mut session = Self {
            ptr: session_ptr,
            api: env.api(),
            input_names: Vec::new(),
            output_names: Vec::new(),
        };

        session.query_io_names()?;

        Ok(session)
    }

    fn query_io_names(&mut self) -> Result<(), OnnxError> {
        let mut allocator: *mut OrtAllocator = ptr::null_mut();
        if let Some(get_alloc) = self.api.GetAllocatorWithDefaultOptions {
            let status = unsafe { get_alloc(&mut allocator) };
            if !status.is_null() || allocator.is_null() {
                return Ok(()); // Non-fatal: we'll use generic names
            }
        }

        // Query input count and names
        if let Some(get_input_count) = self.api.SessionGetInputCount {
            let mut count: usize = 0;
            let status = unsafe { get_input_count(self.ptr, &mut count) };
            if status.is_null() {
                if let Some(get_name) = self.api.SessionGetInputName {
                    for i in 0..count {
                        let mut name_ptr: *mut c_char = ptr::null_mut();
                        let status = unsafe { get_name(self.ptr, i, allocator, &mut name_ptr) };
                        if status.is_null() && !name_ptr.is_null() {
                            let name = unsafe { CStr::from_ptr(name_ptr) }
                                .to_string_lossy()
                                .into_owned();
                            self.input_names.push(name);
                        }
                    }
                }
            }
        }

        // Query output count and names
        if let Some(get_output_count) = self.api.SessionGetOutputCount {
            let mut count: usize = 0;
            let status = unsafe { get_output_count(self.ptr, &mut count) };
            if status.is_null() {
                if let Some(get_name) = self.api.SessionGetOutputName {
                    for i in 0..count {
                        let mut name_ptr: *mut c_char = ptr::null_mut();
                        let status = unsafe { get_name(self.ptr, i, allocator, &mut name_ptr) };
                        if status.is_null() && !name_ptr.is_null() {
                            let name = unsafe { CStr::from_ptr(name_ptr) }
                                .to_string_lossy()
                                .into_owned();
                            self.output_names.push(name);
                        }
                    }
                }
            }
        }

        debug!(
            inputs = ?self.input_names,
            outputs = ?self.output_names,
            "ONNX session I/O names queried"
        );

        Ok(())
    }

    /// คืนรายชื่อ input tensors
    #[must_use]
    pub fn input_names(&self) -> &[String] {
        &self.input_names
    }

    /// คืนรายชื่อ output tensors
    #[must_use]
    pub fn output_names(&self) -> &[String] {
        &self.output_names
    }

    /// รัน inference ด้วย input data (f32 array)
    ///
    /// `input_name` — ชื่อ input tensor (ถ้าไม่ทราบ ใช้ input_names()[0])
    /// `shape` — รูปร่างของ input tensor (เช่น [1, 128] สำหรับ batch=1, seq_len=128)
    /// `data` — ข้อมูล input (f32 values)
    ///
    /// คืนค่า output data เป็น Vec<f32>
    pub fn run_inference(
        &self,
        input_name: Option<&str>,
        shape: &[i64],
        data: &[f32],
    ) -> Result<Vec<f32>, OnnxError> {
        let run_fn = self
            .api
            .Run
            .ok_or_else(|| OnnxError::InferenceError("Run not available".into()))?;

        let get_tensor_data = self.api.GetTensorMutableData.ok_or_else(|| {
            OnnxError::InferenceError("GetTensorMutableData not available".into())
        })?;

        let release_value_fn = self.api.ReleaseValue;

        let mut allocator: *mut OrtAllocator = ptr::null_mut();
        if let Some(get_alloc) = self.api.GetAllocatorWithDefaultOptions {
            unsafe { get_alloc(&mut allocator) };
        }

        // Create input tensor
        let c_input_name = CString::new(input_name.unwrap_or_else(|| {
            self.input_names
                .first()
                .map(|s| s.as_str())
                .unwrap_or("input")
        }))
        .map_err(|e| OnnxError::InferenceError(e.to_string()))?;

        let create_tensor = self.api.CreateTensorWithDataAsOrtValue.ok_or_else(|| {
            OnnxError::InferenceError("CreateTensorWithDataAsOrtValue not available".into())
        })?;

        // Create memory info (CPU, default)
        let mut mem_info: *mut OrtMemoryInfo = ptr::null_mut();
        let c_cpu = c"Cpu";
        if let Some(create_mem) = self.api.CreateMemoryInfo {
            let status = unsafe { create_mem(c_cpu.as_ptr(), 0, 0, 0, &mut mem_info) };
            if !status.is_null() || mem_info.is_null() {
                return Err(OnnxError::InferenceError(
                    "Failed to create memory info".into(),
                ));
            }
        }

        // ORT_ELEMENT_TYPE_FLOAT = 1
        let mut input_tensor: *mut OrtValue = ptr::null_mut();
        let byte_len = std::mem::size_of_val(data);
        let status = unsafe {
            create_tensor(
                mem_info,
                data.as_ptr() as *mut c_void,
                byte_len,
                shape.as_ptr(),
                shape.len(),
                1, // ORT_ELEMENT_TYPE_FLOAT
                &mut input_tensor,
            )
        };

        if !status.is_null() || input_tensor.is_null() {
            return Err(OnnxError::InferenceError(
                "Failed to create input tensor".into(),
            ));
        }

        // Prepare input/output arrays
        let input_names_raw = [c_input_name.as_ptr()];
        let mut output_tensor: *mut OrtValue = ptr::null_mut();

        // Determine output name
        let c_output_name = CString::new(
            self.output_names
                .first()
                .map(|s| s.as_str())
                .unwrap_or("output"),
        )
        .map_err(|e| OnnxError::InferenceError(e.to_string()))?;
        let output_names_raw = [c_output_name.as_ptr()];

        // Run inference
        let status = unsafe {
            run_fn(
                self.ptr,
                ptr::null(), // run_options
                input_names_raw.as_ptr(),
                input_tensor as *const *const OrtValue,
                1,
                output_names_raw.as_ptr(),
                &mut output_tensor,
                1,
            )
        };

        // Cleanup input tensor
        if let Some(release) = release_value_fn {
            unsafe { release(input_tensor) };
        }
        // Note: mem_info is managed by ONNX Runtime internally, no explicit release needed

        if !status.is_null() {
            return Err(OnnxError::InferenceError("Inference Run() failed".into()));
        }

        // Extract output data
        let mut out_data: *mut c_void = ptr::null_mut();
        let status = unsafe { get_tensor_data(output_tensor, &mut out_data) };

        if !status.is_null() || out_data.is_null() {
            if let Some(release) = release_value_fn {
                unsafe { release(output_tensor) };
            }
            return Err(OnnxError::InferenceError(
                "Failed to get output tensor data".into(),
            ));
        }

        // Determine output length from shape (assume flat f32)
        let out_len: usize = data.len(); // Same as input for most models
        let output: Vec<f32> =
            unsafe { std::slice::from_raw_parts(out_data as *const f32, out_len).to_vec() };

        if let Some(release) = release_value_fn {
            unsafe { release(output_tensor) };
        }

        debug!(output_len = output.len(), "ONNX inference completed");

        Ok(output)
    }
}

impl Drop for OnnxSession {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            if let Some(release) = self.api.ReleaseSession {
                unsafe { release(self.ptr) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_onnx_runtime() {
        // Skip if ONNX Runtime is not installed — dlopen may abort on missing libs
        if std::env::var("CI").is_ok() || std::env::var("ONNX_TEST").is_err() {
            println!("Skipping ONNX test (set ONNX_TEST=1 to enable)");
            return;
        }
        match OnnxEnvironment::new("test_log") {
            Ok(env) => {
                assert!(!env.env_ptr().is_null());
                println!("ONNX Runtime environment created successfully");
            }
            Err(e) => {
                println!("ONNX Runtime load failed: {e}");
            }
        }
    }

    #[test]
    fn test_session_options() {
        if std::env::var("ONNX_TEST").is_err() {
            return;
        }
        if let Ok(env) = OnnxEnvironment::new("test") {
            let mut opts = OnnxSessionOptions::new(env.api()).unwrap();
            opts.set_num_threads(4).unwrap();
            opts.set_optimization_level(2).unwrap();
        }
    }
}
