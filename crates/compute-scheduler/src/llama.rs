use std::ffi::{CString, c_char, c_void};
use std::ptr;

// ลิงก์กับ libdl สำหรับโหลด dynamic library (llama.cpp) ตอน runtime
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: std::os::raw::c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> std::os::raw::c_int;
}

/// ชนิด opaque pointer สำหรับโมเดลของ llama.cpp
pub type LlamaModel = c_void;
/// ชนิด opaque pointer สำหรับ context ของ llama.cpp
pub type LlamaContext = c_void;

/// พารามิเตอร์สำหรับสร้างโมเดลใน llama.cpp (ตรงกับ struct llama_model_params ใน C)
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaModelParams {
    /// อุปกรณ์ที่ใช้ (GPU devices)
    pub devices: *mut c_void,
    /// การ override tensor buffer
    pub tensor_buft_overrides: *const c_void,
    /// จำนวน GPU layers
    pub n_gpu_layers: i32,
    /// โหมด split สำหรับ multi-GPU
    pub split_mode: i32,
    /// GPU หลัก
    pub main_gpu: i32,
    /// การแบ่ง tensor ข้าม GPU
    pub tensor_split: *const f32,
    /// callback สำหรับรายงานความคืบหน้า
    pub progress_callback: *mut c_void,
    /// user data สำหรับ progress callback
    pub progress_callback_user_data: *mut c_void,
    /// การ override ค่า KV cache
    pub kv_overrides: *const c_void,
    /// โหลดเฉพาะ vocab (ไม่รวม weights)
    pub vocab_only: bool,
    /// ใช้ memory-mapped file
    pub use_mmap: bool,
    /// ใช้ direct I/O
    pub use_direct_io: bool,
    /// ใช้ mlock เพื่อป้องกัน swapping
    pub use_mlock: bool,
    /// ตรวจสอบ tensor consistency
    pub check_tensors: bool,
    /// ใช้ extra buffer types
    pub use_extra_bufts: bool,
    /// ห้ามใช้ host buffer
    pub no_host: bool,
    /// ห้าม allocation
    pub no_alloc: bool,
}

/// พารามิเตอร์สำหรับสร้าง context ใน llama.cpp (ตรงกับ struct llama_context_params ใน C)
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaContextParams {
    /// ขนาด context window (จำนวน token)
    pub n_ctx: u32,
    /// ขนาด batch สำหรับการประมวลผล
    pub n_batch: u32,
    /// ขนาด microbatch
    pub n_ubatch: u32,
    /// จำนวน sequence สูงสุด
    pub n_seq_max: u32,
    /// จำนวน RS sequence
    pub n_rs_seq: u32,
    /// จำนวน output สูงสุด
    pub n_outputs_max: u32,
    /// จำนวน thread สำหรับการประมวลผล
    pub n_threads: i32,
    /// จำนวน thread สำหรับ batch processing
    pub n_threads_batch: i32,
    /// ประเภท context
    pub ctx_type: i32,
    /// ประเภท RoPE scaling
    pub rope_scaling_type: i32,
    /// ประเภท pooling
    pub pooling_type: i32,
    /// ประเภท attention
    pub attention_type: i32,
    /// ประเภท flash attention
    pub flash_attn_type: i32,
    /// ความถี่ฐานสำหรับ RoPE
    pub rope_freq_base: f32,
    /// สเกลความถี่ RoPE
    pub rope_freq_scale: f32,
    /// ปัจจัยขยาย Yarn
    pub yarn_ext_factor: f32,
    /// ปัจจัย attention Yarn
    pub yarn_attn_factor: f32,
    /// ค่า beta_fast Yarn
    pub yarn_beta_fast: f32,
    /// ค่า beta_slow Yarn
    pub yarn_beta_slow: f32,
    /// ขนาด context ดั้งเดิมสำหรับ Yarn
    pub yarn_orig_ctx: u32,
    /// threshold สำหรับ defragmentation
    pub defrag_thold: f32,
    /// callback สำหรับ evaluation
    pub cb_eval: *mut c_void,
    /// user data สำหรับ evaluation callback
    pub cb_eval_user_data: *mut c_void,
    /// ประเภท K tensor quantization
    pub type_k: i32,
    /// ประเภท V tensor quantization
    pub type_v: i32,
    /// callback สำหรับ abort
    pub abort_callback: *mut c_void,
    /// data สำหรับ abort callback
    pub abort_callback_data: *mut c_void,
    /// เปิดใช้งาน embedding mode
    pub embeddings: bool,
    /// offload KQV ไป GPU
    pub offload_kqv: bool,
    /// ปิด performance counters
    pub no_perf: bool,
    /// เปิด op offloading
    pub op_offload: bool,
    /// ใช้ SWA (Sliding Window Attention) เต็มรูปแบบ
    pub swa_full: bool,
    /// รวม KV cache (unified)
    pub kv_unified: bool,
    /// samplers ที่ใช้
    pub samplers: *mut c_void,
    /// จำนวน samplers
    pub n_samplers: usize,
    /// context อื่น ๆ
    pub ctx_other: *mut c_void,
}

/// ไลบรารี llama.cpp ที่โหลดแบบ dynamic (dlopen/dlsym)
pub struct LlamaLib {
    /// handle จาก dlopen
    handle: *mut c_void,
    /// ฟังก์ชันเริ่มต้น backend
    pub llama_backend_init: unsafe extern "C" fn(),
    /// ฟังก์ชันปิด backend
    pub llama_backend_free: unsafe extern "C" fn(),
    /// ฟังก์ชันดึงค่าเริ่มต้นของ model params
    pub llama_model_default_params: unsafe extern "C" fn() -> LlamaModelParams,
    /// ฟังก์ชันดึงค่าเริ่มต้นของ context params
    pub llama_context_default_params: unsafe extern "C" fn() -> LlamaContextParams,
    /// ฟังก์ชันโหลดโมเดลจากไฟล์
    pub llama_load_model_from_file:
        unsafe extern "C" fn(path: *const c_char, params: LlamaModelParams) -> *mut LlamaModel,
    /// ฟังก์ชันปล่อยโมเดล
    pub llama_free_model: unsafe extern "C" fn(model: *mut LlamaModel),
    /// ฟังก์ชันสร้าง context ใหม่จากโมเดล
    pub llama_new_context_with_model: unsafe extern "C" fn(
        model: *mut LlamaModel,
        params: LlamaContextParams,
    ) -> *mut LlamaContext,
    /// ฟังก์ชันปล่อย context
    pub llama_free: unsafe extern "C" fn(ctx: *mut LlamaContext),
}

/// แปลง string เป็น CString สำหรับส่งให้ฟังก์ชัน C
fn make_cstring(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("CString input contains interior NUL: {value:?}"))
}

impl LlamaLib {
    /// โหลดไลบรารี llama.cpp จาก paths ที่รู้จัก
    /// คืนค่า LlamaLib ที่มี function pointers ทั้งหมดถ้าโหลดสำเร็จ
    #[allow(clippy::missing_transmute_annotations)]
    pub fn load() -> Result<Self, String> {
        // paths ที่จะลองค้นหา libllama.so
        let paths = [
            "libllama.so",
            "/usr/local/lib/ollama/libllama.so",
            "/usr/lib/libllama.so",
        ];

        let mut handle = ptr::null_mut();
        for path in &paths {
            let cpath = make_cstring(path)?;
            // RTLD_NOW = 2
            handle = unsafe { dlopen(cpath.as_ptr(), 2) };
            if !handle.is_null() {
                break;
            }
        }

        if handle.is_null() {
            return Err("Failed to load libllama.so".to_string());
        }

        unsafe {
            let get_sym = |name: &str| -> Result<*mut c_void, String> {
                let cname = make_cstring(name)?;
                let sym = dlsym(handle, cname.as_ptr());
                if sym.is_null() {
                    return Err(format!("Symbol not found: {}", name));
                }
                Ok(sym)
            };

            Ok(Self {
                handle,
                llama_backend_init: std::mem::transmute(get_sym("llama_backend_init")?),
                llama_backend_free: std::mem::transmute(get_sym("llama_backend_free")?),
                llama_model_default_params: std::mem::transmute(get_sym(
                    "llama_model_default_params",
                )?),
                llama_context_default_params: std::mem::transmute(get_sym(
                    "llama_context_default_params",
                )?),
                llama_load_model_from_file: std::mem::transmute(get_sym(
                    "llama_load_model_from_file",
                )?),
                llama_free_model: std::mem::transmute(get_sym("llama_free_model")?),
                llama_new_context_with_model: std::mem::transmute(get_sym(
                    "llama_new_context_with_model",
                )?),
                llama_free: std::mem::transmute(get_sym("llama_free")?),
            })
        }
    }
}

impl Drop for LlamaLib {
    fn drop(&mut self) {
        // ปิดไลบรารีเมื่อ LlamaLib ถูก drop
        if !self.handle.is_null() {
            unsafe { dlclose(self.handle) };
        }
    }
}

/// ตัวจัดการ backend ของ llama.cpp
/// เรียก llama_backend_init เมื่อสร้าง และ llama_backend_free เมื่อ drop
pub struct LlamaBackend {
    /// ไลบรารี llama.cpp ที่โหลดไว้
    lib: LlamaLib,
}

impl LlamaBackend {
    /// เริ่มต้น llama.cpp backend
    /// โหลด libllama.so และเรียก llama_backend_init
    pub fn init() -> Result<Self, String> {
        let lib = LlamaLib::load()?;
        unsafe {
            (lib.llama_backend_init)();
        }
        Ok(Self { lib })
    }

    /// ดึงค่าเริ่มต้นของพารามิเตอร์โมเดล
    #[must_use]
    pub fn get_default_model_params(&self) -> LlamaModelParams {
        unsafe { (self.lib.llama_model_default_params)() }
    }

    /// ดึงค่าเริ่มต้นของพารามิเตอร์ context
    #[must_use]
    pub fn get_default_context_params(&self) -> LlamaContextParams {
        unsafe { (self.lib.llama_context_default_params)() }
    }
}

impl Drop for LlamaBackend {
    fn drop(&mut self) {
        unsafe {
            (self.lib.llama_backend_free)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ทดสอบการโหลด libllama.so (ต้องตั้ง LLAMA_TEST=1 ถึงจะทำงาน)
    #[test]
    fn test_load_llama_lib() {
        if std::env::var("LLAMA_TEST").is_err() {
            println!("Skipping llama.cpp test (set LLAMA_TEST=1 to enable)");
            return;
        }
        match LlamaBackend::init() {
            Ok(backend) => {
                let model_params = backend.get_default_model_params();
                let ctx_params = backend.get_default_context_params();
                println!(
                    "Successfully loaded libllama.so, default n_gpu_layers: {}, n_ctx: {}",
                    model_params.n_gpu_layers, ctx_params.n_ctx
                );
            }
            Err(e) => {
                println!("Llama.cpp load failed: {e}");
            }
        }
    }
}
