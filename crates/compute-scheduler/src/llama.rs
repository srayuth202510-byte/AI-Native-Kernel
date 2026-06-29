use std::ffi::{CString, c_char, c_void};
use std::ptr;

// Link against libdl on Linux for dynamic library loading
#[link(name = "dl")]
unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: std::os::raw::c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> std::os::raw::c_int;
}

pub type LlamaModel = c_void;
pub type LlamaContext = c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaModelParams {
    pub devices: *mut c_void,
    pub tensor_buft_overrides: *const c_void,
    pub n_gpu_layers: i32,
    pub split_mode: i32,
    pub main_gpu: i32,
    pub tensor_split: *const f32,
    pub progress_callback: *mut c_void,
    pub progress_callback_user_data: *mut c_void,
    pub kv_overrides: *const c_void,
    pub vocab_only: bool,
    pub use_mmap: bool,
    pub use_direct_io: bool,
    pub use_mlock: bool,
    pub check_tensors: bool,
    pub use_extra_bufts: bool,
    pub no_host: bool,
    pub no_alloc: bool,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LlamaContextParams {
    pub n_ctx: u32,
    pub n_batch: u32,
    pub n_ubatch: u32,
    pub n_seq_max: u32,
    pub n_rs_seq: u32,
    pub n_outputs_max: u32,
    pub n_threads: i32,
    pub n_threads_batch: i32,
    pub ctx_type: i32,
    pub rope_scaling_type: i32,
    pub pooling_type: i32,
    pub attention_type: i32,
    pub flash_attn_type: i32,
    pub rope_freq_base: f32,
    pub rope_freq_scale: f32,
    pub yarn_ext_factor: f32,
    pub yarn_attn_factor: f32,
    pub yarn_beta_fast: f32,
    pub yarn_beta_slow: f32,
    pub yarn_orig_ctx: u32,
    pub defrag_thold: f32,
    pub cb_eval: *mut c_void,
    pub cb_eval_user_data: *mut c_void,
    pub type_k: i32,
    pub type_v: i32,
    pub abort_callback: *mut c_void,
    pub abort_callback_data: *mut c_void,
    pub embeddings: bool,
    pub offload_kqv: bool,
    pub no_perf: bool,
    pub op_offload: bool,
    pub swa_full: bool,
    pub kv_unified: bool,
    pub samplers: *mut c_void,
    pub n_samplers: usize,
    pub ctx_other: *mut c_void,
}

pub struct LlamaLib {
    handle: *mut c_void,
    pub llama_backend_init: unsafe extern "C" fn(),
    pub llama_backend_free: unsafe extern "C" fn(),
    pub llama_model_default_params: unsafe extern "C" fn() -> LlamaModelParams,
    pub llama_context_default_params: unsafe extern "C" fn() -> LlamaContextParams,
    pub llama_load_model_from_file:
        unsafe extern "C" fn(path: *const c_char, params: LlamaModelParams) -> *mut LlamaModel,
    pub llama_free_model: unsafe extern "C" fn(model: *mut LlamaModel),
    pub llama_new_context_with_model: unsafe extern "C" fn(
        model: *mut LlamaModel,
        params: LlamaContextParams,
    ) -> *mut LlamaContext,
    pub llama_free: unsafe extern "C" fn(ctx: *mut LlamaContext),
}

impl LlamaLib {
    #[allow(clippy::missing_transmute_annotations)]
    pub fn load() -> Result<Self, String> {
        let paths = [
            "libllama.so",
            "/usr/local/lib/ollama/libllama.so",
            "/usr/lib/libllama.so",
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
            return Err("Failed to load libllama.so".to_string());
        }

        unsafe {
            let get_sym = |name: &str| -> Result<*mut c_void, String> {
                let cname = CString::new(name).unwrap();
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
        if !self.handle.is_null() {
            unsafe { dlclose(self.handle) };
        }
    }
}

pub struct LlamaBackend {
    lib: LlamaLib,
}

impl LlamaBackend {
    pub fn init() -> Result<Self, String> {
        let lib = LlamaLib::load()?;
        unsafe {
            (lib.llama_backend_init)();
        }
        Ok(Self { lib })
    }

    #[must_use]
    pub fn get_default_model_params(&self) -> LlamaModelParams {
        unsafe { (self.lib.llama_model_default_params)() }
    }

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

    #[test]
    fn test_load_llama_lib() {
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
                println!(
                    "Llama.cpp load failed (expected if library not installed): {}",
                    e
                );
            }
        }
    }
}
