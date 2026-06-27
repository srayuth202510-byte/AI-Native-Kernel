#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let memory = context_memory::ContextMemoryManager::with_capacity(64, 256);
    if let Ok(key) = std::str::from_utf8(data) {
        let truncated: String = key.chars().take(128).collect();
        memory.put(truncated.clone(), data.to_vec());
        let _ = memory.get(&truncated);
        let _ = memory.tier_of(&truncated);
    }
});
