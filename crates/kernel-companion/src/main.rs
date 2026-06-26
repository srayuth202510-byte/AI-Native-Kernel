use agent_scheduler::AgentControlBlock;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("AI-Native Kernel Companion Daemon starting...");
    
    // Initialize zero-trust security
    let security_manager = Arc::new(audit_manager::AuditManager::new());
    
    // Initialize LSM policy engine
    let lsm_engine = Arc::new(kernel_companion::LsmPolicyEngine::new().await?);
    
    // Initialize agent scheduler
    let scheduler = Arc::new(AgentScheduler::new());
    
    // Initialize context memory manager
    let context_manager = Arc::new(ContextMemoryManager::new());
    
    // Initialize intent bus for communication
    let intent_bus = Arc::new(IntentBus::new());
    
    // Initialize compute scheduler
    let compute_scheduler = Arc::new(ComputeScheduler::new());
    
    println!("Starting eBPF attachment to LSM hooks...");
    
    // Attach to Linux Security Module hooks
    let ebpf_handle = match attach_lsm_hooks(lsm_engine.clone()).await {
        Ok(handle) => handle,
        Err(e) => {
            println!("Failed to attach eBPF hooks: {}", e);
            return Err(e.into());
        }
    };
    
    println!("Successfully attached eBPF hooks: LSM policy engine ready");
    
    println!("AI-Native Kernel Companion Daemon initialized and running...");
    
    // Wait for shutdown signal
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            println!("\nReceived shutdown signal, cleaning up...");
        }
        Err(err) => {
            println!("Error waiting for Ctrl+C: {:?}", err);
        }
    }
    
    // Cleanup sequence
    println!("Detaching eBPF hooks...");
    let _ = ebpf_handle.detach().await;
    
    println!("Shutdown complete.");
    Ok(())
}