use kernel_companion::KernelCompanion;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("AI-Native Kernel Companion Daemon starting...");

    let companion = KernelCompanion::new();
    companion.run().await
}
