use kernel_companion::KernelCompanion;

/// จุดเข้าหลัก (Entry Point) สำหรับการทำงานของ AI-Native Kernel Companion Daemon
/// โดยรันบน Tokio Async Runtime สำหรับรับคำสั่งและเฝ้าดูความปลอดภัยระบบ
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("AI-Native Kernel Companion Daemon starting...");

    // สร้างอินสแตนซ์ของ companion daemon
    let companion = KernelCompanion::new();
    
    // สตาร์ทและรันบริการหลัก
    companion.run().await
}
