use anyhow::{Context, Result};
use intent_bus::{Intent, IntentPriority, IntentType};
use std::env;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: ank-cli <command> [payload]");
        println!("Example: ank-cli spawn-agent \"my agent payload\"");
        return Ok(());
    }

    let cmd = &args[1];
    let payload = if args.len() > 2 { &args[2] } else { "{}" };

    let mut intent = Intent::new(
        uuid::Uuid::new_v4().to_string(),
        IntentType::Command,
        cmd,
        IntentPriority::High,
        "ank-cli",
    );
    if args.len() > 2 {
        intent
            .metadata
            .insert("payload".to_string(), payload.to_string());
    }

    let socket_path = "/tmp/ank-companion.sock";
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("Failed to connect to UDS at {}", socket_path))?;

    let json = serde_json::to_string(&intent)?;
    stream.write_all(json.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    println!("Intent sent successfully: {}", cmd);
    Ok(())
}
