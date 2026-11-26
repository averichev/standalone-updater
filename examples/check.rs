//! Check-only example. The source file contains public trust anchors, no private key.
use standalone_updater::{ChannelStore, UpdateClient, UpdateSource};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(4..=5).contains(&args.len()) {
        return Err(
            "usage: check SOURCE.json CURRENT_VERSION PROTOCOL_TARGET [CHANNEL_DIRECTORY]".into(),
        );
    }
    let source: UpdateSource = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let source = match args.get(4) {
        Some(directory) => ChannelStore::open(directory.as_ref(), source)?.active_source()?,
        None => source,
    };
    let client = UpdateClient::new(source, &args[2], &args[3])?;
    let result = client.check().await?;
    if let Some(update) = result.update {
        println!(
            "Verified update: {} ({} bytes)",
            update.metadata().version,
            update.metadata().size_bytes
        );
    } else {
        println!("No newer signed update");
    }
    Ok(())
}
