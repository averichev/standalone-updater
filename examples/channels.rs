//! Manage the same private channel settings as the application.
use standalone_updater::{ChannelStore, UpdateSource};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let usage = "usage: channels SOURCE.json DIRECTORY list | add NAME MANIFEST_URL | select NAME | remove NAME";
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [source_file, directory, command, rest @ ..] = args.as_slice() else {
        return Err(usage.into());
    };
    let default: UpdateSource = serde_json::from_slice(&std::fs::read(source_file)?)?;
    let channels = ChannelStore::open(Path::new(directory), default)?;
    match (command.as_str(), rest) {
        ("list", []) => {
            for entry in channels.list()? {
                let marker = if entry.selected { "*" } else { " " };
                println!("{marker} {}\t{}", entry.name, entry.manifest_url);
            }
        }
        ("add", [name, manifest]) => channels.add(name, manifest)?,
        ("select", [name]) => channels.select(name)?,
        ("remove", [name]) => channels.remove(name)?,
        _ => return Err(usage.into()),
    }
    Ok(())
}
