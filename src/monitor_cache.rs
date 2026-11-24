//! Optional redacted check cache. It is never an installation/recovery journal.
use crate::*;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub product_id: String,
    pub current_version: String,
    pub target: String,
    pub key_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    schema_version: u32,
    identity: Identity,
    status: OperationStatus,
}
#[derive(Clone)]
pub(crate) struct Cache {
    directory: PathBuf,
    identity: Identity,
}
impl Cache {
    pub fn open(directory: &Path, identity: Identity) -> Result<Self> {
        let directory = std::path::absolute(directory)?;
        // Avoid exposing cached UI data through a symlink or writable ancestor.
        for parent in directory.ancestors() {
            match fs::symlink_metadata(parent) {
                Ok(metadata) => {
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(UpdateError::Unsupported("unsafe check cache directory"));
                    }
                    #[cfg(unix)]
                    if metadata.mode() & 0o022 != 0
                        && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
                    {
                        return Err(UpdateError::Unsupported("writable check cache ancestor"));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&directory)?;
        #[cfg(unix)]
        if fs::metadata(&directory)?.mode() & 0o077 != 0 {
            return Err(UpdateError::Unsupported(
                "check cache directory must be private",
            ));
        }
        Ok(Self {
            directory,
            identity,
        })
    }
    pub fn load(&self) -> Result<OperationStatus> {
        let path = self.directory.join("checks.json");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(OperationStatus::default());
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 1024 * 1024
        {
            return Err(UpdateError::Document);
        }
        let mut bytes = Vec::new();
        File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(UpdateError::Document);
        }
        let cached: Cached = serde_json::from_slice(&bytes).map_err(|_| UpdateError::Document)?;
        if cached.schema_version != 1 || cached.identity != self.identity {
            return Ok(OperationStatus::default());
        }
        let mut status = cached.status;
        // A check cache must never import an installation stage or recovery job.
        if !matches!(
            status.state,
            Stage::Idle | Stage::Checking | Stage::Available | Stage::Failed
        ) || status.recovery_required
            || status.worker.is_some()
        {
            return Err(UpdateError::Document);
        }
        if status.state == Stage::Checking {
            status.state = Stage::Failed;
            status.message = "Проверка прервана; выполните её повторно".into();
        }
        Ok(status)
    }
    pub fn save(&self, status: &OperationStatus) -> Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let temporary = self.directory.join(format!(
            "checks-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let bytes = serde_json::to_vec(&Cached {
            schema_version: 1,
            identity: self.identity.clone(),
            status: status.clone(),
        })
        .map_err(|_| UpdateError::Document)?;
        if bytes.len() > 1024 * 1024 {
            return Err(UpdateError::Document);
        }
        let result = (|| {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.directory.join("checks.json"))?;
            #[cfg(unix)]
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
