//! Private, bounded JSON files for channel settings and the check-only cache.
use crate::{Result, UpdateError};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const FILE_LIMIT: usize = 1024 * 1024;

#[derive(Clone)]
pub(crate) struct PrivateDirectory(PathBuf);

impl PrivateDirectory {
    pub fn open(path: &Path) -> Result<Self> {
        if path.as_os_str().is_empty() || path.components().any(|c| c == Component::ParentDir) {
            return Err(UpdateError::Unsupported("invalid local state directory"));
        }
        let path = std::path::absolute(path)?;
        let builder = &mut fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        #[cfg(unix)]
        let uid = unsafe { libc::geteuid() };
        for parent in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let metadata = match fs::symlink_metadata(parent) {
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    match builder.create(parent) {
                        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(e.into()),
                        Ok(()) =>
                        {
                            #[cfg(unix)]
                            if let Some(containing_dir) = parent.parent() {
                                File::open(containing_dir)?.sync_all()?;
                            }
                        }
                    }
                    fs::symlink_metadata(parent)?
                }
                result => result?,
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(UpdateError::Unsupported("unsafe local state directory"));
            }
            #[cfg(unix)]
            {
                let owner = metadata.uid();
                let sticky_root = owner == 0 && metadata.mode() & 0o1000 != 0;
                if !(owner == 0 || owner == uid) || metadata.mode() & 0o022 != 0 && !sticky_root {
                    return Err(UpdateError::Unsupported("unsafe local state ancestor"));
                }
                if parent == path && (owner != uid || metadata.mode() & 0o077 != 0) {
                    return Err(UpdateError::Unsupported(
                        "local state directory must be private",
                    ));
                }
            }
        }
        Ok(Self(path))
    }

    // Only fixed, crate-owned names are passed to these methods.
    fn options() -> OpenOptions {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options
    }

    fn open_file(&self, name: &str, options: &OpenOptions) -> Result<File> {
        let path = self.0.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() => return Err(UpdateError::Document),
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(UpdateError::Document);
        }
        #[cfg(unix)]
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err(UpdateError::Unsupported("unsafe local state file"));
        }
        Ok(file)
    }

    pub fn lock(&self, name: &str) -> Result<File> {
        let file = self.open_file(
            name,
            Self::options().write(true).create(true).truncate(false),
        )?;
        file.lock()?;
        Ok(file)
    }

    pub fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let file = match self.open_file(name, &Self::options()) {
            Err(UpdateError::Io(ErrorKind::NotFound)) => return Ok(None),
            result => result?,
        };
        if file.metadata()?.len() > FILE_LIMIT as u64 {
            return Err(UpdateError::Document);
        }
        let mut bytes = Vec::new();
        file.take(FILE_LIMIT as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > FILE_LIMIT {
            return Err(UpdateError::Document);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| UpdateError::Document)
    }

    pub fn write(&self, name: &str, value: &impl Serialize) -> Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let bytes = serde_json::to_vec(value).map_err(|_| UpdateError::Document)?;
        if bytes.len() > FILE_LIMIT {
            return Err(UpdateError::Document);
        }
        let (temporary, mut file) = loop {
            let path = self.0.join(format!(
                ".{name}-{}-{}.tmp",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match Self::options().write(true).create_new(true).open(&path) {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                result => break (path, result?),
            }
        };
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.0.join(name))?;
            #[cfg(unix)]
            File::open(&self.0)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}
