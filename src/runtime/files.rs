//! Local filesystem policy. Names passed to Directory are locally generated, never URLs.
use crate::artifact::verify_elf;
use crate::*;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct Directory {
    path: PathBuf,
}

/// Explicit unlock is essential in a multithreaded process that also forks:
/// close-on-exec descriptors can temporarily remain open in an unrelated child.
/// Closing only the parent's descriptor would keep flock held until that exec.
pub struct FileLock {
    file: File,
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options
}

fn regular(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(UpdateError::Unsupported("ожидается обычный файл"));
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(UpdateError::Unsupported(
            "небезопасный владелец или права файла",
        ));
    }
    Ok(())
}

pub fn open_regular(path: &Path) -> Result<File> {
    let file = options().read(true).open(path)?;
    regular(&file)?;
    Ok(file)
}

impl Directory {
    pub fn private(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        secure_parents(&path)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => sync_directory(path.parent().ok_or(UpdateError::Worker)?)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(UpdateError::Unsupported(
                "каталог обновлений не должен быть symlink",
            ));
        }
        #[cfg(unix)]
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(UpdateError::Unsupported(
                "каталог обновлений должен принадлежать процессу и иметь права 0700",
            ));
        }
        Ok(Self {
            path: fs::canonicalize(&path)?,
        })
    }
    pub fn as_path(&self) -> &Path {
        &self.path
    }
    pub fn bind_product(&self, product: &str) -> Result<()> {
        let _initialization = self.lock("state.lock")?;
        match self.read::<String>("product.json") {
            Ok(previous) if previous != product => {
                Err(UpdateError::Trust("state belongs to another product"))
            }
            Err(UpdateError::Io(std::io::ErrorKind::NotFound)) => {
                self.write("product.json", &product)
            }
            Err(error) => Err(error),
            _ => Ok(()),
        }
    }
    pub fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
            return Err(UpdateError::Unsupported("invalid local filename"));
        }
        Ok(self.path.join(name))
    }
    pub fn create(&self, name: &str) -> Result<File> {
        Ok(options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(self.path(name)?)?)
    }
    pub fn lock(&self, name: &str) -> Result<FileLock> {
        let file = options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.path(name)?)?;
        regular(&file)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => UpdateError::Busy,
            std::fs::TryLockError::Error(error) => error.into(),
        })?;
        Ok(FileLock { file })
    }
    pub fn read<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let file = open_regular(&self.path(name)?)?;
        if file.metadata()?.len() > 128 * 1024 {
            return Err(UpdateError::Document);
        }
        serde_json::from_reader(file).map_err(|_| UpdateError::Document)
    }
    pub fn write<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let temporary = format!("write-{}.tmp", operation_id()?);
        let result = (|| {
            let mut file = self.create(&temporary)?;
            serde_json::to_writer(&mut file, value).map_err(|_| UpdateError::Document)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(self.path(&temporary)?, self.path(name)?)?;
            self.sync()
        })();
        if result.is_err() {
            let _ = self.remove(&temporary);
        }
        result
    }
    pub fn remove(&self, name: &str) -> Result<()> {
        match fs::remove_file(self.path(name)?) {
            Ok(()) => self.sync(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn sync(&self) -> Result<()> {
        sync_directory(&self.path)
    }
    pub fn status(&self) -> Result<OperationStatus> {
        Ok(self.stored_check()?.status)
    }
    pub fn stored_check(&self) -> Result<StoredCheck> {
        match self.read("status.json") {
            Err(UpdateError::Io(std::io::ErrorKind::NotFound)) => Ok(StoredCheck::default()),
            result => result,
        }
    }
    pub fn save_check(&self, status: &mut OperationStatus, source_id: &str) -> Result<()> {
        status.updated_at = now();
        self.write("status.json", &StoredCheck::new(status, source_id))
    }
    pub fn save_status(&self, status: &mut OperationStatus) -> Result<()> {
        status.updated_at = now();
        self.write("status.json", status)
    }
}

pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct ExecutableLayout {
    pub executable: PathBuf,
    pub staging: Directory,
}
impl ExecutableLayout {
    pub fn inspect(executable: &Path, staging_path: &Path) -> Result<Self> {
        let executable = absolute(executable)?;
        secure_parents(&executable)?;
        let executable = executable.as_path();
        if !cfg!(target_os = "linux") {
            return Err(UpdateError::Unsupported(
                "автономная установка поддерживается только на Linux",
            ));
        }
        let metadata = fs::symlink_metadata(executable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(UpdateError::Unsupported(
                "исполняемый файл не должен быть symlink",
            ));
        }
        let parent = executable
            .parent()
            .ok_or(UpdateError::Unsupported("нет каталога приложения"))?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err(UpdateError::Unsupported(
                "каталог приложения не должен быть symlink",
            ));
        }
        #[cfg(unix)]
        if metadata.uid() != unsafe { libc::geteuid() }
            || parent_metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o6022 != 0
            || metadata.mode() & 0o100 == 0
            || parent_metadata.mode() & 0o022 != 0
            || parent_metadata.mode() & 0o300 != 0o300
        {
            return Err(UpdateError::Unsupported(
                "процесс должен владеть бинарником и доступным для записи каталогом без group/other write и setuid/setgid",
            ));
        }
        let executable = fs::canonicalize(executable)?;
        let staging = Directory::private(staging_path)?;
        if fs::metadata(staging.as_path())?.dev() != parent_metadata.dev() {
            return Err(UpdateError::Unsupported(
                "staging and executable must share a filesystem",
            ));
        }
        // Exercise writes before the server is stopped (also catches read-only mounts).
        let probe = format!("probe-{}", operation_id()?);
        staging.create(&probe)?.sync_all()?;
        staging.remove(&probe)?;
        Ok(Self {
            executable,
            staging,
        })
    }
    pub fn available_space(&self) -> Result<u64> {
        available_space(self.staging.as_path())
    }
}

pub fn require_space(available: u64, required: u64) -> Result<()> {
    if available < required {
        Err(UpdateError::NoSpace)
    } else {
        Ok(())
    }
}

pub fn hash_file(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(crate::hex(&hash.finalize()))
}

pub fn verify_file(path: &Path, metadata: &SignedMetadata) -> Result<()> {
    let mut file = open_regular(path)?;
    if file.metadata()?.len() != metadata.size_bytes || hash_file(&mut file)? != metadata.sha256 {
        return Err(UpdateError::Integrity(
            "размер/SHA-256 подготовленного файла изменился",
        ));
    }
    verify_elf(
        &mut file,
        &format!("{}-{}", metadata.os, metadata.arch),
        metadata.size_bytes,
    )
}

pub fn executable_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o755))?;
    file.sync_all()?;
    Ok(())
}

pub fn process_identity(pid: u32) -> Option<ProcessIdentity> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields: Vec<_> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
        if matches!(*fields.first()?, "Z" | "X") {
            return None;
        }
        Some(ProcessIdentity {
            pid,
            start_ticks: fields.get(19)?.parse().ok()?,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}
pub fn process_alive(identity: &ProcessIdentity) -> bool {
    process_identity(identity.pid).as_ref() == Some(identity)
}

/// Reject lexical traversal and symlinks in every ancestor. Root-owned sticky
/// temporary roots are allowed; the final state/staging directory is always 0700.
fn absolute(path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err(UpdateError::Unsupported("parent traversal in local path"));
    }
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
fn secure_parents(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(UpdateError::Unsupported("missing parent"))?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700).create(&current)?;
                sync_directory(current.parent().ok_or(UpdateError::Worker)?)?;
                fs::symlink_metadata(&current)?
            }
            Err(e) => return Err(e.into()),
        };
        let uid = unsafe { libc::geteuid() };
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !(metadata.uid() == 0 || metadata.uid() == uid)
            || metadata.mode() & 0o022 != 0 && !sticky_root
        {
            return Err(UpdateError::Unsupported(
                "unsafe ancestor of local update path",
            ));
        }
    }
    Ok(())
}

pub fn available_space(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| UpdateError::Worker)?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is NUL terminated; statvfs initializes value on success.
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    Ok(value.f_bavail.saturating_mul(value.f_frsize))
}

pub fn allocate(file: &File, bytes: u64) -> Result<()> {
    let bytes = i64::try_from(bytes).map_err(|_| UpdateError::NoSpace)?;
    // SAFETY: borrowed valid file descriptor; no ownership transfer.
    let code = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, bytes) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code).into());
    }
    Ok(())
}

/// Reading the original launcher may be allowed even when it is root-owned and
/// read-only. Runtime copies still require process ownership.
pub fn open_launcher(path: &Path) -> Result<File> {
    let path = absolute(path)?;
    secure_parents(&path)?;
    let file = options().read(true).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || !(metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() })
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o100 == 0
    {
        return Err(UpdateError::Unsupported(
            "unsafe launcher ownership or permissions",
        ));
    }
    Ok(file)
}
