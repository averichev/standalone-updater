//! Signed standalone update protocol v1 and an opt-in Linux installation runtime.
//!
//! [`UpdateClient`] checks a pinned Ed25519 key and the full signed release context.
//! [`VerifiedUpdate`] can only be created by successful verification. Manifest
//! entries are untrusted hints, never installation candidates.
//!
//! Enable `linux-runtime` for the `runtime` module on Linux. See the repository's
//! `examples/axum-service.rs` for graceful shutdown, readiness and process dispatch.
//! No network request occurs until the application explicitly calls `check`.
//!
//! Version 0.1.0 is experimental; publication is gated on reintegration testing.
//!
//! ```no_run
//! use standalone_updater::{UpdateClient, UpdateSource};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let source: UpdateSource = serde_json::from_slice(&std::fs::read("source.json")?)?;
//! let client = UpdateClient::new(source, "0.5.0", "linux-x86_64")?;
//! if let Some(candidate) = client.check().await?.update {
//!     println!("Verified release {}", candidate.metadata().version);
//! }
//! # Ok(()) }
//! ```
#![warn(missing_docs)]
mod artifact;
mod client;
mod models;

#[cfg(all(feature = "linux-runtime", target_os = "linux"))]
pub mod runtime;

pub use client::{DownloadEvent, UpdateClient, canonical_version};
pub use models::*;

/// A result with redacted, typed update failures.
pub type Result<T> = std::result::Result<T, UpdateError>;

#[derive(Debug, thiserror::Error)]
/// Failures contain no paths, request URLs, process arguments or server bodies.
pub enum UpdateError {
    #[error("Источник обновлений недоступен или превышено время ожидания")]
    /// Network failure, redirect policy failure or timeout; remote details are redacted.
    Unavailable,
    #[error("Источник обновлений вернул HTTP {0}")]
    /// Unexpected HTTP status; no remote error body is retained.
    Http(u16),
    #[error("Некорректный или слишком большой документ обновления")]
    /// Malformed or oversized JSON/update document.
    Document,
    #[error("Проверка доверия не пройдена: {0}")]
    /// Signature, key, product, platform, version or URL trust policy failed.
    Trust(&'static str),
    #[error("Проверка файла не пройдена: {0}")]
    /// Artifact, executable or backup integrity failed.
    Integrity(&'static str),
    #[error("Установка недоступна: {0}")]
    /// Local mode, platform, compatibility or filesystem policy disallows installation.
    Unsupported(&'static str),
    #[error("Уже выполняется операция обновления")]
    /// Another lifecycle/update operation owns the required file lock.
    Busy,
    #[error("Недостаточно свободного места для обновления")]
    /// Insufficient available space or allocation failed with storage-full.
    NoSpace,
    #[error("Ошибка файловой системы ({0:?})")]
    /// Local I/O failure with the path and OS error message deliberately removed.
    Io(std::io::ErrorKind),
    #[error("Выбранное обновление изменилось; повторите проверку и подтверждение")]
    /// The selected release/operation or current executable changed; check again.
    Stale,
    #[error("Не удалось запустить updater-worker")]
    /// Worker/supervisor handshake or process-control failure.
    Worker,
    #[error("Новая версия не прошла проверку готовности")]
    /// The specific restarted child did not pass application readiness.
    Health,
}

impl From<std::io::Error> for UpdateError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::StorageFull {
            Self::NoSpace
        } else {
            // Do not persist paths, request URLs, environment or arbitrary server messages.
            Self::Io(error.kind())
        }
    }
}

#[cfg(all(feature = "linux-runtime", target_os = "linux"))]
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

#[cfg(all(feature = "linux-runtime", target_os = "linux"))]
pub(crate) fn operation_id() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| UpdateError::Worker)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(all(feature = "linux-runtime", target_os = "linux"))]
pub(crate) fn valid_operation_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
