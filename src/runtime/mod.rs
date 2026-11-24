//! Linux process lifecycle and recoverable installation.
//!
//! Call [`launch`] before opening listeners or business data. Use the returned
//! [`UpdateManager`] from the application. Wait on [`UpdateManager::shutdown_requested`],
//! drain requests and close application resources, then call
//! [`UpdateManager::finish_shutdown`]. Never acknowledge shutdown before resources close.
//!
//! The same executable dispatches its internal supervisor/server/worker roles.
//! No additional distributed binary or system service is needed. Logs must go to
//! stderr: supervised stdout is a bounded private control channel.
mod files;
mod manager;
mod supervisor;
#[cfg(test)]
mod tests;
mod worker;

use crate::*;
pub use manager::{InstallRequest, UpdateManager, UpdateSummary};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Reserved CLI argument handled before application startup.
pub const BUILD_INFO_ARGUMENT: &str = "--standalone-updater-build-info";
/// Reserved internal role; applications must pass remaining original arguments through.
pub const SERVER_ARGUMENT: &str = "--standalone-updater-server";
/// Reserved internal role for a temporary copy of the installed executable.
pub const WORKER_ARGUMENT: &str = "--standalone-updater-worker";
/// Explicit offline recovery command; the application must be stopped first.
pub const RECOVER_ARGUMENT: &str = "--standalone-updater-recover";
const HEALTH_NONCE: &str = "STANDALONE_UPDATER_HEALTH_NONCE";

/// Application build identity. Emit this for [`BUILD_INFO_ARGUMENT`] before
/// loading business configuration or opening data. This is a local runtime
/// contract, independent of the wire protocol's schema version.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildInfo {
    /// Canonical installed SemVer, including build metadata.
    pub version: String,
    /// Full Rust compilation target; installation requires an exact match.
    pub rust_target: String,
    /// Permanent publisher UUID, matching the configured protocol source.
    pub product_id: String,
    /// Runtime handshake version. Currently 1.
    pub self_update_protocol: u32,
    /// Non-secret fingerprint of migrations and data formats. Equality is
    /// necessary, but the publisher must also preserve semantic compatibility.
    pub data_compatibility: String,
}
impl BuildInfo {
    /// Answer an isolated build-info invocation. Returns whether it was handled.
    pub fn handle_cli(&self) -> Result<bool> {
        if std::env::args().skip(1).collect::<Vec<_>>() == [BUILD_INFO_ARGUMENT] {
            serde_json::to_writer(std::io::stdout().lock(), self)
                .map_err(|_| UpdateError::Document)?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Protocol target derived from the application's compiled Rust target.
    pub fn protocol_target(&self) -> Result<String> {
        let arch = self.rust_target.split('-').next().unwrap_or("");
        let os = if self.rust_target.contains("-linux-") {
            "linux"
        } else if self.rust_target.contains("-apple-darwin") {
            "darwin"
        } else if self.rust_target.contains("-windows-") {
            "windows"
        } else {
            return Err(UpdateError::Unsupported("unsupported Rust target"));
        };
        if !matches!(arch, "x86_64" | "aarch64") {
            return Err(UpdateError::Unsupported("unsupported architecture"));
        }
        Ok(format!("{os}-{arch}"))
    }
}

/// Who owns process restarts and executable installation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallationMode {
    /// Keep the original launcher PID and update a private working copy.
    Supervisor,
    /// Replace the application-owned executable using a short-lived worker.
    Standalone,
    /// Check only; a package/process manager or operator handles installation.
    External,
}

/// Binary rollback never rolls back user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataPolicy {
    /// Require the same nonempty data compatibility fingerprint in preflight.
    RequireExact,
    /// Permit checks but disable installation until an operator handles data.
    ManualOnly,
}

/// Bounded loopback HTTP readiness probe, with an instance nonce to reject a
/// stale server. The application chooses the route and checks its own resources.
#[derive(Clone, Debug)]
pub struct Readiness {
    /// Fixed local listening address. Wildcard addresses are mapped to loopback.
    pub address: SocketAddr,
    /// Absolute route path without query or fragment (for example `/health`).
    pub path: String,
    /// Maximum startup/readiness duration.
    pub timeout: Duration,
    /// Minimum survival after the successful health response.
    pub stability: Duration,
}
impl Readiness {
    /// Default 30-second probe with a 300 ms survival check.
    pub fn http(address: SocketAddr, path: impl Into<String>) -> Self {
        Self {
            address,
            path: path.into(),
            timeout: Duration::from_secs(30),
            stability: Duration::from_millis(300),
        }
    }
}

/// Ready response returned by the application's health route only after its
/// own resources are ready. The nonce is ephemeral and is never persisted.
#[derive(Clone, Serialize)]
pub struct ReadyResponse {
    /// Always `ok` for this success response.
    pub status: &'static str,
    /// Installed application version.
    pub version: String,
    /// Nonce inherited by the specific restarted child.
    pub update_instance: Option<String>,
}

/// Trusted application configuration, constructed in each executable role.
/// Arguments and environment stay in memory and are never written to a job.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Pinned source configuration, not settings supplied by an HTTP caller.
    pub source: UpdateSource,
    /// Identity of this application build, not the updater crate version.
    pub build: BuildInfo,
    /// Lifecycle ownership.
    pub mode: InstallationMode,
    /// Installed executable, including its actual filename.
    pub executable: PathBuf,
    /// Private state/runtime/staging directory. In standalone mode it must
    /// share a filesystem with the executable. Must be owned by the process, 0700.
    pub updates_directory: PathBuf,
    /// Original application arguments, excluding reserved internal role flags.
    pub arguments: Vec<String>,
    /// Original working directory to retain on restart.
    pub working_directory: PathBuf,
    /// Explicit data safety policy.
    pub data_policy: DataPolicy,
    /// Application-defined local health route.
    pub readiness: Readiness,
}
impl RuntimeConfig {
    pub(crate) fn client(&self) -> Result<UpdateClient> {
        if self.build.product_id != self.source.product_id || self.build.self_update_protocol != 1 {
            return Err(UpdateError::Trust("application build identity mismatch"));
        }
        UpdateClient::new(
            self.source.clone(),
            &self.build.version,
            &self.build.protocol_target()?,
        )
    }
    pub(crate) fn validate_installation(&self) -> Result<()> {
        if self.mode == InstallationMode::External || self.data_policy == DataPolicy::ManualOnly {
            return Err(UpdateError::Unsupported(
                "installation is externally managed",
            ));
        }
        let target = self.build.protocol_target()?;
        if !target.starts_with("linux-")
            || self.build.data_compatibility.is_empty()
            || self.build.data_compatibility.len() > 256
        {
            return Err(UpdateError::Unsupported(
                "Linux installation requires a data compatibility fingerprint",
            ));
        }
        let address = worker::loopback_address(self.readiness.address);
        let path = &self.readiness.path;
        if !address.ip().is_loopback()
            || address.port() == 0
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['?', '#', '\\', '\r', '\n'])
            || path.len() > 2048
            || self.readiness.timeout.is_zero()
            || self.readiness.timeout > Duration::from_secs(300)
            || self.readiness.stability > self.readiness.timeout
        {
            return Err(UpdateError::Unsupported("invalid local readiness policy"));
        }
        Ok(())
    }
    pub(crate) fn layout(&self) -> Result<files::ExecutableLayout> {
        self.validate_installation()?;
        files::ExecutableLayout::inspect(&self.executable, &self.updates_directory.join("staging"))
    }
}

/// Result of early process dispatch. Return an Exit code from main, or serve
/// the application with the supplied manager.
pub enum Launch {
    /// The process should start its application normally.
    Serve(UpdateManager),
    /// A supervisor, worker or recovery role has finished.
    Exit(i32),
}

/// Dispatch internal roles and start the optional supervisor. Call before
/// opening business data/listeners. It does not contact the release source.
pub async fn launch(config: RuntimeConfig) -> Result<Launch> {
    config.client()?;
    let role = std::env::args().nth(1);
    match role.as_deref() {
        Some(WORKER_ARGUMENT) => {
            worker::run(config).await?;
            Ok(Launch::Exit(0))
        }
        Some(RECOVER_ARGUMENT) => {
            recover(&config)?;
            Ok(Launch::Exit(0))
        }
        Some(SERVER_ARGUMENT) if config.mode == InstallationMode::Supervisor => {
            let parent = files::process_identity(unsafe { libc::getppid() } as u32)
                .ok_or(UpdateError::Worker)?;
            Ok(Launch::Serve(UpdateManager::new(config, Some(parent))?))
        }
        _ if config.mode == InstallationMode::Supervisor => {
            Ok(Launch::Exit(supervisor::run(config).await?))
        }
        Some(SERVER_ARGUMENT) => Err(UpdateError::Worker),
        _ => Ok(Launch::Serve(UpdateManager::new(config, None)?)),
    }
}

/// Offline binary-only recovery. Requires no running server/supervisor/worker.
/// Never modifies business data; restore the process with its original settings.
pub fn recover(config: &RuntimeConfig) -> Result<()> {
    worker::recover(config)
}

/// Resolve the working copy for application CLI commands such as `--version`.
/// A manually replaced launcher intentionally supersedes the prior working copy.
pub fn active_executable(config: &RuntimeConfig) -> Result<Option<PathBuf>> {
    supervisor::active_executable(config)
}
