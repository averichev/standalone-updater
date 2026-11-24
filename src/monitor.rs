//! Check orchestration for applications without an installation runtime.
use crate::*;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
/// Cloneable background checks with redacted snapshots, with an optional private redacted cache.
pub struct UpdateMonitor {
    client: UpdateClient,
    identity: crate::monitor_cache::Identity,
    cache: Option<crate::monitor_cache::Cache>,
    snapshot: Arc<Mutex<(OperationStatus, Option<ManualRelease>)>>,
}
/// Check-only diagnostics. Installation always belongs to the caller.
pub struct CheckSummary {
    /// Public trust-anchor thumbprint.
    pub trusted_key_id: String,
    /// Always false: the monitor does not install.
    pub installation_supported: bool,
    /// Explains that installation requires an application runtime.
    pub installation_reason: Option<String>,
    /// Latest redacted snapshot.
    pub status: OperationStatus,
}
impl UpdateMonitor {
    /// Construct a check-only monitor. No network requests occur until `check`.
    pub fn new(source: UpdateSource, current_version: &str, target: &str) -> Result<Self> {
        let product_id = source.product_id.clone();
        let client = UpdateClient::new(source, current_version, target)?;
        let identity = crate::monitor_cache::Identity {
            product_id,
            current_version: current_version.into(),
            target: target.into(),
            key_id: client.key_id().into(),
        };
        Ok(Self {
            client,
            identity,
            cache: None,
            snapshot: Arc::new(Mutex::new((OperationStatus::default(), None))),
        })
    }
    /// Retain redacted check results in a dedicated process-owned directory.
    /// This cache is bound to product/key/version/target, contains no download
    /// URLs and never accepts installation/recovery state. No network is used.
    /// Existing symlinks or unsafe permissions are rejected, not repaired.
    pub fn with_cache(mut self, directory: &std::path::Path) -> Result<Self> {
        let cache = crate::monitor_cache::Cache::open(directory, self.identity.clone())?;
        let status = cache.load()?;
        *self.snapshot.lock().map_err(|_| UpdateError::Worker)? = (status, None);
        self.cache = Some(cache);
        Ok(self)
    }
    /// Read the latest in-memory snapshot.
    pub fn status(&self) -> Result<OperationStatus> {
        Ok(self
            .snapshot
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .0
            .clone())
    }
    /// Read a transient manual download hint. URLs never enter snapshots.
    pub fn manual_release(&self) -> Result<Option<ManualRelease>> {
        Ok(self
            .snapshot
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .1
            .clone())
    }
    /// Read the current check-only diagnostics.
    pub fn summary(&self) -> Result<CheckSummary> {
        Ok(CheckSummary {
            trusted_key_id: self.client.key_id().into(),
            installation_supported: false,
            installation_reason: Some(
                "Installation runtime is unavailable; manual download is supported".into(),
            ),
            status: self.status()?,
        })
    }
    /// Start a background check, rejecting overlapping calls with `Busy`.
    pub fn check(&self) -> Result<OperationStatus> {
        let mut current = self.snapshot.lock().map_err(|_| UpdateError::Worker)?;
        if current.0.state.busy() {
            return Err(UpdateError::Busy);
        }
        let mut random = [0; 16];
        // ID only identifies an in-process check; it never authorizes installation.
        static NEXT_CHECK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        random[..8].copy_from_slice(
            &NEXT_CHECK
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_le_bytes(),
        );
        let mut status = OperationStatus {
            operation_id: Some(random.iter().map(|b| format!("{b:02x}")).collect()),
            state: Stage::Checking,
            message: "Проверка подписанного выпуска".into(),
            last_checked: current.0.last_checked,
            ..Default::default()
        };
        if let Some(cache) = &self.cache {
            cache.save(&status)?;
        }
        *current = (status.clone(), None);
        let initial = status.clone();
        let checks = self.clone();
        tokio::spawn(async move {
            let result = checks.client.check().await;
            status.last_checked = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            );
            let mut manual = None;
            match result {
                Ok(result) => {
                    manual = result.manual;
                    status.manual_release = manual.as_ref().map(|r| ManualReleaseInfo {
                        version: r.version.clone(),
                        notes: r.notes.clone(),
                    });
                    if let Some(update) = result.update {
                        let m = update.metadata();
                        status.state = Stage::Available;
                        status.check_outcome = CheckOutcome::Available;
                        status.available = Some(ReleaseInfo {
                            version: m.version.clone(),
                            size_bytes: m.size_bytes,
                            sha256: m.sha256.clone(),
                            notes: result.notes,
                            signature_verified: true,
                        });
                        status.message = "Доступно подписанное обновление".into();
                    } else {
                        status.state = Stage::Idle;
                        status.check_outcome = CheckOutcome::NoUpdate;
                        status.message = "Более новых подписанных обновлений нет".into();
                    }
                    if result.manifest_unavailable {
                        status.message.push_str("; публичный манифест недоступен");
                    }
                }
                Err(error) => {
                    status.state = Stage::Failed;
                    status.check_outcome = match error {
                        UpdateError::Trust(_) | UpdateError::Integrity(_) => {
                            CheckOutcome::TrustError
                        }
                        UpdateError::Unsupported(_) => CheckOutcome::Unsupported,
                        _ => CheckOutcome::Unavailable,
                    };
                    status.message = error.to_string();
                }
            }
            status.updated_at = status.last_checked.unwrap_or_default();
            if let Some(cache) = &checks.cache
                && let Err(error) = cache.save(&status)
            {
                status.state = Stage::Failed;
                status.message = error.to_string();
            }
            if let Ok(mut current) = checks.snapshot.lock() {
                *current = (status, manual);
            }
        });
        Ok(initial)
    }
}
