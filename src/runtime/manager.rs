use super::{
    files::{self, Directory, ExecutableLayout},
    worker::{self, PreparedJob, SignedContext, transition},
    *,
};
use serde::{Deserialize, Serialize};
use std::{
    process::Stdio,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, Command},
    sync::watch,
};

struct WorkerChannel {
    input: ChildStdin,
    child: Child,
}
struct Inner {
    config: RuntimeConfig,
    client: UpdateClient,
    store: Directory,
    layout: std::result::Result<ExecutableLayout, String>,
    supervisor: Option<ProcessIdentity>,
    server_lock: Mutex<Option<files::FileLock>>,
    worker: Mutex<Option<WorkerChannel>>,
    prepared: Mutex<Option<PreparedJob>>,
    handoff: Mutex<Option<PreparedJob>>,
    shutdown: watch::Sender<bool>,
}

/// Cloneable update operations and durable polling snapshots. It creates no
/// HTTP handlers. Applications own access control and shutdown resource order.
#[derive(Clone)]
pub struct UpdateManager(Arc<Inner>);

/// Redacted updater diagnostics. Endpoint URLs, argv and environment are absent.
#[derive(Serialize)]
pub struct UpdateSummary {
    /// Application version (not the updater crate version).
    pub current_version: String,
    /// Exact protocol target derived from the application's Rust target.
    pub target: String,
    /// Public trust-anchor thumbprint.
    pub trusted_key_id: String,
    /// Configured process ownership.
    pub installation_mode: InstallationMode,
    /// Whether preparation is currently allowed.
    pub installation_supported: bool,
    /// Redacted reason when installation is unavailable.
    pub installation_reason: Option<String>,
    /// Persistent progress and recovery result.
    pub status: OperationStatus,
}

/// Confirmation of one previously checked signed release. No URL/key/target
/// supplied by a caller is accepted here.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    /// Operation identifier returned by [`UpdateManager::check`].
    pub check_id: String,
    /// Exact selected version, including build metadata.
    pub version: String,
}

impl UpdateManager {
    pub(super) fn new(config: RuntimeConfig, supervisor: Option<ProcessIdentity>) -> Result<Self> {
        let client = config.client()?;
        let store = Directory::private(&config.updates_directory)?;
        store.bind_product(&config.build.product_id)?;
        let server_lock = if config.mode == InstallationMode::External {
            None
        } else {
            Some(store.lock("server.lock")?)
        };
        let layout = if config.mode == InstallationMode::Supervisor && supervisor.is_none() {
            Err("supervisor is not running".into())
        } else {
            config.layout().map_err(|e| e.to_string())
        };
        if config.mode != InstallationMode::External
            && config.executable != std::env::current_exe()?
        {
            return Err(UpdateError::Integrity(
                "configured executable differs from the running application",
            ));
        }
        let (shutdown, _) = watch::channel(false);
        let manager = Self(Arc::new(Inner {
            config,
            client,
            store,
            layout,
            supervisor,
            server_lock: Mutex::new(server_lock),
            worker: Mutex::new(None),
            prepared: Mutex::new(None),
            handoff: Mutex::new(None),
            shutdown,
        }));
        manager.reconcile_interrupted()?;
        Ok(manager)
    }

    fn reconcile_interrupted(&self) -> Result<()> {
        let store = &self.0.store;
        let mut status = store.status()?;
        if !status.state.busy() || status.worker.as_ref().is_some_and(files::process_alive) {
            return Ok(());
        }
        let _lock = match store.lock("operation.lock") {
            Ok(lock) => lock,
            Err(UpdateError::Busy) => return Ok(()),
            Err(error) => return Err(error),
        };
        status = store.status()?;
        if !status.state.busy() || status.worker.as_ref().is_some_and(files::process_alive) {
            return Ok(());
        }
        status.recovery_required = status.state.may_have_switched();
        if let Some(id) = status
            .operation_id
            .as_ref()
            .filter(|id| valid_operation_id(id))
            && let Ok(layout) = &self.0.layout
        {
            layout.staging.remove(&format!("candidate-{id}.part"))?;
        }
        let message = if status.recovery_required {
            "Interrupted installation requires offline recovery; previous binary retained"
        } else {
            "Interrupted before binary replacement; check and prepare again"
        };
        transition(store, &mut status, Stage::Failed, message)
    }

    /// Read persistent state. Reconcile abandoned preparation without touching data.
    pub fn status(&self) -> Result<OperationStatus> {
        self.reconcile_interrupted()?;
        self.0.store.status()
    }

    /// Read diagnostics suitable for a polling or SSE adapter.
    pub fn summary(&self) -> Result<UpdateSummary> {
        let status = self.status()?;
        let reason = self.0.layout.as_ref().err().cloned().or_else(|| {
            status
                .recovery_required
                .then(|| "offline recovery required".into())
        });
        Ok(UpdateSummary {
            current_version: self.0.config.build.version.clone(),
            target: self.0.config.build.protocol_target()?,
            trusted_key_id: self.0.client.key_id().into(),
            installation_mode: self.0.config.mode,
            installation_supported: reason.is_none(),
            installation_reason: reason,
            status,
        })
    }

    /// Begin a background signed update check. Returns the operation ID immediately.
    /// An overlapping operation returns [`UpdateError::Busy`].
    pub fn check(&self) -> Result<OperationStatus> {
        let store = &self.0.store;
        let lock = store.lock("operation.lock")?;
        let previous = store.status()?;
        if previous.recovery_required {
            return Err(UpdateError::Unsupported("offline recovery required"));
        }
        if previous.state.busy() {
            return Err(UpdateError::Busy);
        }
        let mut status = OperationStatus {
            operation_id: Some(operation_id()?),
            state: Stage::Checking,
            message: "Checking signed release".into(),
            last_checked: previous.last_checked,
            ..Default::default()
        };
        store.save_status(&mut status)?;
        let initial = status.clone();
        let manager = self.clone();
        tokio::spawn(async move {
            let _lock = lock;
            let result = manager.0.client.check().await;
            status.last_checked = Some(now());
            match result {
                Ok(result) => {
                    status.manual_release = result.manual.map(|r| ManualReleaseInfo {
                        version: r.version,
                        notes: r.notes,
                    });
                    if let Some(update) = result.update {
                        let m = update.metadata();
                        status.check_outcome = CheckOutcome::Available;
                        status.state = Stage::Available;
                        status.available = Some(ReleaseInfo {
                            version: m.version.clone(),
                            size_bytes: m.size_bytes,
                            sha256: m.sha256.clone(),
                            notes: result.notes,
                            signature_verified: true,
                        });
                        status.message =
                            "Signed update available; artifact verification pending".into();
                    } else {
                        status.check_outcome = CheckOutcome::NoUpdate;
                        status.state = Stage::Idle;
                        status.message = "No newer signed release for this target".into();
                    }
                    if result.manifest_unavailable {
                        status.message.push_str("; manifest unavailable");
                    }
                }
                Err(error) => mark_failed(&mut status, &error),
            }
            // Persistence failures are visible through status() as abandoned work.
            let _ = manager.0.store.save_status(&mut status);
        });
        Ok(initial)
    }

    /// Download and preflight the selected release in the background. The
    /// application continues serving until a separate [`Self::install`] call.
    /// Preparation rechecks the selected version/hash/size and reserves disk blocks.
    pub fn prepare(&self, request: InstallRequest) -> Result<OperationStatus> {
        let store = &self.0.store;
        let lock = store.lock("operation.lock")?;
        let mut status = store.status()?;
        if status.operation_id.as_deref() != Some(&request.check_id)
            || status
                .available
                .as_ref()
                .is_none_or(|a| a.version != request.version || !a.signature_verified)
            || status.state != Stage::Available
            || status.recovery_required
        {
            return Err(UpdateError::Stale);
        }
        if !self.summary()?.installation_supported {
            return Err(UpdateError::Unsupported("installation is unavailable"));
        }
        self.0.config.layout()?;
        status.worker = files::process_identity(std::process::id());
        transition(
            store,
            &mut status,
            Stage::Checking,
            "Rechecking selected release",
        )?;
        let initial = status.clone();
        let manager = self.clone();
        tokio::spawn(async move {
            let _lock = lock;
            match manager.prepare_job(&mut status).await {
                Ok(job) => match manager.0.prepared.lock() {
                    Ok(mut prepared) => *prepared = Some(job),
                    Err(_) => {
                        mark_failed(&mut status, &UpdateError::Worker);
                        let _ = manager.0.store.save_status(&mut status);
                    }
                },
                Err(error) => {
                    if let Some(id) = status
                        .operation_id
                        .as_ref()
                        .filter(|id| valid_operation_id(id))
                        && let Ok(layout) = &manager.0.layout
                    {
                        let _ = layout.staging.remove(&format!("candidate-{id}.part"));
                        let _ = layout.staging.remove(&format!("candidate-{id}.ready"));
                    }
                    status.worker = None;
                    mark_failed(&mut status, &error);
                    let _ = manager.0.store.save_status(&mut status);
                }
            }
        });
        Ok(initial)
    }

    async fn prepare_job(&self, status: &mut OperationStatus) -> Result<PreparedJob> {
        let store = &self.0.store;
        let config = &self.0.config;
        let update = self
            .0
            .client
            .check()
            .await?
            .update
            .ok_or(UpdateError::Stale)?;
        let selected = status.available.as_ref().ok_or(UpdateError::Stale)?;
        let metadata = update.metadata();
        if selected.version != metadata.version
            || selected.sha256 != metadata.sha256
            || selected.size_bytes != metadata.size_bytes
        {
            return Err(UpdateError::Stale);
        }
        let layout = config.layout()?;
        let mut current = files::open_regular(&layout.executable)?;
        let required = metadata
            .size_bytes
            .checked_add(current.metadata()?.len())
            .and_then(|s| s.checked_add(16 * 1024 * 1024))
            .ok_or(UpdateError::NoSpace)?;
        files::require_space(layout.available_space()?, required)?;
        let job = PreparedJob {
            operation_id: status.operation_id.clone().ok_or(UpdateError::Stale)?,
            executable: layout.executable.clone(),
            parent: files::process_identity(std::process::id()).ok_or(UpdateError::Worker)?,
            previous_version: config.build.version.clone(),
            previous_sha256: files::hash_file(&mut current)?,
            candidate_sha256: metadata.sha256.clone(),
            rust_target: config.build.rust_target.clone(),
            product_id: config.build.product_id.clone(),
            data_compatibility: config.build.data_compatibility.clone(),
            signed: SignedContext {
                version: update.descriptor().version.clone(),
                signed_metadata: update.descriptor().signed_metadata.clone(),
            },
        };
        status.total_bytes = Some(metadata.size_bytes);
        transition(store, status, Stage::Downloading, "Downloading artifact")?;
        let file = layout.staging.create(&job.part())?;
        files::allocate(&file, metadata.size_bytes)?;
        let mut saved = Instant::now();
        let file = self
            .0
            .client
            .download(&update, file, |event| {
                match event {
                    DownloadEvent::Progress { downloaded, total } => {
                        status.downloaded_bytes = downloaded;
                        status.total_bytes = Some(total);
                        if downloaded == total || saved.elapsed() >= Duration::from_millis(200) {
                            store.save_status(status)?;
                            saved = Instant::now();
                        }
                    }
                    DownloadEvent::Verifying => transition(
                        store,
                        status,
                        Stage::Verifying,
                        "Verifying size, SHA-256 and ELF",
                    )?,
                }
                Ok(())
            })
            .await?;
        files::executable_permissions(&file)?;
        drop(file);
        std::fs::rename(
            layout.staging.path(&job.part())?,
            layout.staging.path(&job.ready())?,
        )?;
        layout.staging.sync()?;
        worker::inspect_candidate(
            &layout.staging.path(&job.ready())?,
            &config.build,
            &metadata.version,
        )
        .await?;
        std::fs::hard_link(&job.executable, layout.staging.path(&job.backup())?)?;
        current.sync_all()?;
        layout.staging.sync()?;
        store.write("job.json", &job.recovery())?;
        transition(
            store,
            status,
            Stage::Prepared,
            "Prepared; installation awaits explicit handoff",
        )?;
        Ok(job)
    }

    /// Begin installation of an already prepared operation. No release-server
    /// request is made. Signals shutdown only after the supervisor/worker is ready.
    /// Repeated calls for the same stopping/completed operation return its status.
    pub async fn install(&self, id: &str) -> Result<OperationStatus> {
        let store = &self.0.store;
        let _operation = store.lock("operation.lock")?;
        let mut status = store.status()?;
        if status.operation_id.as_deref() != Some(id) || status.recovery_required {
            return Err(UpdateError::Stale);
        }
        if matches!(
            status.state,
            Stage::Stopping | Stage::Completed | Stage::RolledBack
        ) {
            return Ok(status);
        }
        if status.state != Stage::Prepared {
            return Err(UpdateError::Stale);
        }
        let job = self
            .0
            .prepared
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .take()
            .ok_or(UpdateError::Stale)?;
        if let Err(error) = self.begin_handoff(&job, &mut status).await {
            status.worker = None;
            mark_failed(&mut status, &error);
            store.save_status(&mut status)?;
            return Err(error);
        }
        Ok(status)
    }

    /// Discard a prepared candidate before shutdown. A fresh check is needed to
    /// prepare again; this cannot cancel an installation that already handed off.
    pub fn cancel_prepared(&self, id: &str) -> Result<OperationStatus> {
        let store = &self.0.store;
        let _operation = store.lock("operation.lock")?;
        let mut status = store.status()?;
        if status.operation_id.as_deref() != Some(id) || status.state != Stage::Prepared {
            return Err(UpdateError::Stale);
        }
        let job = self
            .0
            .prepared
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .take()
            .ok_or(UpdateError::Stale)?;
        let layout = self.0.config.layout()?;
        layout.staging.remove(&job.ready())?;
        layout.staging.remove(&job.backup())?;
        store.remove("job.json")?;
        status.worker = None;
        transition(
            store,
            &mut status,
            Stage::Failed,
            "Prepared update cancelled; check again",
        )?;
        Ok(status)
    }

    async fn begin_handoff(&self, job: &PreparedJob, status: &mut OperationStatus) -> Result<()> {
        let config = &self.0.config;
        let store = &self.0.store;
        let layout = config.layout()?;
        let metadata = self
            .0
            .client
            .verify_context(&job.signed.version, &job.signed.signed_metadata)?;
        files::verify_file(&layout.staging.path(&job.ready())?, &metadata)?;
        worker::inspect_candidate(
            &layout.staging.path(&job.ready())?,
            &config.build,
            &metadata.version,
        )
        .await?;
        if config.mode == InstallationMode::Supervisor {
            status.worker = self.0.supervisor.clone();
            if status.worker.is_none() {
                return Err(UpdateError::Worker);
            }
            transition(
                store,
                status,
                Stage::Stopping,
                "Waiting for graceful application shutdown",
            )?;
            *self.0.handoff.lock().map_err(|_| UpdateError::Worker)? = Some(job.clone());
        } else {
            let mut current = files::open_regular(&layout.executable)?;
            if files::hash_file(&mut current)? != job.previous_sha256 {
                return Err(UpdateError::Integrity("running executable changed"));
            }
            use std::io::{Seek, SeekFrom};
            current.seek(SeekFrom::Start(0))?;
            let mut worker = layout.staging.create(&job.worker())?;
            std::io::copy(&mut current, &mut worker)?;
            files::executable_permissions(&worker)?;
            drop(worker);
            layout.staging.sync()?;
            let mut child = Command::new(layout.staging.path(&job.worker())?)
                .arg(WORKER_ARGUMENT)
                .args(&config.arguments)
                .current_dir(&config.working_directory)
                .stdin(Stdio::piped())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|_| UpdateError::Worker)?;
            let mut input = child.stdin.take().ok_or(UpdateError::Worker)?;
            let mut encoded = serde_json::to_vec(job).map_err(|_| UpdateError::Document)?;
            encoded.push(b'\n');
            let started = async {
                input.write_all(&encoded).await?;
                input.flush().await?;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                loop {
                    if let Ok(identity) =
                        layout.staging.read::<ProcessIdentity>(&job.acknowledged())
                        && child.id() == Some(identity.pid)
                        && files::process_alive(&identity)
                    {
                        return Ok(identity);
                    }
                    if child.try_wait()?.is_some() || tokio::time::Instant::now() >= deadline {
                        return Err(UpdateError::Worker);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            .await;
            let identity = match started {
                Ok(id) => id,
                Err(error) => {
                    let _ = child.kill().await;
                    return Err(error);
                }
            };
            status.worker = Some(identity);
            if let Err(error) = transition(
                store,
                status,
                Stage::Stopping,
                "Waiting for graceful application shutdown",
            ) {
                let _ = child.kill().await;
                return Err(error);
            }
            *self.0.worker.lock().map_err(|_| UpdateError::Worker)? =
                Some(WorkerChannel { input, child });
        }
        self.0.shutdown.send_replace(true);
        Ok(())
    }

    /// Await the updater's shutdown request; combine with the application's
    /// existing signal handling. Clones can independently await the same request.
    pub async fn shutdown_requested(&self) {
        let mut receiver = self.0.shutdown.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }

    /// Construct a success response for the configured health route. Call only
    /// after checking the application's database and other required resources.
    pub fn ready_response(&self) -> ReadyResponse {
        ReadyResponse {
            status: "ok",
            version: self.0.config.build.version.clone(),
            update_instance: std::env::var(HEALTH_NONCE)
                .ok()
                .filter(|id| valid_operation_id(id)),
        }
    }

    /// Commit a clean shutdown after listener drain and application resource
    /// closure. Failure to call this cancels the switch. Return from main promptly
    /// after success; the worker also requires the old process to exit.
    pub fn finish_shutdown(&self) -> Result<()> {
        let handoff = self
            .0
            .handoff
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .take();
        let channel = self
            .0
            .worker
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .take();
        if handoff.is_some() || channel.is_some() {
            let job: worker::RecoveryJob = self.0.store.read("job.json")?;
            let layout = self.0.config.layout()?;
            layout.staging.write(&job.stopped(), &job.operation_id)?;
        }
        if let Some(job) = handoff {
            use std::io::Write;
            let mut output = std::io::stdout().lock();
            serde_json::to_writer(&mut output, &job).map_err(|_| UpdateError::Document)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
        self.0
            .server_lock
            .lock()
            .map_err(|_| UpdateError::Worker)?
            .take();
        if let Some(channel) = channel {
            drop(channel.input);
            drop(channel.child);
        }
        Ok(())
    }
}

fn mark_failed(status: &mut OperationStatus, error: &UpdateError) {
    status.state = Stage::Failed;
    status.message = error.to_string();
    status.check_outcome = match error {
        UpdateError::Trust(_) | UpdateError::Integrity(_) => CheckOutcome::TrustError,
        UpdateError::Unsupported(_) => CheckOutcome::Unsupported,
        _ => CheckOutcome::Unavailable,
    };
}
