//! Short-lived worker using a temporary copy of the application executable.
use super::{
    files::{self, Directory, ExecutableLayout},
    *,
};
use crate::client::bounded_body;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::{Child, Command},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedJob {
    pub operation_id: String,
    pub executable: PathBuf,
    pub parent: ProcessIdentity,
    pub previous_version: String,
    pub previous_sha256: String,
    pub candidate_sha256: String,
    pub rust_target: String,
    pub product_id: String,
    pub data_compatibility: String,
    pub signed: SignedContext,
}

/// Durable recovery needs no remote URL, signed download token, argv or environment.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryJob {
    pub operation_id: String,
    pub executable: PathBuf,
    pub previous_version: String,
    pub previous_sha256: String,
    pub candidate_sha256: String,
    pub rust_target: String,
    pub product_id: String,
    pub data_compatibility: String,
}
impl RecoveryJob {
    pub fn backup(&self) -> String {
        format!("backup-{}", self.operation_id)
    }
    pub fn stopped(&self) -> String {
        format!("stopped-{}.json", self.operation_id)
    }
}
impl PreparedJob {
    pub fn recovery(&self) -> RecoveryJob {
        RecoveryJob {
            operation_id: self.operation_id.clone(),
            executable: self.executable.clone(),
            previous_version: self.previous_version.clone(),
            previous_sha256: self.previous_sha256.clone(),
            candidate_sha256: self.candidate_sha256.clone(),
            rust_target: self.rust_target.clone(),
            product_id: self.product_id.clone(),
            data_compatibility: self.data_compatibility.clone(),
        }
    }
    pub fn part(&self) -> String {
        format!("candidate-{}.part", self.operation_id)
    }
    pub fn ready(&self) -> String {
        format!("candidate-{}.ready", self.operation_id)
    }
    pub fn backup(&self) -> String {
        format!("backup-{}", self.operation_id)
    }
    pub fn worker(&self) -> String {
        format!("worker-{}", self.operation_id)
    }
    pub fn acknowledged(&self) -> String {
        format!("worker-ready-{}.json", self.operation_id)
    }
    pub fn stopped(&self) -> String {
        format!("stopped-{}.json", self.operation_id)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedContext {
    pub version: String,
    pub signed_metadata: String,
}

pub async fn inspect_candidate(path: &Path, expected: &BuildInfo, version: &str) -> Result<()> {
    let info = build_info(path).await?;
    if info.version != version
        || info.rust_target != expected.rust_target
        || info.product_id != expected.product_id
    {
        return Err(UpdateError::Integrity(
            "candidate version/product/Rust target mismatch",
        ));
    }
    if info.self_update_protocol != 1 || info.data_compatibility != expected.data_compatibility {
        return Err(UpdateError::Unsupported(
            "data compatibility changed or runtime handshake unsupported; manual update required",
        ));
    }
    Ok(())
}

pub(super) async fn build_info(path: &Path) -> Result<BuildInfo> {
    let mut child = Command::new(path)
        .arg(BUILD_INFO_ARGUMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            UpdateError::Unsupported("подготовленный бинарник не запускается на этой системе")
        })?;
    let output = child.stdout.take().ok_or(UpdateError::Worker)?;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = Vec::new();
        output.take(16 * 1024 + 1).read_to_end(&mut bytes).await?;
        let status = child.wait().await?;
        if !status.success() || bytes.len() > 16 * 1024 {
            return Err(UpdateError::Integrity("некорректный --build-info"));
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| UpdateError::Integrity("некорректный --build-info"))
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => {
            let _ = child.kill().await;
            Err(UpdateError::Unsupported(
                "истекло время проверки совместимости бинарника",
            ))
        }
    }
}

pub fn loopback_address(address: SocketAddr) -> SocketAddr {
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, address.port())
}

pub fn transition(
    store: &Directory,
    status: &mut OperationStatus,
    stage: Stage,
    message: impl Into<String>,
) -> Result<()> {
    status.state = stage;
    status.message = message.into();
    store.save_status(status)
}

#[cfg(target_os = "linux")]
pub async fn run(mut config: RuntimeConfig) -> Result<()> {
    config.validate_installation()?;
    if config.mode != InstallationMode::Standalone {
        return Err(UpdateError::Unsupported(
            "внешний менеджер владеет процессом",
        ));
    }
    // No job paths, keys, URLs or environment on the command line. The parent owns this pipe.
    let mut input = BufReader::new(tokio::io::stdin().take(128 * 1024));
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), input.read_line(&mut line))
        .await
        .map_err(|_| UpdateError::Worker)??;
    let job: PreparedJob = serde_json::from_str(&line).map_err(|_| UpdateError::Document)?;
    let store = Directory::private(&config.updates_directory)?;
    store.bind_product(&config.build.product_id)?;
    if !valid_operation_id(&job.operation_id)
        || std::env::current_exe()?
            != Directory::private(&config.updates_directory.join("staging"))?.path(&job.worker())?
    {
        return Err(UpdateError::Worker);
    }
    config.executable = job.executable.clone();
    let mut status = store.status()?;
    let result = run_job(&config, &store, &mut status, &job, &mut input).await;
    if let Err(error) = &result {
        status.recovery_required = status.state.may_have_switched()
            || files::open_regular(&job.executable)
                .and_then(|mut file| files::hash_file(&mut file))
                .is_ok_and(|hash| hash != job.previous_sha256);
        let _ = transition(&store, &mut status, Stage::Failed, error.to_string());
    }
    result
}

#[cfg(target_os = "linux")]
async fn run_job(
    config: &RuntimeConfig,
    store: &Directory,
    status: &mut OperationStatus,
    job: &PreparedJob,
    input: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<()> {
    if !valid_operation_id(&job.operation_id)
        || status.operation_id.as_deref() != Some(&job.operation_id)
        || status.state != Stage::Prepared
        || job.previous_version != config.build.version
        || job.rust_target != config.build.rust_target
        || job.data_compatibility != config.build.data_compatibility
        || job.product_id != config.build.product_id
        || !files::process_alive(&job.parent)
        || job.executable != config.executable
    {
        return Err(UpdateError::Worker);
    }
    let layout = config.layout()?;
    if std::env::current_exe()? != layout.staging.path(&job.worker())?
        || files::hash_file(&mut files::open_regular(&std::env::current_exe()?)?)?
            != job.previous_sha256
        || files::hash_file(&mut files::open_regular(&job.executable)?)? != job.previous_sha256
    {
        return Err(UpdateError::Integrity("worker/текущий бинарник изменился"));
    }
    let client = config.client()?;
    let metadata = client.verify_context(&job.signed.version, &job.signed.signed_metadata)?;
    files::verify_file(&layout.staging.path(&job.ready())?, &metadata)?;
    verify_backup(&layout, &job.recovery())?;
    layout.staging.write(
        &job.acknowledged(),
        &files::process_identity(std::process::id()).ok_or(UpdateError::Worker)?,
    )?;
    // EOF alone is insufficient: a crash is not approval to replace the executable.
    let mut tail = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(90),
        input.take(1).read_to_end(&mut tail),
    )
    .await
    .map_err(|_| UpdateError::Worker)??;
    if !tail.is_empty() || layout.staging.read::<String>(&job.stopped())? != job.operation_id {
        return Err(UpdateError::Worker);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while files::process_alive(&job.parent) {
        if tokio::time::Instant::now() >= deadline {
            return Err(UpdateError::Worker);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _operation_lock = store.lock("operation.lock")?;
    // A second server or a recovery command must not overlap the switch.
    let server_lock = store.lock("server.lock")?;
    *status = store.status()?;
    if status.operation_id.as_deref() != Some(&job.operation_id) || status.state != Stage::Stopping
    {
        return Err(UpdateError::Worker);
    }
    let switched = switch_binary(store, status, job, &layout, &metadata);
    drop(server_lock);
    if matches!(switched, Err(UpdateError::Stale)) {
        return Err(UpdateError::Stale);
    }
    let new_result = match switched {
        Ok(()) => match launch_and_check(config, store, status, job, &job.signed.version).await {
            Ok(mut child) => {
                status.recovery_required = false;
                match transition(
                    store,
                    status,
                    Stage::Completed,
                    format!("Установлена версия {}", job.signed.version),
                ) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        stop_child(&mut child).await?;
                        Err(error)
                    }
                }
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    match new_result {
        Ok(()) => {}
        Err(error) => {
            if matches!(error, UpdateError::Trust(_) | UpdateError::Integrity(_)) {
                status.check_outcome = CheckOutcome::TrustError;
            }
            transition(
                store,
                status,
                Stage::RollingBack,
                format!("{error}. Восстановление предыдущего бинарника"),
            )?;
            let server_lock = store.lock("server.lock")?;
            restore_binary(&layout, &job.recovery())?;
            drop(server_lock);
            match launch_and_check(config, store, status, job, &job.previous_version).await {
                Ok(_child) => {
                    status.recovery_required = false;
                    transition(
                        store,
                        status,
                        Stage::RolledBack,
                        format!(
                            "{error}. Восстановлен бинарник {}. Пользовательские данные не восстанавливались",
                            job.previous_version
                        ),
                    )?;
                }
                Err(_) => {
                    return Err(UpdateError::Unsupported(
                        "предыдущий бинарник восстановлен, но его запуск не подтверждён; проверьте журнал процесса и запустите вручную",
                    ));
                }
            }
        }
    }
    let _ = layout.staging.remove(&job.stopped());
    let _ = layout.staging.remove(&job.acknowledged());
    let _ = layout.staging.remove(&job.worker());
    Ok(())
}

#[cfg(target_os = "linux")]
async fn launch_and_check(
    config: &RuntimeConfig,
    store: &Directory,
    status: &mut OperationStatus,
    job: &PreparedJob,
    version: &str,
) -> Result<Child> {
    let rollback = status.state == Stage::RollingBack;
    if !rollback {
        transition(
            store,
            status,
            Stage::Starting,
            "Запуск новой версии с прежними параметрами и окружением",
        )?;
    }
    let nonce = operation_id()?;
    let mut child = Command::new(&job.executable)
        .args(&config.arguments)
        .current_dir(&config.working_directory)
        .env(HEALTH_NONCE, &nonce)
        .env("STANDALONE_UPDATER_RESTART", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| UpdateError::Health)?;
    let result = async {
        if !rollback {
            transition(
                store,
                status,
                Stage::HealthCheck,
                "Ожидание готовности приложения",
            )?;
        }
        health_check(&mut child, &config.readiness, version, &nonce).await
    }
    .await;
    if result.is_err() {
        stop_child(&mut child).await?;
    }
    result.map(|()| child)
}

#[cfg(target_os = "linux")]
pub(super) async fn health_check(
    child: &mut Child,
    readiness: &Readiness,
    version: &str,
    nonce: &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| UpdateError::Health)?;
    let deadline = tokio::time::Instant::now() + readiness.timeout;
    let address = loopback_address(readiness.address);
    while tokio::time::Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Err(UpdateError::Health);
        }
        if let Ok(response) = client
            .get(format!("http://{address}{}", readiness.path))
            .send()
            .await
            && response.status() == reqwest::StatusCode::OK
            && let Ok(bytes) = bounded_body(response, 4096).await
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && value["status"] == "ok"
            && value["version"] == version
            && value["update_instance"] == nonce
        {
            // Do not leave a child that has already exited after answering once.
            tokio::time::sleep(readiness.stability).await;
            if child.try_wait()?.is_none() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(UpdateError::Health)
}

#[cfg(target_os = "linux")]
pub(super) async fn stop_child(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_none() {
        if let Some(pid) = child.id() {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(result) => {
                result?;
            }
            Err(_) => child.kill().await?,
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn switch_binary(
    store: &Directory,
    status: &mut OperationStatus,
    job: &PreparedJob,
    layout: &ExecutableLayout,
    metadata: &SignedMetadata,
) -> Result<()> {
    config_layout_matches(layout)?;
    if job.candidate_sha256 != metadata.sha256 {
        return Err(UpdateError::Integrity("candidate context changed"));
    }
    files::verify_file(&layout.staging.path(&job.ready())?, metadata)?;
    verify_backup(layout, &job.recovery())?;
    if files::hash_file(&mut files::open_regular(&job.executable)?)? != job.previous_sha256 {
        return Err(UpdateError::Stale);
    }
    transition(
        store,
        status,
        Stage::Switching,
        "Атомарная замена исполняемого файла",
    )?;
    std::fs::rename(layout.staging.path(&job.ready())?, &job.executable)?;
    files::sync_directory(job.executable.parent().ok_or(UpdateError::Worker)?)?;
    layout.staging.sync()
}

fn verify_backup(layout: &ExecutableLayout, job: &RecoveryJob) -> Result<()> {
    if files::hash_file(&mut files::open_regular(
        &layout.staging.path(&job.backup())?,
    )?)? != job.previous_sha256
    {
        return Err(UpdateError::Integrity("резервный бинарник повреждён"));
    }
    Ok(())
}
pub(super) fn restore_binary(layout: &ExecutableLayout, job: &RecoveryJob) -> Result<()> {
    config_layout_matches(layout)?;
    let actual = files::hash_file(&mut files::open_regular(&job.executable)?)?;
    if actual == job.previous_sha256 {
        return Ok(());
    }
    if actual != job.candidate_sha256 {
        return Err(UpdateError::Integrity(
            "installed binary changed outside this operation; refusing to overwrite it",
        ));
    }
    verify_backup(layout, job)?;
    let temporary = format!("restore-{}", operation_id()?);
    let path = layout.staging.path(&temporary)?;
    std::fs::hard_link(layout.staging.path(&job.backup())?, &path)?;
    std::fs::rename(&path, &job.executable)?;
    files::sync_directory(job.executable.parent().ok_or(UpdateError::Worker)?)?;
    layout.staging.sync()
}

pub fn recover(config: &RuntimeConfig) -> Result<()> {
    config.validate_installation()?;
    let store = Directory::private(&config.updates_directory)?;
    store.bind_product(&config.build.product_id)?;
    let _supervisor = store.lock("supervisor.lock")?;
    let _operation = store.lock("operation.lock")?;
    let _server = store.lock("server.lock")?;
    let mut effective = config.clone();
    if config.mode == InstallationMode::Supervisor {
        effective.executable =
            super::supervisor::active_executable(config)?.ok_or(UpdateError::Worker)?;
    }
    let job: RecoveryJob = store.read("job.json")?;
    let mut status = store.status()?;
    if !valid_operation_id(&job.operation_id)
        || status.operation_id.as_deref() != Some(&job.operation_id)
        || !status.recovery_required && !status.state.may_have_switched()
        || job.executable != effective.executable
        || job.data_compatibility != config.build.data_compatibility
        || job.product_id != config.build.product_id
        || job.rust_target != config.build.rust_target
        || status.worker.as_ref().is_some_and(files::process_alive)
    {
        return Err(UpdateError::Unsupported(
            "recovery identity/compatibility could not be established",
        ));
    }
    let layout = effective.layout()?;
    restore_binary(&layout, &job)?;
    status.recovery_required = false;
    transition(
        &store,
        &mut status,
        Stage::RolledBack,
        "Previous binary restored. Restart with the original configuration; user data was not restored",
    )
}

fn config_layout_matches(layout: &ExecutableLayout) -> Result<()> {
    ExecutableLayout::inspect(&layout.executable, layout.staging.as_path())?;
    Ok(())
}
