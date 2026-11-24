//! Keep the launched PID alive across updates, regardless of the process manager.
//! Only private runtime copies in the data directory are replaced; the installed
//! launcher may be owned by root or mounted read-only.
use super::{
    files::{self, Directory, ExecutableLayout},
    worker as update_worker, *,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Stdio};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStdout, Command},
    signal::unix::{Signal, SignalKind, signal},
};

const CONTROL_LIMIT: u64 = 128 * 1024;

#[derive(Deserialize, Serialize)]
struct Launcher {
    sha256: String,
    product_id: String,
}

fn launcher_hash(config: &RuntimeConfig) -> Result<String> {
    files::hash_file(&mut files::open_launcher(&config.executable)?)
}

/// Read-only dispatch also keeps CLI version/build info in sync with the running
/// release without parsing unrelated server settings such as PORT.
pub fn active_executable(config: &RuntimeConfig) -> Result<Option<PathBuf>> {
    if config.mode != InstallationMode::Supervisor {
        return Ok(None);
    }
    let path = config.updates_directory.join("runtime");
    if !path.try_exists()? {
        return Ok(None);
    }
    let runtime = Directory::private(&path)?;
    if !runtime.path("launcher.json")?.try_exists()? {
        return Ok(None);
    }
    let launcher: Launcher = runtime.read("launcher.json")?;
    if launcher.sha256 != launcher_hash(config)? || launcher.product_id != config.build.product_id {
        return Ok(None);
    }
    let executable = runtime.path(executable_name(config)?)?;
    files::open_regular(&executable)?;
    Ok(Some(executable))
}

fn prepare_runtime(config: &RuntimeConfig, store: &Directory) -> Result<(PathBuf, bool)> {
    let _server_lock = store.lock("server.lock")?;
    let runtime = Directory::private(&store.as_path().join("runtime"))?;
    let executable = runtime.path(executable_name(config)?)?;
    let hash = launcher_hash(config)?;
    let initialized = runtime.path("launcher.json")?.try_exists()?;
    if initialized {
        let previous: Launcher = runtime.read("launcher.json")?;
        if previous.sha256 == hash && previous.product_id == config.build.product_id {
            files::open_regular(&executable)?;
            return Ok((executable, false));
        }
    }
    // A newly installed launcher intentionally supersedes its previous runtime.
    // A normal restart reuses the updated runtime without network access.
    let temporary = format!("launcher-{}.part", operation_id()?);
    let mut output = runtime.create(&temporary)?;
    let mut input = files::open_launcher(&config.executable)?;
    files::allocate(&output, input.metadata()?.len())?;
    std::io::copy(&mut input, &mut output)?;
    files::executable_permissions(&output)?;
    drop(output);
    std::fs::rename(runtime.path(&temporary)?, &executable)?;
    runtime.sync()?;
    runtime.write(
        "launcher.json",
        &Launcher {
            sha256: hash,
            product_id: config.build.product_id.clone(),
        },
    )?;
    Ok((executable, true))
}

pub(super) fn recover_interrupted(
    config: &RuntimeConfig,
    store: &Directory,
    executable: &std::path::Path,
) -> Result<()> {
    let mut status = store.status()?;
    if !(status.state.may_have_switched() || status.recovery_required)
        || status.worker.as_ref().is_some_and(files::process_alive)
    {
        return Ok(());
    }
    let _operation_lock = store.lock("operation.lock")?;
    let _server_lock = store.lock("server.lock")?;
    let job: update_worker::RecoveryJob = store.read("job.json")?;
    if job.executable != executable
        || status.operation_id.as_deref() != Some(&job.operation_id)
        || !valid_operation_id(&job.operation_id)
        || job.rust_target != config.build.rust_target
        || job.data_compatibility != config.build.data_compatibility
        || job.product_id != config.build.product_id
    {
        return Err(UpdateError::Worker);
    }
    let layout = ExecutableLayout::inspect(executable, &config.updates_directory.join("staging"))?;
    update_worker::restore_binary(&layout, &job)?;
    status.recovery_required = false;
    update_worker::transition(
        store,
        &mut status,
        Stage::RolledBack,
        "Перезапуск прервал проверку обновления; предыдущая версия восстановлена",
    )
}

struct Server {
    child: Child,
    output: ChildStdout,
    identity: ProcessIdentity,
}

fn launch(
    executable: &std::path::Path,
    arguments: &[String],
    nonce: Option<&str>,
    restart: bool,
    working_directory: &std::path::Path,
) -> Result<Server> {
    let mut command = Command::new(executable);
    command
        .current_dir(working_directory)
        .arg(SERVER_ARGUMENT)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    if restart {
        command.env("STANDALONE_UPDATER_RESTART", "1");
    }
    if let Some(nonce) = nonce {
        command.env(HEALTH_NONCE, nonce);
    }
    let parent = std::process::id();
    // A killed launcher must not leave an unmanaged HTTP server behind. This
    // also handles containers whose entrypoint is this executable (PID 1).
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() as u32 != parent {
                // pre_exec runs after fork: do not allocate on this error path.
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|_| UpdateError::Worker)?;
    let output = child.stdout.take().ok_or(UpdateError::Worker)?;
    let identity = child
        .id()
        .and_then(files::process_identity)
        .ok_or(UpdateError::Worker)?;
    Ok(Server {
        child,
        output,
        identity,
    })
}

struct Signals {
    terminate: Signal,
    interrupt: Signal,
}
impl Signals {
    fn new() -> Result<Self> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }
    async fn receive(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {},
            _ = self.interrupt.recv() => {},
        }
    }
}

pub async fn run(mut config: RuntimeConfig) -> Result<i32> {
    // An application may keep its supervisor while installation is disabled by
    // data policy or readiness configuration. These are manager capabilities,
    // not requirements for serving the current version.
    if !config.build.protocol_target()?.starts_with("linux-") {
        return Err(UpdateError::Unsupported(
            "supervisor requires a Linux build",
        ));
    }
    let arguments = config.arguments.clone();
    let mut signals = Signals::new()?;
    let store = Directory::private(&config.updates_directory)?;
    store.bind_product(&config.build.product_id)?;
    let _supervisor_lock = store.lock("supervisor.lock")?;
    let (executable, replaced) = prepare_runtime(&config, &store)?;
    if !replaced {
        recover_interrupted(&config, &store, &executable)?;
    } else {
        let mut status = store.status()?;
        if status.state.busy() || status.recovery_required {
            status.recovery_required = false;
            update_worker::transition(
                &store,
                &mut status,
                Stage::Failed,
                "Установлен новый исходный бинарник; прежняя операция отменена",
            )?;
        }
    }
    config.executable = executable.clone();
    let info = update_worker::build_info(&executable).await?;
    update_worker::inspect_candidate(&executable, &config.build, &info.version).await?;
    let mut version = info.version;
    config.build.version = version.clone();
    let mut server = launch(
        &executable,
        &arguments,
        None,
        false,
        &config.working_directory,
    )?;
    loop {
        let mut bytes = Vec::new();
        let wait = async {
            (&mut server.output)
                .take(CONTROL_LIMIT + 1)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() > CONTROL_LIMIT as usize {
                return Err(UpdateError::Document);
            }
            Ok::<_, UpdateError>(server.child.wait().await?)
        };
        let exit = tokio::select! {
            result = wait => result?,
            _ = signals.receive() => {
                update_worker::stop_child(&mut server.child).await?;
                return Ok(0);
            }
        };
        if !exit.success() || bytes.is_empty() {
            return Ok(exit.code().unwrap_or(1));
        }
        if bytes.len() > CONTROL_LIMIT as usize {
            return Err(UpdateError::Document);
        }
        let job: update_worker::PreparedJob =
            serde_json::from_slice(&bytes).map_err(|_| UpdateError::Document)?;
        if job.parent != server.identity
            || job.executable != executable
            || job.previous_version != version
            || job.rust_target != config.build.rust_target
            || job.data_compatibility != config.build.data_compatibility
            || job.product_id != config.build.product_id
        {
            return Err(UpdateError::Worker);
        }
        match install(&config, &store, &job, &mut signals).await {
            Ok(Some(next)) => {
                version = update_worker::build_info(&executable).await?.version;
                config.build.version = version.clone();
                server = next;
            }
            Ok(None) => return Ok(0),
            Err(error) => {
                let mut status = store.status()?;
                status.recovery_required = status.state.may_have_switched();
                update_worker::transition(&store, &mut status, Stage::Failed, error.to_string())?;
                return Err(error);
            }
        }
    }
}

async fn start_checked(
    config: &RuntimeConfig,
    store: &Directory,
    status: &mut OperationStatus,
    job: &update_worker::PreparedJob,
    version: &str,
    signals: &mut Signals,
    stopped: &mut bool,
) -> Result<Server> {
    let rollback = status.state == Stage::RollingBack;
    if !rollback {
        update_worker::transition(store, status, Stage::Starting, "Запуск новой версии")?;
    }
    // The nonce is inherited only by this launch, never written to the job.
    let nonce = operation_id()?;
    let mut server = launch(
        &job.executable,
        &config.arguments,
        Some(&nonce),
        true,
        &config.working_directory,
    )?;
    if !rollback {
        update_worker::transition(
            store,
            status,
            Stage::HealthCheck,
            "Ожидание готовности приложения",
        )?;
    }
    let result = tokio::select! {
        result = update_worker::health_check(&mut server.child, &config.readiness, version, &nonce) => result,
        _ = signals.receive() => {
            *stopped = true;
            Err(UpdateError::Worker)
        }
    };
    if let Err(error) = result {
        update_worker::stop_child(&mut server.child).await?;
        return Err(error);
    }
    Ok(server)
}

async fn install(
    config: &RuntimeConfig,
    store: &Directory,
    job: &update_worker::PreparedJob,
    signals: &mut Signals,
) -> Result<Option<Server>> {
    let _operation_lock = store.lock("operation.lock")?;
    let layout = config.layout()?;
    let mut status = store.status()?;
    if !valid_operation_id(&job.operation_id)
        || status.operation_id.as_deref() != Some(&job.operation_id)
        || status.state != Stage::Stopping
        || layout.staging.read::<String>(&job.stopped())? != job.operation_id
    {
        return Err(UpdateError::Worker);
    }
    let mut effective = config.clone();
    effective.build.version = job.previous_version.clone();
    let client = effective.client()?;
    let metadata = client.verify_context(&job.signed.version, &job.signed.signed_metadata)?;
    let server_lock = store.lock("server.lock")?;
    let switched = update_worker::switch_binary(store, &mut status, job, &layout, &metadata);
    drop(server_lock);
    if matches!(switched, Err(UpdateError::Stale)) {
        return Err(UpdateError::Stale);
    }
    let mut stopped = false;
    let result = match switched {
        Ok(()) => {
            start_checked(
                config,
                store,
                &mut status,
                job,
                &job.signed.version,
                signals,
                &mut stopped,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let server = match result {
        Ok(mut server) => {
            status.recovery_required = false;
            if let Err(error) = update_worker::transition(
                store,
                &mut status,
                Stage::Completed,
                format!("Установлена версия {}", job.signed.version),
            ) {
                update_worker::stop_child(&mut server.child).await?;
                return Err(error);
            }
            Some(server)
        }
        Err(error) => {
            if matches!(error, UpdateError::Trust(_) | UpdateError::Integrity(_)) {
                status.check_outcome = CheckOutcome::TrustError;
            }
            update_worker::transition(
                store,
                &mut status,
                Stage::RollingBack,
                format!("{error}. Восстановление предыдущего бинарника"),
            )?;
            let server_lock = store.lock("server.lock")?;
            update_worker::restore_binary(&layout, &job.recovery())?;
            drop(server_lock);
            if stopped {
                update_worker::transition(
                    store,
                    &mut status,
                    Stage::RolledBack,
                    "Обновление отменено при остановке приложения; предыдущий бинарник восстановлен",
                )?;
                None
            } else {
                let server = start_checked(
                    config,
                    store,
                    &mut status,
                    job,
                    &job.previous_version,
                    signals,
                    &mut stopped,
                )
                .await?;
                status.recovery_required = false;
                update_worker::transition(
                    store,
                    &mut status,
                    Stage::RolledBack,
                    format!("{error}. Восстановлена версия {}", job.previous_version),
                )?;
                Some(server)
            }
        }
    };
    let _ = layout.staging.remove(&job.stopped());
    Ok(server)
}

fn executable_name(config: &RuntimeConfig) -> Result<&str> {
    config
        .executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(UpdateError::Unsupported("executable name is not UTF-8"))
}
