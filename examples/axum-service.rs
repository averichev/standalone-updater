//! Independent, loopback-only consumer. All HTTP routes and authorization live
//! here, outside the library. See docs/integration.md and scripts/e2e.py.
#[cfg(target_os = "linux")]
mod service {
    use axum::{
        Json, Router,
        extract::{Request, State},
        http::StatusCode,
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use serde::Deserialize;
    use standalone_updater::{OperationStatus, UpdateError, UpdateSource, runtime::*};
    use std::{future::IntoFuture, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

    #[derive(Deserialize)]
    struct Settings {
        source: UpdateSource,
        mode: InstallationMode,
        updates_directory: PathBuf,
        data_file: PathBuf,
        address: SocketAddr,
        #[serde(default = "health_timeout")]
        health_timeout_ms: u64,
        #[serde(default)]
        manual_data_policy: bool,
    }
    fn health_timeout() -> u64 {
        30_000
    }
    const PRODUCT: &str = "44872c33-bef2-4c34-9290-29d762b6d965";
    fn build() -> BuildInfo {
        BuildInfo {
            version: option_env!("UPDATER_EXAMPLE_VERSION")
                .unwrap_or("0.5.0")
                .into(),
            rust_target: env!("UPDATER_EXAMPLE_TARGET").into(),
            product_id: PRODUCT.into(),
            self_update_protocol: 1,
            data_compatibility: option_env!("UPDATER_EXAMPLE_DATA")
                .unwrap_or("demo-format-v1")
                .into(),
        }
    }
    fn behavior() -> &'static str {
        option_env!("UPDATER_EXAMPLE_BEHAVIOR").unwrap_or("good")
    }

    #[derive(Clone)]
    struct App {
        manager: UpdateManager,
        data: PathBuf,
        admin_token: Arc<String>,
    }
    async fn authorize(State(app): State<App>, request: Request, next: Next) -> Response {
        // Non-cookie bearer authorization; browser Origin requests are rejected.
        if request.headers().contains_key("origin") {
            return StatusCode::FORBIDDEN.into_response();
        }
        let provided = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let expected = app.admin_token.as_bytes();
        let actual = provided.as_bytes();
        let mut difference = expected.len() ^ actual.len();
        for (index, byte) in expected.iter().enumerate() {
            difference |= usize::from(*byte ^ actual.get(index).copied().unwrap_or(0));
        }
        if difference != 0 {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        next.run(request).await
    }
    fn error(error: UpdateError) -> Response {
        let code = match error {
            UpdateError::Busy | UpdateError::Stale | UpdateError::Unsupported(_) => {
                StatusCode::CONFLICT
            }
            UpdateError::Trust(_) | UpdateError::Integrity(_) => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        (code, error.to_string()).into_response()
    }
    async fn health(State(app): State<App>) -> Response {
        // This is the application's readiness decision. A real application can
        // issue SELECT 1 here and return 503 while business resources are unready.
        if behavior() == "fail-health" || tokio::fs::metadata(&app.data).await.is_err() {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Json(app.manager.ready_response()).into_response()
    }
    async fn summary(State(app): State<App>) -> Response {
        app.manager
            .summary()
            .map(Json)
            .map(IntoResponse::into_response)
            .unwrap_or_else(error)
    }
    async fn check(State(app): State<App>) -> Response {
        operation(app.manager.check())
    }
    async fn prepare(State(app): State<App>, Json(request): Json<InstallRequest>) -> Response {
        operation(app.manager.prepare(request))
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Commit {
        operation_id: String,
    }
    async fn install(State(app): State<App>, Json(request): Json<Commit>) -> Response {
        operation(app.manager.install(&request.operation_id).await)
    }
    fn operation(result: standalone_updater::Result<OperationStatus>) -> Response {
        result
            .map(|value| (StatusCode::ACCEPTED, Json(value)).into_response())
            .unwrap_or_else(error)
    }
    async fn shutdown(manager: UpdateManager) {
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler")
                .recv()
                .await;
        };
        tokio::select! { _ = manager.shutdown_requested() => {}, _ = tokio::signal::ctrl_c() => {}, _ = terminate => {} }
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let build = build();
        if build.handle_cli()? {
            return Ok(());
        }
        let settings: Settings = serde_json::from_slice(&std::fs::read(
            std::env::var_os("UPDATER_DEMO_CONFIG").ok_or("set UPDATER_DEMO_CONFIG")?,
        )?)?;
        if !settings.address.ip().is_loopback() {
            return Err("demo requires loopback".into());
        }
        let mut arguments: Vec<String> = std::env::args().skip(1).collect();
        if arguments.first().is_some_and(|a| {
            [SERVER_ARGUMENT, WORKER_ARGUMENT, RECOVER_ARGUMENT].contains(&a.as_str())
        }) {
            arguments.remove(0);
        }
        let config = RuntimeConfig {
            source: settings.source,
            build,
            mode: settings.mode,
            executable: std::env::current_exe()?,
            updates_directory: settings.updates_directory,
            arguments,
            working_directory: std::env::current_dir()?,
            data_policy: if settings.manual_data_policy {
                DataPolicy::ManualOnly
            } else {
                DataPolicy::RequireExact
            },
            readiness: Readiness {
                timeout: Duration::from_millis(settings.health_timeout_ms),
                ..Readiness::http(settings.address, "/ready")
            },
        };
        let manager = match launch(config).await? {
            Launch::Exit(code) => std::process::exit(code),
            Launch::Serve(manager) => manager,
        };
        // Everything below is application-specific and never runs in build-info,
        // worker, recovery or supervising processes.
        if behavior() == "fail-start" {
            return Err("injected startup failure".into());
        }
        let resource_file = tokio::fs::File::open(&settings.data_file).await?;
        let token = std::env::var("UPDATER_DEMO_ADMIN_TOKEN")
            .map_err(|_| "set UPDATER_DEMO_ADMIN_TOKEN")?;
        if token.len() < 24 {
            return Err("demo token must contain at least 24 bytes".into());
        }
        let app = App {
            manager: manager.clone(),
            data: settings.data_file,
            admin_token: Arc::new(token),
        };
        let admin = Router::new()
            .route("/update", get(summary))
            .route("/update/check", post(check))
            .route("/update/prepare", post(prepare))
            .route("/update/install", post(install))
            .route_layer(middleware::from_fn_with_state(app.clone(), authorize));
        let router = Router::new()
            .route("/ready", get(health))
            .merge(admin)
            .with_state(app);
        let listener = tokio::net::TcpListener::bind(settings.address).await?;
        eprintln!(
            "Example application {} ready",
            manager.summary()?.current_version
        );
        let (draining, mut drain_started) = tokio::sync::oneshot::channel();
        let shutdown_manager = manager.clone();
        let server = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown(shutdown_manager).await;
                let _ = draining.send(());
            })
            .into_future();
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result?,
            _ = &mut drain_started => { tokio::time::timeout(Duration::from_secs(30), &mut server).await??; }
        }
        // Close business resources here (for SQLx: pool.close().await). A timeout
        // or failure must return without calling finish_shutdown().
        drop(resource_file);
        if behavior() == "unclean-shutdown" {
            return Err("injected shutdown failure; handoff intentionally not acknowledged".into());
        }
        manager.finish_shutdown()?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    service::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The installation example requires Linux. The protocol client is cross-platform.");
}
