use super::{files::*, worker::*, *};
use std::{
    fs,
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
};

fn executable(path: &std::path::Path, source: &str) {
    fs::copy(source, path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn private_state_is_durable_and_locks_exclude_other_handles() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Directory::private(&temporary.path().join("private/state")).unwrap();
    let mut status = OperationStatus {
        state: Stage::Downloading,
        downloaded_bytes: 73,
        ..Default::default()
    };
    store.save_status(&mut status).unwrap();
    let reopened = Directory::private(store.as_path()).unwrap();
    store.bind_product("product-one").unwrap();
    reopened.bind_product("product-one").unwrap();
    assert!(matches!(
        reopened.bind_product("product-two"),
        Err(UpdateError::Trust(_))
    ));
    assert_eq!(reopened.status().unwrap().downloaded_bytes, 73);
    assert_eq!(
        fs::metadata(store.path("status.json").unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let lock = store.lock("operation.lock").unwrap();
    assert!(matches!(
        reopened.lock("operation.lock"),
        Err(UpdateError::Busy)
    ));
    drop(lock);
    assert!(reopened.lock("operation.lock").is_ok());
    assert!(matches!(require_space(10, 11), Err(UpdateError::NoSpace)));
}

#[test]
fn lock_release_does_not_wait_for_an_unrelated_forked_child_to_exec() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Directory::private(&temporary.path().join("state")).unwrap();
    let lock = store.lock("operation.lock").unwrap();
    let mut pipe = [-1; 2];
    // SAFETY: two valid out-parameters; child performs only async-signal-safe
    // syscalls after fork, then _exit without running Rust destructors.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        unsafe {
            libc::close(pipe[1]);
            let mut byte = 0_u8;
            libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
            libc::_exit(0);
        }
    }
    drop(lock);
    let acquired = store.lock("operation.lock");
    // Release and reap the child before asserting, including failure paths.
    unsafe {
        libc::close(pipe[0]);
        let byte = 1_u8;
        libc::write(pipe[1], (&byte as *const u8).cast(), 1);
        libc::close(pipe[1]);
        libc::waitpid(child, std::ptr::null_mut(), 0);
    }
    assert!(
        acquired.is_ok(),
        "a pre-exec child must not prolong a released lock"
    );
}

#[test]
fn supervisor_recovers_failed_with_recovery_required_without_replaying_completed_jobs() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, layout, job, metadata, mut status) = fixture(temporary.path());
    switch_binary(&store, &mut status, &job, &layout, &metadata).unwrap();
    status.state = Stage::Failed;
    status.recovery_required = true;
    store.save_status(&mut status).unwrap();
    store.write("job.json", &job.recovery()).unwrap();
    let config = RuntimeConfig {
        source: UpdateSource {
            product_id: job.product_id.clone(),
            manifest_url: "http://127.0.0.1:1/manifest".into(),
            descriptor_url: "http://127.0.0.1:1/descriptor".into(),
            public_key: PublicKey {
                kty: "OKP".into(),
                crv: "Ed25519".into(),
                x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
            },
            allowed_download_origins: vec![],
            max_artifact_bytes: 1024,
        },
        build: BuildInfo {
            version: job.previous_version.clone(),
            rust_target: job.rust_target.clone(),
            product_id: job.product_id.clone(),
            self_update_protocol: 1,
            data_compatibility: job.data_compatibility.clone(),
        },
        mode: InstallationMode::Standalone,
        executable: layout.executable.clone(),
        updates_directory: store.as_path().into(),
        arguments: vec![],
        working_directory: temporary.path().into(),
        data_policy: DataPolicy::RequireExact,
        readiness: Readiness::http("127.0.0.1:8080".parse().unwrap(), "/ready"),
    };
    supervisor::recover_interrupted(&config, &store, &layout.executable).unwrap();
    assert_eq!(store.status().unwrap().state, Stage::RolledBack);
    assert!(!store.status().unwrap().recovery_required);
    assert_eq!(
        hash_file(&mut open_regular(&layout.executable).unwrap()).unwrap(),
        job.previous_sha256
    );
    status.state = Stage::Completed;
    status.recovery_required = false;
    store.save_status(&mut status).unwrap();
    assert!(super::recover(&config).is_err());
}

#[tokio::test]
async fn readiness_rejects_wrong_instance_and_a_child_that_exits_after_answering() {
    use axum::{Json, Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/ready", get(|| async { Json(serde_json::json!({"status":"ok","version":"0.6.0","update_instance":"exact-instance"})) }))).await.unwrap();
    });
    let policy = Readiness {
        address,
        path: "/ready".into(),
        timeout: std::time::Duration::from_millis(80),
        stability: std::time::Duration::from_millis(30),
    };
    let mut child = tokio::process::Command::new("/bin/sleep")
        .arg("5")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    assert!(matches!(
        worker::health_check(&mut child, &policy, "0.6.0", "another-instance").await,
        Err(UpdateError::Health)
    ));
    worker::stop_child(&mut child).await.unwrap();
    let mut child = tokio::process::Command::new("/bin/sleep")
        .arg("0.01")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    assert!(matches!(
        worker::health_check(&mut child, &policy, "0.6.0", "exact-instance").await,
        Err(UpdateError::Health)
    ));
    child.wait().await.unwrap();
    server.abort();
}

#[test]
fn symlinks_traversal_special_files_and_unsafe_permissions_are_rejected() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Directory::private(&temporary.path().join("state")).unwrap();
    for name in ["../app", "/tmp/file", "..", "a/b", "a\\b", "", "\0"] {
        assert!(store.path(name).is_err());
    }
    let business = temporary.path().join("business-data");
    fs::write(&business, b"untouched").unwrap();
    symlink(&business, store.path("link").unwrap()).unwrap();
    assert!(store.read::<serde_json::Value>("link").is_err());
    assert!(store.lock("link").is_err());
    assert!(store.create("link").is_err());
    assert_eq!(fs::read(&business).unwrap(), b"untouched");
    symlink(store.as_path(), temporary.path().join("ancestor-link")).unwrap();
    assert!(Directory::private(&temporary.path().join("ancestor-link/nested")).is_err());
    assert!(!store.path("nested").unwrap().exists());
    let unsafe_directory = temporary.path().join("unsafe");
    fs::create_dir(&unsafe_directory).unwrap();
    fs::set_permissions(&unsafe_directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Directory::private(&unsafe_directory).is_err());
    assert!(Directory::private(&unsafe_directory.join("nested")).is_err());
    let fifo = store.path("fifo").unwrap();
    use std::os::unix::ffi::OsStrExt;
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(open_regular(&fifo).is_err());
}

#[test]
fn executable_directory_must_be_writable_even_when_running_as_root() {
    let temporary = tempfile::tempdir().unwrap();
    let parent = temporary.path().join("app");
    fs::create_dir(&parent).unwrap();
    let app = parent.join("arbitrary binary name");
    executable(&app, "/bin/true");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(ExecutableLayout::inspect(&app, &temporary.path().join("staging")).is_err());
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ExecutableLayout::inspect(&app, &temporary.path().join("staging")).is_ok());
    symlink(&app, parent.join("alias")).unwrap();
    assert!(
        ExecutableLayout::inspect(&parent.join("alias"), &temporary.path().join("staging"))
            .is_err()
    );
}

fn fixture(
    root: &std::path::Path,
) -> (
    Directory,
    ExecutableLayout,
    PreparedJob,
    SignedMetadata,
    OperationStatus,
) {
    let app = root.join("any-name");
    executable(&app, "/bin/true");
    let store = Directory::private(&root.join("state")).unwrap();
    let layout = ExecutableLayout::inspect(&app, &store.as_path().join("staging")).unwrap();
    // Some distributions use multicall coreutils with identical file bytes.
    // Give each fixture a distinct trailer without changing valid ELF segments.
    fs::OpenOptions::new()
        .append(true)
        .open(&app)
        .unwrap()
        .write_all(b"baseline-fixture-v1")
        .unwrap();
    let mut candidate = fs::read("/bin/true").unwrap();
    candidate.extend_from_slice(b"candidate-fixture-v2");
    let candidate_size = candidate.len() as u64;
    let job = PreparedJob {
        operation_id: operation_id().unwrap(),
        executable: app,
        parent: process_identity(std::process::id()).unwrap(),
        previous_version: "0.5.0".into(),
        previous_sha256: hash_file(&mut open_regular(&layout.executable).unwrap()).unwrap(),
        candidate_sha256: {
            use sha2::{Digest, Sha256};
            crate::hex(&Sha256::digest(&candidate))
        },
        rust_target: format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
        product_id: "44872c33-bef2-4c34-9290-29d762b6d965".into(),
        data_compatibility: "v1".into(),
        signed: SignedContext {
            version: "0.6.0".into(),
            signed_metadata: "not-used-by-file-tests".into(),
        },
    };
    fs::write(layout.staging.path(&job.ready()).unwrap(), candidate).unwrap();
    executable_permissions(&open_regular(&layout.staging.path(&job.ready()).unwrap()).unwrap())
        .unwrap();
    fs::hard_link(
        &layout.executable,
        layout.staging.path(&job.backup()).unwrap(),
    )
    .unwrap();
    let metadata = SignedMetadata {
        schema_version: 1,
        application_id: job.product_id.clone(),
        version: "0.6.0".into(),
        os: "linux".into(),
        arch: std::env::consts::ARCH.into(),
        size_bytes: candidate_size,
        sha256: job.candidate_sha256.clone(),
    };
    let status = OperationStatus {
        operation_id: Some(job.operation_id.clone()),
        state: Stage::Stopping,
        ..Default::default()
    };
    (store, layout, job, metadata, status)
}

#[test]
fn switch_and_restore_are_atomic_and_do_not_write_through_backups_or_data() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, layout, job, metadata, mut status) = fixture(temporary.path());
    fs::write(temporary.path().join("customer.data"), b"preserved").unwrap();
    switch_binary(&store, &mut status, &job, &layout, &metadata).unwrap();
    assert_eq!(status.state, Stage::Switching);
    assert_eq!(
        hash_file(&mut open_regular(&layout.executable).unwrap()).unwrap(),
        metadata.sha256
    );
    assert_eq!(
        hash_file(&mut open_regular(&layout.staging.path(&job.backup()).unwrap()).unwrap())
            .unwrap(),
        job.previous_sha256
    );
    assert!(switch_binary(&store, &mut status, &job, &layout, &metadata).is_err());
    restore_binary(&layout, &job.recovery()).unwrap();
    restore_binary(&layout, &job.recovery()).unwrap();
    assert_eq!(
        hash_file(&mut open_regular(&layout.executable).unwrap()).unwrap(),
        job.previous_sha256
    );
    assert_eq!(
        fs::read(temporary.path().join("customer.data")).unwrap(),
        b"preserved"
    );
}

#[test]
fn manual_replacement_and_corrupt_backup_are_not_overwritten() {
    let temporary = tempfile::tempdir().unwrap();
    let (store, layout, job, metadata, mut status) = fixture(temporary.path());
    let replacement = temporary.path().join("manual.part");
    executable(&replacement, "/bin/true");
    fs::OpenOptions::new()
        .append(true)
        .open(&replacement)
        .unwrap()
        .write_all(b"manual-replacement-v3")
        .unwrap();
    let manual_bytes = fs::read(&replacement).unwrap();
    fs::rename(&replacement, &layout.executable).unwrap();
    assert!(matches!(
        switch_binary(&store, &mut status, &job, &layout, &metadata),
        Err(UpdateError::Stale)
    ));
    assert!(restore_binary(&layout, &job.recovery()).is_err());
    assert_eq!(fs::read(&layout.executable).unwrap(), manual_bytes);
    // Corrupt backup cannot restore even a known candidate.
    fs::copy(
        layout.staging.path(&job.ready()).unwrap(),
        &layout.executable,
    )
    .unwrap();
    fs::write(layout.staging.path(&job.backup()).unwrap(), b"corrupt").unwrap();
    assert!(restore_binary(&layout, &job.recovery()).is_err());
}

#[test]
fn process_identity_includes_start_time_and_diagnostics_exclude_transport_tokens() {
    let identity = process_identity(std::process::id()).unwrap();
    assert!(process_alive(&identity));
    assert!(!process_alive(&ProcessIdentity {
        start_ticks: identity.start_ticks + 1,
        ..identity
    }));
    let temporary = tempfile::tempdir().unwrap();
    let (_, _, job, _, _) = fixture(temporary.path());
    let encoded = serde_json::to_string(&job.recovery()).unwrap();
    assert!(!encoded.contains("signed_metadata"));
    assert!(!encoded.contains("arguments"));
    assert!(!encoded.contains("http"));
}
