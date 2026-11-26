use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use standalone_updater::*;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

const PRODUCT: &str = "a426b4ad-9b71-4672-a834-6f76578f2c31";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public_key() -> PublicKey {
    PublicKey {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: B64.encode(key().verifying_key().as_bytes()),
    }
}
fn source(base: &str) -> UpdateSource {
    UpdateSource {
        product_id: PRODUCT.into(),
        manifest_url: format!("{base}/manifest"),
        descriptor_url: format!("{base}/descriptor/{{target}}"),
        public_key: public_key(),
        allowed_download_origins: vec![base.into()],
        max_artifact_bytes: 1024 * 1024,
    }
}
fn client() -> UpdateClient {
    UpdateClient::new(source("http://127.0.0.1:1"), "0.5.0", "linux-x86_64").unwrap()
}
fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 128];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20] = 1;
    bytes[24..32].copy_from_slice(&0x400078_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&128_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&128_u64.to_le_bytes());
    bytes
}
fn payload(bytes: &[u8]) -> Value {
    json!({"schema_version":1,"application_id":PRODUCT,"version":"0.6.0","os":"linux","arch":"x86_64","size_bytes":bytes.len(),"sha256":Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()})
}
fn sign_raw(header: &str, payload: &str) -> String {
    sign_with(&key(), header, payload)
}
fn sign_with(signer: &SigningKey, header: &str, payload: &str) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(payload));
    format!(
        "{input}.{}",
        B64.encode(signer.sign(input.as_bytes()).to_bytes())
    )
}
fn descriptor(base: &str, payload: Value) -> Descriptor {
    Descriptor {
        version: payload["version"].as_str().unwrap().into(),
        url: format!("{base}/artifact"),
        signed_metadata: sign_raw(
            r#"{"alg":"EdDSA","typ":"releases-standalone+jws"}"#,
            &payload.to_string(),
        ),
    }
}

fn manifest_release(base: &str, version: &str) -> Value {
    let mut metadata = payload(&elf());
    metadata["version"] = json!(version);
    let signed = descriptor(base, metadata);
    json!({
        "version": version, "notes": format!("Notes for {version}"),
        "artifacts": [{
            "target": "linux-x86_64", "purpose": "executable",
            "download_url": signed.url, "signed_metadata": signed.signed_metadata
        }]
    })
}

#[derive(Clone)]
struct ServerState {
    descriptor: Arc<Mutex<(StatusCode, String)>>,
    manifest: Arc<Mutex<(StatusCode, String)>>,
    manifest_requests: Arc<Mutex<Vec<String>>>,
    artifact: Arc<Mutex<Vec<u8>>>,
    broken: Arc<Mutex<bool>>,
    query: Arc<Mutex<String>>,
    redirects: Arc<Mutex<Option<String>>>,
}
struct Server {
    base: String,
    state: ServerState,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn new() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = ServerState {
            descriptor: Arc::new(Mutex::new((
                StatusCode::OK,
                serde_json::to_string(&descriptor(&base, payload(&elf()))).unwrap(),
            ))),
            manifest: Arc::new(Mutex::new((
                StatusCode::OK,
                json!({"schema_version":2,"releases":[]}).to_string(),
            ))),
            manifest_requests: Arc::default(),
            artifact: Arc::new(Mutex::new(elf())),
            broken: Arc::new(Mutex::new(false)),
            query: Arc::new(Mutex::new(String::new())),
            redirects: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route("/descriptor/{target}", get(serve_descriptor))
            .route("/manifest", get(serve_manifest))
            .route("/artifact", get(serve_artifact))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, state, task }
    }
    fn client(&self) -> UpdateClient {
        UpdateClient::new(source(&self.base), "0.5.0", "linux-x86_64").unwrap()
    }
    fn manifest_client(&self) -> UpdateClient {
        let source = UpdateSource::from_manifest(
            format!("{}/manifest", self.base),
            PRODUCT,
            public_key(),
            vec![self.base.clone()],
            1024 * 1024,
        );
        UpdateClient::new(source, "0.5.0", "linux-x86_64").unwrap()
    }
    fn set_manifest(&self, document: Value) {
        *self.state.manifest.lock().unwrap() = (StatusCode::OK, document.to_string());
    }
    fn response(&self, code: StatusCode, body: impl Into<String>) {
        *self.state.descriptor.lock().unwrap() = (code, body.into());
    }
    fn signed(&self, bytes: &[u8]) {
        self.response(
            StatusCode::OK,
            serde_json::to_string(&descriptor(&self.base, payload(bytes))).unwrap(),
        );
    }
}
async fn serve_descriptor(State(state): State<ServerState>, request: Request) -> Response {
    *state.query.lock().unwrap() = request.uri().query().unwrap_or_default().into();
    // Keep the operation alive long enough to exercise concurrent requests deterministically.
    tokio::time::sleep(Duration::from_millis(60)).await;
    let (status, body) = state.descriptor.lock().unwrap().clone();
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}
async fn serve_manifest(State(state): State<ServerState>, request: Request) -> Response {
    state
        .manifest_requests
        .lock()
        .unwrap()
        .push(request.uri().to_string());
    state.manifest.lock().unwrap().clone().into_response()
}
async fn serve_artifact(State(state): State<ServerState>) -> Response {
    if let Some(url) = state.redirects.lock().unwrap().clone() {
        return (StatusCode::FOUND, [(header::LOCATION, url)]).into_response();
    }
    let bytes = state.artifact.lock().unwrap().clone();
    if *state.broken.lock().unwrap() {
        let stream = futures_util::stream::iter(vec![
            Ok(Bytes::from(bytes[..20].to_vec())),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "test disconnect",
            )),
        ]);
        return (
            StatusCode::OK,
            [(header::CONTENT_LENGTH, bytes.len().to_string())],
            Body::from_stream(stream),
        )
            .into_response();
    }
    bytes.into_response()
}

#[test]
fn channel_settings_persist_only_manifest_overrides_and_the_selection() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap().join("settings");
    let default = source("https://publisher.example.test");
    let channels = ChannelStore::open(&dir, default.clone()).unwrap();
    let entries = channels.list().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, DEFAULT_CHANNEL);
    assert!(entries[0].selected);
    assert_eq!(entries[0].manifest_url, default.manifest_url);
    let url = "https://archive.example.test/releases/1.x.json";
    channels.add("1.x", url).unwrap();
    assert_eq!(
        channels.active_source().unwrap().descriptor_url,
        default.descriptor_url
    );
    channels.select("1.x").unwrap();
    assert!(channels.add("1.x", "https://example.test/other").is_err());
    assert!(channels.add(DEFAULT_CHANNEL, url).is_err());
    assert!(channels.remove(DEFAULT_CHANNEL).is_err());
    assert!(channels.remove("1.x").is_err());
    assert!(channels.select("unknown").is_err());
    for invalid in [
        "file:///tmp/releases",
        "http://example.test/list",
        "https://u:p@example.test/",
    ] {
        assert!(channels.add("invalid", invalid).is_err());
    }
    let path = dir.join("channels.json");
    let settings: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        settings,
        json!({"schema_version": 1, "product_id": PRODUCT,
        "selected": "1.x", "channels": {"1.x": url}})
    );

    // The next build may change the embedded source or trust policy.
    let mut next = source("https://new.example.test");
    next.max_artifact_bytes = 128;
    next.public_key.x = B64.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().as_bytes());
    let reopened = ChannelStore::open(&dir, next.clone()).unwrap();
    let active = reopened.active_source().unwrap();
    assert_eq!(active.manifest_url, url);
    assert!(active.descriptor_url.is_empty());
    assert_eq!(active.product_id, next.product_id);
    assert_eq!(active.public_key.x, next.public_key.x);
    assert_eq!(
        active.allowed_download_origins,
        next.allowed_download_origins
    );
    assert_eq!(active.max_artifact_bytes, 128);
    let entries = reopened.list().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries.iter().find(|e| e.selected).unwrap().name, "1.x");
    reopened.select(DEFAULT_CHANNEL).unwrap();
    reopened.remove("1.x").unwrap();
    assert_eq!(
        reopened.active_source().unwrap().manifest_url,
        next.manifest_url
    );
    assert_eq!(
        reopened.active_source().unwrap().descriptor_url,
        next.descriptor_url
    );
    let mut other = next;
    other.product_id = "11111111-1111-4111-8111-111111111111".into();
    assert!(matches!(
        ChannelStore::open(&dir, other).unwrap().active_source(),
        Err(UpdateError::Trust(_))
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn channel_edits_merge_concurrent_writers_and_preserve_invalid_settings() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap().join("settings");
    let channels = ChannelStore::open(&dir, source("https://example.test")).unwrap();
    std::thread::scope(|scope| {
        for name in ["one", "two", "three", "four"] {
            let channels = channels.clone();
            scope.spawn(move || {
                channels
                    .add(name, &format!("https://example.test/{name}"))
                    .unwrap()
            });
        }
    });
    assert_eq!(channels.list().unwrap().len(), 5);
    let path = dir.join("channels.json");
    let settings: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for (field, value) in [
        ("selected", json!("missing")),
        ("public_key", json!({})),
        (
            "channels",
            json!({"default": "https://elsewhere.example.test"}),
        ),
    ] {
        let mut edited = settings.clone();
        edited[field] = value;
        let bytes = serde_json::to_vec(&edited).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            channels.active_source(),
            Err(UpdateError::Document)
        ));
        assert!(channels.select(DEFAULT_CHANNEL).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[tokio::test]
async fn selected_branch_works_offline_from_the_default_and_keeps_publisher_trust() {
    let official = Server::new().await;
    let branch = Server::new().await;
    official.response(StatusCode::SERVICE_UNAVAILABLE, "");
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().canonicalize().unwrap().join("settings");
    let channels = ChannelStore::open(&dir, source(&official.base)).unwrap();
    let client =
        || UpdateClient::new(channels.active_source().unwrap(), "0.5.0", "linux-x86_64").unwrap();
    assert!(matches!(
        client().check().await,
        Err(UpdateError::Http(503))
    ));
    channels
        .add("maintenance", &format!("{}/manifest", branch.base))
        .unwrap();
    channels.select("maintenance").unwrap();
    official.set_manifest(
        json!({"schema_version": 2, "releases": [manifest_release(&official.base, "9.0.0")]}),
    );
    official.state.manifest_requests.lock().unwrap().clear();
    official.state.query.lock().unwrap().clear();
    let release = manifest_release(&official.base, "0.5.2");
    let publish =
        |release: Value| branch.set_manifest(json!({"schema_version": 2, "releases": [release]}));
    publish(release.clone());
    let client = client();
    let update = client.check().await.unwrap().update.unwrap();
    assert_eq!(update.metadata().version, "0.5.2");
    client
        .download(&update, tempfile::tempfile().unwrap(), |_| Ok(()))
        .await
        .unwrap();
    let mut metadata = payload(&elf());
    metadata["version"] = json!("0.5.2");
    let mut forged = release;
    forged["artifacts"][0]["signed_metadata"] = json!(sign_with(
        &SigningKey::from_bytes(&[7; 32]),
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws"}"#,
        &metadata.to_string(),
    ));
    publish(forged);
    assert!(matches!(client.check().await, Err(UpdateError::Trust(_))));
    publish(manifest_release(&branch.base, "0.5.2"));
    assert!(matches!(client.check().await, Err(UpdateError::Trust(_))));
    publish(manifest_release(&official.base, "0.4.9"));
    assert!(client.check().await.unwrap().update.is_none());
    *branch.state.manifest.lock().unwrap() = (StatusCode::NOT_FOUND, String::new());
    assert!(matches!(client.check().await, Err(UpdateError::Http(404))));
    assert!(official.state.manifest_requests.lock().unwrap().is_empty());
    assert!(official.state.query.lock().unwrap().is_empty());
    assert!(branch.state.query.lock().unwrap().is_empty());

    let mut embedded = source(&official.base);
    embedded.allowed_download_origins.push(branch.base.clone());
    drop(official);
    publish(manifest_release(&branch.base, "0.5.3"));
    let channels = ChannelStore::open(&dir, embedded).unwrap();
    let client =
        UpdateClient::new(channels.active_source().unwrap(), "0.5.0", "linux-x86_64").unwrap();
    let update = client.check().await.unwrap().update.unwrap();
    assert_eq!(update.metadata().version, "0.5.3");
    client
        .download(&update, tempfile::tempfile().unwrap(), |_| Ok(()))
        .await
        .unwrap();
}

#[tokio::test]
async fn one_manifest_selects_the_newest_signed_executable_and_downloads_it() {
    let server = Server::new().await;
    let release = |v| manifest_release(&server.base, v);
    let mut manual = release("0.11.0");
    manual["artifacts"][0]
        .as_object_mut()
        .unwrap()
        .remove("signed_metadata");
    let mut foreign = release("2.0.0");
    foreign["artifacts"][0]["target"] = json!("linux-aarch64");
    let mut installer = release("3.0.0");
    installer["artifacts"][0]["purpose"] = json!("installer");
    server.set_manifest(json!({
        "schema_version": 2,
        "releases": [manual, foreign, release("1.0.0-rc.1"), installer, release("0.9.0")],
        "latest_by_type": {"executable": {"linux-x86_64": release("0.10.0")}}
    }));
    let config: UpdateSource = serde_json::from_value(json!({
        "product_id": PRODUCT, "public_key": public_key(),
        "manifest_url": format!("{}/manifest", server.base),
        "allowed_download_origins": [server.base], "max_artifact_bytes": 1024
    }))
    .unwrap();
    let client = UpdateClient::new(config, "0.5.0", "linux-x86_64").unwrap();
    let result = client.check().await.unwrap();
    assert_eq!(
        *server.state.manifest_requests.lock().unwrap(),
        ["/manifest"]
    );
    assert!(server.state.query.lock().unwrap().is_empty());
    assert!(!result.manifest_unavailable);
    assert_eq!(result.manual.unwrap().version, "0.11.0");
    assert_eq!(result.notes, "Notes for 0.10.0");
    let update = result.update.unwrap();
    assert_eq!(update.metadata().version, "0.10.0");
    client
        .download(&update, tempfile::tempfile().unwrap(), |_| Ok(()))
        .await
        .unwrap();
    server.state.artifact.lock().unwrap()[100] ^= 1;
    assert!(matches!(
        client
            .download(&update, tempfile::tempfile().unwrap(), |_| Ok(()))
            .await,
        Err(UpdateError::Integrity(_))
    ));
}

#[tokio::test]
async fn manifest_rejects_invalid_signed_candidates_without_falling_back() {
    let server = Server::new().await;
    let client = server.manifest_client();
    let older = manifest_release(&server.base, "0.6.0");
    let good = manifest_release(&server.base, "0.7.0");
    let mut bad_signature = good.clone();
    bad_signature["artifacts"][0]["signed_metadata"] = json!("invalid");
    let mut wrong_version = good.clone();
    wrong_version["version"] = json!("0.8.0");
    let mut wrong_origin = good;
    wrong_origin["artifacts"][0]["download_url"] = json!("https://foreign.test/file");
    for invalid in [bad_signature, wrong_version, wrong_origin] {
        server.set_manifest(json!({"schema_version": 2, "releases": [invalid, older]}));
        assert!(matches!(client.check().await, Err(UpdateError::Trust(_))));
    }
}

#[tokio::test]
async fn unsigned_manifest_offers_only_manual_download_and_requires_a_readable_manifest() {
    let server = Server::new().await;
    let client = server.manifest_client();
    let mut manual = manifest_release(&server.base, "0.6.0");
    manual["artifacts"][0]
        .as_object_mut()
        .unwrap()
        .remove("signed_metadata");
    server.set_manifest(json!({"schema_version": 2, "releases": [
        manual, manifest_release(&server.base, "0.5.0+other"), manifest_release(&server.base, "0.4.0")
    ]}));
    let result = client.check().await.unwrap();
    assert!(result.update.is_none());
    assert_eq!(result.manual.unwrap().version, "0.6.0");
    server.set_manifest(json!({"schema_version": 99}));
    assert!(matches!(client.check().await, Err(UpdateError::Document)));
    *server.state.manifest.lock().unwrap() = (StatusCode::SERVICE_UNAVAILABLE, String::new());
    assert!(matches!(client.check().await, Err(UpdateError::Http(503))));
    let legacy = server.client().check().await.unwrap();
    assert!(legacy.manifest_unavailable);
    assert_eq!(legacy.update.unwrap().metadata().version, "0.6.0");
}

#[tokio::test]
async fn explicit_descriptor_remains_authoritative_with_inline_signatures() {
    let server = Server::new().await;
    let client = server.client();
    server.set_manifest(
        json!({"schema_version": 2, "releases": [manifest_release(&server.base, "0.8.0")]}),
    );
    let result = client.check().await.unwrap();
    assert_eq!(result.update.unwrap().metadata().version, "0.6.0");
    assert_eq!(result.manual.unwrap().version, "0.8.0");
    server.response(StatusCode::NO_CONTENT, "");
    assert!(client.check().await.unwrap().update.is_none());
    server.response(StatusCode::OK, r#"{"version":"0.8.0"}"#);
    assert!(matches!(client.check().await, Err(UpdateError::Trust(_))));
}

#[tokio::test]
async fn no_update_and_available_update_and_manual_fallback() {
    let server = Server::new().await;
    let result = server.client().check().await.unwrap();
    assert_eq!(result.update.unwrap().metadata().version, "0.6.0");
    server.response(StatusCode::NO_CONTENT, "");
    assert!(server.client().check().await.unwrap().update.is_none());
    *server.state.manifest.lock().unwrap() = (StatusCode::OK, json!({"schema_version":2,"releases":[{"version":"0.7.0","notes":"Manual only","artifacts":[{"purpose":"executable","target":"linux-x86_64","download_url":format!("{}/artifact",server.base)}]}]}).to_string());
    let result = server.client().check().await.unwrap();
    assert!(result.update.is_none());
    assert_eq!(result.manual.unwrap().version, "0.7.0");
}

#[tokio::test]
async fn unavailable_server_invalid_json_and_oversized_response() {
    let server = Server::new().await;
    for (code, body) in [
        (StatusCode::SERVICE_UNAVAILABLE, "down".into()),
        (StatusCode::OK, "{".into()),
        (StatusCode::OK, "x".repeat(16 * 1024 + 1)),
    ] {
        server.response(code, body);
        assert!(matches!(
            server.client().check().await,
            Err(UpdateError::Http(503) | UpdateError::Document)
        ));
    }
    let client = server.client();
    drop(server);
    assert!(matches!(
        client.check().await,
        Err(UpdateError::Unavailable)
    ));
}

#[tokio::test]
async fn signature_is_required_even_when_manifest_and_https_claim_a_release() {
    let server = Server::new().await;
    server.response(
        StatusCode::OK,
        json!({"version":"0.6.0","url":format!("{}/artifact",server.base)}).to_string(),
    );
    assert!(matches!(
        server.client().check().await,
        Err(UpdateError::Trust(_))
    ));
    let mut descriptor = descriptor(&server.base, payload(&elf()));
    descriptor.signed_metadata.push('x');
    server.response(StatusCode::OK, serde_json::to_string(&descriptor).unwrap());
    assert!(matches!(
        server.client().check().await,
        Err(UpdateError::Trust(_))
    ));
}

#[test]
fn strict_jws_profile_rejects_unknown_duplicate_null_and_remote_keys() {
    let client = client();
    let base = "http://127.0.0.1:1";
    let good = payload(&elf());
    for header in [
        r#"{"alg":"none","typ":"releases-standalone+jws"}"#,
        r#"{"alg":"EdDSA","alg":"EdDSA","typ":"releases-standalone+jws"}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","kid":null}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","kid":""}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","kid":"other"}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","jku":"https://evil.test/key"}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","b64":false}"#,
        r#"{"alg":"EdDSA","typ":"releases-standalone+jws","crit":[]}"#,
    ] {
        let mut descriptor = descriptor(base, good.clone());
        descriptor.signed_metadata = sign_raw(header, &good.to_string());
        assert!(
            matches!(client.verify(descriptor), Err(UpdateError::Trust(_))),
            "{header}"
        );
    }
    for body in [
        good.to_string().replacen("{", r#"{"schema_version":1,"#, 1),
        good.to_string().replacen("{", r#"{"extra":true,"#, 1),
    ] {
        let mut descriptor = descriptor(base, good.clone());
        descriptor.signed_metadata =
            sign_raw(r#"{"alg":"EdDSA","typ":"releases-standalone+jws"}"#, &body);
        assert!(client.verify(descriptor).is_err());
    }
    let mut signed = descriptor(base, good);
    signed.signed_metadata = sign_raw(
        &json!({"alg":"EdDSA","typ":"releases-standalone+jws","kid":client.key_id()}).to_string(),
        &payload(&elf()).to_string(),
    );
    assert!(client.verify(signed).is_ok());
}

#[test]
fn signed_identity_versions_architecture_size_and_hash_are_enforced() {
    let client = client();
    for (field, value) in [
        (
            "application_id",
            json!("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        ),
        ("schema_version", json!(2)),
        ("os", json!("windows")),
        ("arch", json!("aarch64")),
        ("version", json!("0.4.0")),
        ("version", json!("0.5.0")),
        ("version", json!("0.5.0+other")),
        ("version", json!("v0.6.0")),
        ("version", json!("0.6.0-rc.1")),
        ("size_bytes", json!(0)),
        ("size_bytes", json!(1.5)),
        ("size_bytes", json!(2_u64.pow(53) + 1)),
        ("sha256", json!("A".repeat(64))),
    ] {
        let mut payload = payload(&elf());
        payload[field] = value;
        assert!(
            client
                .verify(descriptor("http://127.0.0.1:1", payload))
                .is_err(),
            "{field}"
        );
    }
    let mut mismatched = descriptor("http://127.0.0.1:1", payload(&elf()));
    mismatched.version = "0.9.0".into();
    assert!(client.verify(mismatched).is_err());
    let mut altered = descriptor("http://127.0.0.1:1", payload(&elf()));
    altered.url = "https://evil.test/payload".into();
    assert!(client.verify(altered).is_err());
}

#[tokio::test]
async fn build_metadata_is_encoded_and_does_not_raise_semver_precedence() {
    let server = Server::new().await;
    server.response(StatusCode::NO_CONTENT, "");
    let client = UpdateClient::new(source(&server.base), "0.5.0+build.1", "linux-x86_64").unwrap();
    client.check().await.unwrap();
    assert_eq!(
        *server.state.query.lock().unwrap(),
        "current_version=0.5.0%2Bbuild.1"
    );
}

#[tokio::test]
async fn streaming_download_reports_real_bytes_and_verifies_elf_and_sha256() {
    let server = Server::new().await;
    let client = server.client();
    let candidate = client.check().await.unwrap().update.unwrap();
    let mut received = Vec::new();
    let mut verifying = false;
    let file = client
        .download(&candidate, tempfile::tempfile().unwrap(), |event| {
            match event {
                DownloadEvent::Progress { downloaded, total } => {
                    assert_eq!(total, 128);
                    received.push(downloaded);
                }
                DownloadEvent::Verifying => verifying = true,
            }
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(file.metadata().unwrap().len(), 128);
    assert_eq!(received.first(), Some(&0));
    assert_eq!(received.last(), Some(&128));
    assert!(verifying);
    let mut bad = elf();
    bad[120] ^= 1;
    *server.state.artifact.lock().unwrap() = bad;
    assert!(matches!(
        client
            .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
            .await,
        Err(UpdateError::Integrity(_))
    ));
}

#[tokio::test]
async fn truncated_corrupted_wrong_arch_and_disconnected_downloads_never_prepare() {
    let server = Server::new().await;
    let client = server.client();
    for bytes in [elf()[..63].to_vec(), vec![0; 128], {
        let mut b = elf();
        b[18] = 183;
        b
    }] {
        server.signed(&bytes);
        *server.state.artifact.lock().unwrap() = bytes;
        let candidate = client.check().await.unwrap().update.unwrap();
        assert!(matches!(
            client
                .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
                .await,
            Err(UpdateError::Integrity(_))
        ));
    }
    server.signed(&elf());
    *server.state.artifact.lock().unwrap() = elf()[..63].to_vec();
    let candidate = client.check().await.unwrap().update.unwrap();
    assert!(
        client
            .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
            .await
            .is_err()
    );
    *server.state.artifact.lock().unwrap() = elf();
    *server.state.broken.lock().unwrap() = true;
    assert!(
        client
            .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn redirects_cannot_escape_allowlist_or_loop_forever() {
    let server = Server::new().await;
    let client = server.client();
    let candidate = client.check().await.unwrap().update.unwrap();
    for location in [
        "https://evil.test/file".to_string(),
        format!("{}/artifact", server.base),
    ] {
        *server.state.redirects.lock().unwrap() = Some(location);
        assert!(
            client
                .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
                .await
                .is_err()
        );
    }
}

#[test]
fn private_keys_public_http_and_noncanonical_origins_are_rejected() {
    assert!(
        serde_json::from_value::<PublicKey>(
            json!({"kty":"OKP","crv":"Ed25519","x":public_key().x,"d":"private"})
        )
        .is_err()
    );
    let mut config = source("http://127.0.0.1:1");
    config.descriptor_url = "http://example.com/updates".into();
    assert!(UpdateClient::new(config, "0.5.0", "linux-x86_64").is_err());
    let mut config = source("http://127.0.0.1:1");
    config.allowed_download_origins = vec!["https://example.com/path".into()];
    assert!(UpdateClient::new(config, "0.5.0", "linux-x86_64").is_err());
    let rfc = PublicKey {
        kty: "OKP".into(),
        crv: "Ed25519".into(),
        x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".into(),
    };
    let mut config = source("http://127.0.0.1:1");
    config.public_key = rfc;
    assert_eq!(
        UpdateClient::new(config, "0.5.0", "linux-x86_64")
            .unwrap()
            .key_id(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

#[tokio::test]
async fn candidates_cannot_cross_client_product_or_key_boundaries() {
    let server = Server::new().await;
    let candidate = server.client().check().await.unwrap().update.unwrap();
    let mut other_product = source(&server.base);
    other_product.product_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa".into();
    let mut other_key = source(&server.base);
    other_key.public_key.x =
        B64.encode(SigningKey::from_bytes(&[17; 32]).verifying_key().as_bytes());
    for source in [other_product, other_key] {
        let client = UpdateClient::new(source, "0.5.0", "linux-x86_64").unwrap();
        assert!(matches!(
            client
                .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
                .await,
            Err(UpdateError::Trust(_))
        ));
    }
}

#[test]
fn urls_and_debug_diagnostics_do_not_admit_credentials_or_expose_transport_tokens() {
    let mut config = source("http://127.0.0.1:1");
    config
        .manifest_url
        .push_str("?ticket=sensitive-example-token");
    assert!(!format!("{config:?}").contains("sensitive-example-token"));
    let client = UpdateClient::new(config, "0.5.0", "linux-x86_64").unwrap();
    let mut signed = descriptor("http://127.0.0.1:1", payload(&elf()));
    signed.url.push_str("?ticket=sensitive-example-token");
    let candidate = client.verify(signed).unwrap();
    assert!(!format!("{candidate:?}").contains("sensitive-example-token"));
    for url in [
        "http://localhost/file",
        "https://u:p@127.0.0.1/file",
        "http://127.0.0.1:1/file#fragment",
        "file:///tmp/payload",
    ] {
        assert!(client.artifact_url(url).is_err());
    }
}

#[tokio::test]
async fn non_linux_checks_and_downloads_do_not_pretend_to_install_or_require_elf() {
    let server = Server::new().await;
    let bytes = b"opaque platform executable";
    *server.state.artifact.lock().unwrap() = bytes.to_vec();
    for (os, arch) in [("windows", "x86_64"), ("darwin", "aarch64")] {
        let mut body = payload(bytes);
        body["os"] = json!(os);
        body["arch"] = json!(arch);
        let signed = descriptor(&server.base, body);
        server.response(StatusCode::OK, serde_json::to_string(&signed).unwrap());
        let client =
            UpdateClient::new(source(&server.base), "0.5.0", &format!("{os}-{arch}")).unwrap();
        let candidate = client.check().await.unwrap().update.unwrap();
        let result = client
            .download(&candidate, tempfile::tempfile().unwrap(), |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(result.metadata().unwrap().len(), bytes.len() as u64);
    }
}

#[test]
fn descriptor_duplicates_and_noncanonical_jws_are_rejected() {
    assert!(serde_json::from_str::<Descriptor>(r#"{"version":"0.6.0","version":"0.6.0","url":"https://example.test","signed_metadata":"x"}"#).is_err());
    for suffix in ["=", "\n", ".extra", "é"] {
        let mut signed = descriptor("http://127.0.0.1:1", payload(&elf()));
        signed.signed_metadata.push_str(suffix);
        assert!(client().verify(signed).is_err());
    }
    for bad in ["v0.6.0", " 0.6.0", "0.06.0", "0.6", "0.6.0 "] {
        assert!(canonical_version(bad).is_err());
    }
}

#[tokio::test]
async fn monitor_keeps_manual_urls_transient_and_checks_in_background() {
    let server = Server::new().await;
    server.response(StatusCode::NO_CONTENT, "");
    *server.state.manifest.lock().unwrap() = (StatusCode::OK, serde_json::json!({
        "schema_version": 2, "releases": [{"version":"0.6.0", "notes":"manual hint", "artifacts":[{
            "purpose":"executable", "target":"linux-x86_64", "download_url":format!("{}/artifact?token=transient-secret", server.base)
        }]}]
    }).to_string());
    let monitor =
        standalone_updater::UpdateMonitor::new(source(&server.base), "0.5.0", "linux-x86_64")
            .unwrap();
    assert_eq!(
        monitor.status().unwrap().state,
        standalone_updater::Stage::Idle
    );
    monitor.check().unwrap();
    assert!(matches!(monitor.check(), Err(UpdateError::Busy)));
    let status = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = monitor.status().unwrap();
            if !status.state.busy() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        status.check_outcome,
        standalone_updater::CheckOutcome::NoUpdate
    );
    assert!(
        monitor
            .manual_release()
            .unwrap()
            .unwrap()
            .download_url
            .contains("transient-secret")
    );
    assert!(
        !serde_json::to_string(&status)
            .unwrap()
            .contains("transient-secret")
    );
    assert!(!monitor.summary().unwrap().installation_supported);
}

#[tokio::test]
async fn check_cache_survives_restart_without_urls_or_installation_state() {
    let server = Server::new().await;
    let temporary = tempfile::tempdir().unwrap();
    let directory = temporary.path().canonicalize().unwrap().join("checks");
    let monitor =
        standalone_updater::UpdateMonitor::new(source(&server.base), "0.5.0", "linux-x86_64")
            .unwrap()
            .with_cache(&directory)
            .unwrap();
    monitor.check().unwrap();
    let checked = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = monitor.status().unwrap();
            if !status.state.busy() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(checked.state, standalone_updater::Stage::Available);
    let cache = directory.join("checks.json");
    let bytes = std::fs::read(&cache).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(&server.base));
    let reopened = || {
        standalone_updater::UpdateMonitor::new(source(&server.base), "0.5.0", "linux-x86_64")
            .unwrap()
            .with_cache(&directory)
    };
    assert_eq!(
        reopened().unwrap().status().unwrap().last_checked,
        checked.last_checked
    );
    assert_eq!(
        reopened()
            .unwrap()
            .status()
            .unwrap()
            .available
            .unwrap()
            .version,
        "0.6.0"
    );
    assert!(reopened().unwrap().manual_release().unwrap().is_none());
    for (version, target) in [("0.6.0", "linux-x86_64"), ("0.5.0", "darwin-x86_64")] {
        let other = standalone_updater::UpdateMonitor::new(source(&server.base), version, target)
            .unwrap()
            .with_cache(&directory)
            .unwrap();
        assert_eq!(
            other.status().unwrap().check_outcome,
            standalone_updater::CheckOutcome::NotChecked
        );
    }
    let mut other_branch = source(&server.base);
    other_branch.manifest_url.push_str("?branch=maintenance");
    let monitor = UpdateMonitor::new(other_branch, "0.5.0", "linux-x86_64")
        .unwrap()
        .with_cache(&directory)
        .unwrap();
    assert_eq!(
        monitor.status().unwrap().check_outcome,
        CheckOutcome::NotChecked
    );
    let mut another_product = source(&server.base);
    another_product.product_id = "11111111-1111-4111-8111-111111111111".into();
    assert_eq!(
        standalone_updater::UpdateMonitor::new(another_product, "0.5.0", "linux-x86_64")
            .unwrap()
            .with_cache(&directory)
            .unwrap()
            .status()
            .unwrap()
            .state,
        standalone_updater::Stage::Idle
    );
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut legacy = value.clone();
    legacy["schema_version"] = json!(1);
    legacy["status"]
        .as_object_mut()
        .unwrap()
        .remove("check_source_id");
    std::fs::write(&cache, serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_eq!(
        reopened().unwrap().status().unwrap().check_outcome,
        CheckOutcome::NotChecked
    );
    value["status"]["state"] = "prepared".into();
    std::fs::write(&cache, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(reopened(), Err(UpdateError::Document)));
    value["status"]["state"] = "checking".into();
    std::fs::write(&cache, serde_json::to_vec(&value).unwrap()).unwrap();
    let interrupted = reopened().unwrap().status().unwrap();
    assert_eq!(interrupted.state, standalone_updater::Stage::Failed);
    assert!(!interrupted.recovery_required);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let link = directory.parent().unwrap().join("alias");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(
            standalone_updater::UpdateMonitor::new(source(&server.base), "0.5.0", "linux-x86_64")
                .unwrap()
                .with_cache(&link)
                .is_err()
        );
    }
}
