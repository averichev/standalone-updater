use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::{Client, Response, StatusCode, redirect::Policy};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};
use tokio::io::AsyncWriteExt;
use url::Url;

const DOCUMENT_LIMIT: usize = 16 * 1024;
const MANIFEST_LIMIT: usize = 512 * 1024;

#[derive(Clone)]
/// Async protocol client with pinned trust, size limits and constrained redirects.
pub struct UpdateClient {
    source: UpdateSource,
    current: Version,
    target: String,
    metadata_client: Client,
    download_client: Client,
    key: VerifyingKey,
    key_id: String,
}

/// Stream download events. Bytes are actual received bytes.
pub enum DownloadEvent {
    /// Actual bytes streamed so far.
    Progress {
        /// Received and written bytes.
        downloaded: u64,
        /// Signed expected artifact length.
        total: u64,
    },
    /// Streaming ended; final size/hash/platform validation begins.
    Verifying,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    #[serde(default, deserialize_with = "present_string")]
    kid: Option<String>,
}
fn present_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| UpdateError::Trust("неверный base64url"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value || value.is_empty() {
        return Err(UpdateError::Trust("неканонический base64url"));
    }
    Ok(bytes)
}

fn parse_url(value: &str) -> Result<Url> {
    if value.len() > 8192 {
        return Err(UpdateError::Trust("URL превышает локальный лимит"));
    }
    let url = Url::parse(value).map_err(|_| UpdateError::Trust("некорректный URL"))?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if url.host_str().is_none()
        || !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(UpdateError::Trust(
            "разрешён HTTPS без credentials; HTTP только для loopback",
        ));
    }
    Ok(url)
}

fn client(origins: Option<Vec<String>>, timeout: Duration) -> Result<Client> {
    Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(15))
        .timeout(timeout)
        .redirect(Policy::custom(move |attempt| {
            let allowed = match &origins {
                Some(origins) => origins.contains(&attempt.url().origin().ascii_serialization()),
                None => attempt
                    .previous()
                    .first()
                    .is_some_and(|original| original.origin() == attempt.url().origin()),
            };
            if attempt.previous().len() > 3
                || !allowed
                || parse_url(attempt.url().as_str()).is_err()
            {
                attempt.error("redirect denied by local update policy")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| UpdateError::Unavailable)
}

pub(crate) async fn bounded_body(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(UpdateError::Document);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| UpdateError::Unavailable)?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(UpdateError::Document);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Parse a canonical SemVer without silently normalizing it.
pub fn canonical_version(value: &str) -> Result<Version> {
    let version =
        Version::parse(value).map_err(|_| UpdateError::Trust("некорректная SemVer-версия"))?;
    if version.to_string() != value {
        return Err(UpdateError::Trust("неканоническая SemVer-версия"));
    }
    Ok(version)
}

fn product_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

impl UpdateClient {
    /// Construct a client; validates configuration without network access.
    pub fn new(source: UpdateSource, current_version: &str, target: &str) -> Result<Self> {
        if !product_id(&source.product_id)
            || !matches!(
                target,
                "linux-x86_64"
                    | "linux-aarch64"
                    | "darwin-aarch64"
                    | "darwin-x86_64"
                    | "windows-x86_64"
                    | "windows-aarch64"
            )
            || source.max_artifact_bytes == 0
            || source.max_artifact_bytes > 4 * 1024 * 1024 * 1024
        {
            return Err(UpdateError::Unsupported(
                "некорректная конфигурация продукта/платформы/лимитов",
            ));
        }
        parse_url(&source.manifest_url)?;
        let endpoint = parse_url(&source.descriptor_url.replace("{target}", target))?;
        if endpoint.query().is_some()
            || source
                .descriptor_url
                .replace("{target}", target)
                .contains(['{', '}'])
        {
            return Err(UpdateError::Unsupported(
                "update endpoint должен быть задан явно без query",
            ));
        }
        for origin in &source.allowed_download_origins {
            let url = parse_url(origin)?;
            if url.origin().ascii_serialization() != *origin {
                return Err(UpdateError::Unsupported(
                    "allowed_download_origins содержит не origin",
                ));
            }
        }
        let jwk = &source.public_key;
        if jwk.kty != "OKP" || jwk.crv != "Ed25519" {
            return Err(UpdateError::Trust("ожидается публичный Ed25519 JWK"));
        }
        let raw: [u8; 32] = decode(&jwk.x)?
            .try_into()
            .map_err(|_| UpdateError::Trust("неверный размер публичного ключа"))?;
        let key = VerifyingKey::from_bytes(&raw)
            .map_err(|_| UpdateError::Trust("неверный публичный ключ"))?;
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, jwk.x);
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Ok(Self {
            current: canonical_version(current_version)?,
            target: target.into(),
            metadata_client: client(None, Duration::from_secs(20))?,
            download_client: client(
                Some(source.allowed_download_origins.clone()),
                Duration::from_secs(600),
            )?,
            source,
            key,
            key_id,
        })
    }

    /// RFC 7638 SHA-256 thumbprint of the pinned public key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Apply local HTTPS, credential and origin policy to an artifact URL.
    pub fn artifact_url(&self, value: &str) -> Result<Url> {
        let url = parse_url(value)?;
        if !self
            .source
            .allowed_download_origins
            .contains(&url.origin().ascii_serialization())
        {
            return Err(UpdateError::Trust(
                "origin файла не разрешён локальной конфигурацией",
            ));
        }
        Ok(url)
    }

    /// Verify the signature, product, target, SemVer, limits and URL policy.
    pub fn verify(&self, descriptor: Descriptor) -> Result<VerifiedUpdate> {
        let metadata = self.verify_context(&descriptor.version, &descriptor.signed_metadata)?;
        self.artifact_url(&descriptor.url)?;
        Ok(VerifiedUpdate {
            descriptor,
            metadata,
        })
    }

    pub(crate) fn verify_context(
        &self,
        version_text: &str,
        signed_metadata: &str,
    ) -> Result<SignedMetadata> {
        let compact = signed_metadata;
        if compact.len() > 4096 || !compact.is_ascii() {
            return Err(UpdateError::Trust("неверный размер JWS"));
        }
        let parts: Vec<_> = compact.split('.').collect();
        if parts.len() != 3 {
            return Err(UpdateError::Trust("требуется JWS Compact"));
        }
        let header: Header = serde_json::from_slice(&decode(parts[0])?)
            .map_err(|_| UpdateError::Trust("неверный JWS header"))?;
        if header.alg != "EdDSA"
            || header.typ != "releases-standalone+jws"
            || header.kid.as_ref().is_some_and(|kid| kid != &self.key_id)
        {
            return Err(UpdateError::Trust("JWS algorithm/type/kid не совпадает"));
        }
        let signature = Signature::from_slice(&decode(parts[2])?)
            .map_err(|_| UpdateError::Trust("неверная подпись"))?;
        self.key
            .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .map_err(|_| UpdateError::Trust("неверная Ed25519-подпись"))?;
        let metadata: SignedMetadata = serde_json::from_slice(&decode(parts[1])?)
            .map_err(|_| UpdateError::Trust("неверная схема подписанных метаданных"))?;
        let version = canonical_version(&metadata.version)?;
        if metadata.schema_version != 1 || metadata.application_id != self.source.product_id {
            return Err(UpdateError::Trust("идентичность продукта не совпадает"));
        }
        if format!("{}-{}", metadata.os, metadata.arch) != self.target {
            return Err(UpdateError::Trust(
                "платформа не совпадает с ABI текущей сборки",
            ));
        }
        if metadata.version != version_text
            || !version.pre.is_empty()
            || !version.cmp_precedence(&self.current).is_gt()
        {
            return Err(UpdateError::Trust(
                "версия не является строго более новым стабильным выпуском",
            ));
        }
        if metadata.size_bytes == 0
            || metadata.size_bytes > self.source.max_artifact_bytes
            || metadata.sha256.len() != 64
            || !metadata
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(UpdateError::Trust("неверный размер или SHA-256"));
        }
        Ok(metadata)
    }

    async fn descriptor(&self) -> Result<Option<VerifiedUpdate>> {
        let mut url = parse_url(&self.source.descriptor_url.replace("{target}", &self.target))?;
        url.query_pairs_mut()
            .append_pair("current_version", &self.current.to_string());
        let response = self
            .metadata_client
            .get(url)
            .header("Accept", "application/json")
            .header("Cache-Control", "no-cache")
            .send()
            .await
            .map_err(|_| UpdateError::Unavailable)?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::OK => {
                let bytes = bounded_body(response, DOCUMENT_LIMIT).await?;
                // A missing signature is a trust failure, not an unsigned install candidate.
                let descriptor: Descriptor = serde_json::from_slice(&bytes).map_err(|_| {
                    match serde_json::from_slice::<serde_json::Value>(&bytes) {
                        Ok(v) if v.get("signed_metadata").and_then(|v| v.as_str()).is_none() => {
                            UpdateError::Trust("подписанные метаданные отсутствуют")
                        }
                        _ => UpdateError::Document,
                    }
                })?;
                self.verify(descriptor).map(Some)
            }
            status => Err(UpdateError::Http(status.as_u16())),
        }
    }

    async fn manifest(&self) -> Result<Manifest> {
        let response = self
            .metadata_client
            .get(&self.source.manifest_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| UpdateError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(UpdateError::Http(response.status().as_u16()));
        }
        let manifest: Manifest =
            serde_json::from_slice(&bounded_body(response, MANIFEST_LIMIT).await?)
                .map_err(|_| UpdateError::Document)?;
        if manifest.schema_version != 2 {
            return Err(UpdateError::Document);
        }
        Ok(manifest)
    }

    /// Check descriptor and manifest. Manifest failures cannot authorize installation.
    pub async fn check(&self) -> Result<CheckResult> {
        let (signed, manifest) = tokio::join!(self.descriptor(), self.manifest());
        let update = signed?;
        let mut result = CheckResult {
            update,
            manual: None,
            notes: String::new(),
            manifest_unavailable: manifest.is_err(),
        };
        if let Ok(manifest) = manifest {
            let mut releases = manifest.releases;
            if let Some(release) = manifest
                .latest_by_type
                .get("executable")
                .and_then(|targets| targets.get(&self.target))
            {
                releases.push(release.clone());
            }
            for release in releases {
                let Ok(version) = canonical_version(&release.version) else {
                    continue;
                };
                if !version.pre.is_empty() || !version.cmp_precedence(&self.current).is_gt() {
                    continue;
                }
                if result
                    .update
                    .as_ref()
                    .is_some_and(|u| u.metadata.version == release.version)
                {
                    result.notes = release.notes.chars().take(4_000).collect();
                }
                if result.manual.as_ref().is_some_and(|r| {
                    canonical_version(&r.version).is_ok_and(|v| !version.cmp_precedence(&v).is_gt())
                }) {
                    continue;
                }
                if let Some(artifact) = release.artifacts.iter().find(|a| {
                    a.target == self.target
                        && a.purpose == "executable"
                        && self.artifact_url(&a.download_url).is_ok()
                }) {
                    result.manual = Some(ManualRelease {
                        version: release.version,
                        notes: release.notes.chars().take(4_000).collect(),
                        download_url: artifact.download_url.clone(),
                    });
                }
            }
        }
        Ok(result)
    }

    /// Stream to a caller-owned writable regular file; verify size, hash and Linux ELF.
    /// The caller owns the destination and must provide an isolated file; this method
    /// writes to it. Errors leave an untrusted partial file for the caller to remove.
    pub async fn download(
        &self,
        update: &VerifiedUpdate,
        file: std::fs::File,
        mut progress: impl FnMut(DownloadEvent) -> Result<()>,
    ) -> Result<std::fs::File> {
        // A verified candidate from a different client is not trusted by this source.
        let checked = self.verify(update.descriptor.clone())?;
        let expected = &checked.metadata;
        if !file.metadata()?.is_file() || file.metadata()?.len() > expected.size_bytes {
            return Err(UpdateError::Integrity(
                "download destination is not a bounded regular file",
            ));
        }
        use std::io::{Seek, SeekFrom};
        let mut file = file;
        file.seek(SeekFrom::Start(0))?;
        let mut response = self
            .download_client
            .get(self.artifact_url(&update.descriptor.url)?)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|_| UpdateError::Unavailable)?;
        if response.status() != StatusCode::OK {
            return Err(UpdateError::Http(response.status().as_u16()));
        }
        if response
            .content_length()
            .is_some_and(|n| n != expected.size_bytes)
        {
            return Err(UpdateError::Integrity(
                "Content-Length не совпадает с подписанным размером",
            ));
        }
        let mut file = tokio::fs::File::from_std(file);
        let mut hash = Sha256::new();
        let mut downloaded = 0_u64;
        progress(DownloadEvent::Progress {
            downloaded,
            total: expected.size_bytes,
        })?;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| UpdateError::Unavailable)?
        {
            downloaded = downloaded
                .checked_add(chunk.len() as u64)
                .ok_or(UpdateError::Integrity("размер файла превышен"))?;
            if downloaded > expected.size_bytes {
                return Err(UpdateError::Integrity("размер файла превышен"));
            }
            file.write_all(&chunk).await?;
            hash.update(&chunk);
            progress(DownloadEvent::Progress {
                downloaded,
                total: expected.size_bytes,
            })?;
        }
        progress(DownloadEvent::Verifying)?;
        if downloaded != expected.size_bytes {
            return Err(UpdateError::Integrity("файл усечён"));
        }
        if crate::hex(&hash.finalize()) != expected.sha256 {
            return Err(UpdateError::Integrity("SHA-256 не совпадает"));
        }
        file.flush().await?;
        file.sync_all().await?;
        let mut file = file.into_std().await;
        if self.target.starts_with("linux-") {
            artifact::verify_elf(&mut file, &self.target, expected.size_bytes)?;
        }
        Ok(file)
    }
}

#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    #[serde(default)]
    releases: Vec<ManifestRelease>,
    #[serde(default)]
    latest_by_type: BTreeMap<String, BTreeMap<String, ManifestRelease>>,
}
#[derive(Clone, Deserialize)]
struct ManifestRelease {
    version: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    artifacts: Vec<ManifestArtifact>,
}
#[derive(Clone, Deserialize)]
struct ManifestArtifact {
    target: String,
    purpose: String,
    download_url: String,
}
