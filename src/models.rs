use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// A pinned public Ed25519 JWK. Private and unknown fields are rejected.
pub struct PublicKey {
    /// JWK key type; must be `OKP`.
    pub kty: String,
    /// JWK curve; must be `Ed25519`.
    pub crv: String,
    /// Canonical unpadded base64url encoding of 32 public-key bytes.
    pub x: String,
}

/// Trust anchors, manifest URL and download policy supplied by the application.
/// Debug output deliberately omits endpoint URLs.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSource {
    /// Permanent canonical publisher UUID.
    pub product_id: String,
    /// Schema-v2 manifest URL, including per-artifact signed metadata for automatic updates.
    pub manifest_url: String,
    /// Optional legacy descriptor endpoint with `{target}` substitution.
    /// An omitted or empty value selects signed artifacts from the manifest.
    #[serde(default)]
    pub descriptor_url: String,
    /// Pinned public key; keys returned by a server are never adopted.
    pub public_key: PublicKey,
    /// Exact allowed artifact origins, including ports. No paths or trailing slash.
    pub allowed_download_origins: Vec<String>,
    /// Positive local artifact size limit, at most 4 GiB.
    pub max_artifact_bytes: u64,
}

impl UpdateSource {
    /// Configure a channel with one manifest URL and the application's pinned trust and limits.
    pub fn from_manifest(
        manifest_url: impl Into<String>,
        product_id: impl Into<String>,
        public_key: PublicKey,
        allowed_download_origins: Vec<String>,
        max_artifact_bytes: u64,
    ) -> Self {
        Self {
            manifest_url: manifest_url.into(),
            descriptor_url: String::new(),
            product_id: product_id.into(),
            public_key,
            allowed_download_origins,
            max_artifact_bytes,
        }
    }
}

/// Untrusted protocol v1 descriptor. Never persist its potentially signed URL.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Exact version declared by the untrusted transport.
    pub version: String,
    /// Opaque artifact URL, checked against local policy.
    pub url: String,
    /// JWS Compact string, at most 4096 ASCII bytes.
    pub signed_metadata: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// The complete signed protocol v1 context, after strict JSON decoding.
pub struct SignedMetadata {
    /// Protocol schema; exactly 1.
    pub schema_version: u32,
    /// Publisher product UUID, despite the historical field name.
    pub application_id: String,
    /// Canonical stable SemVer, including build metadata.
    pub version: String,
    /// Protocol operating system name.
    pub os: String,
    /// Protocol architecture name.
    pub arch: String,
    /// Exact positive signed file length in bytes.
    pub size_bytes: u64,
    /// Lowercase hexadecimal SHA-256 of the complete artifact.
    pub sha256: String,
}

/// Construction is restricted to successful signature verification. Persisted jobs must be
/// reverified from their original descriptor, never deserialized as a trusted candidate.
#[derive(Clone, Debug)]
pub struct VerifiedUpdate {
    pub(super) descriptor: Descriptor,
    pub(super) metadata: SignedMetadata,
}
impl VerifiedUpdate {
    /// Original descriptor; its URL may contain a transport token.
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    /// Complete verified signed context.
    pub fn metadata(&self) -> &SignedMetadata {
        &self.metadata
    }
}

#[derive(Clone, Serialize, Deserialize)]
/// A manual-download hint; never sufficient to authorize installation.
pub struct ManualRelease {
    /// Untrusted manifest version, newer by SemVer precedence.
    pub version: String,
    /// Untrusted release notes, truncated to 4000 characters.
    pub notes: String,
    /// Untrusted manual link passing local origin policy. It is never an install candidate.
    pub download_url: String,
}

#[derive(Clone, Debug)]
/// Verified candidate and optional untrusted manual-release hints.
pub struct CheckResult {
    /// A candidate whose signature and complete context were verified.
    pub update: Option<VerifiedUpdate>,
    /// Optional untrusted manifest hint for manual download only.
    pub manual: Option<ManualRelease>,
    /// Untrusted notes for the signed candidate, bounded to 4000 characters.
    pub notes: String,
    /// The supplementary manifest could not be read in legacy descriptor mode.
    pub manifest_unavailable: bool,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Outcome of a check, distinct from the installation lifecycle.
pub enum CheckOutcome {
    #[default]
    /// No check has completed.
    NotChecked,
    /// No newer signed release.
    NoUpdate,
    /// A newer signed candidate is available.
    Available,
    /// Source or response unavailable.
    Unavailable,
    /// Signature, identity or artifact-integrity failure.
    TrustError,
    /// Local policy or platform prevents the operation.
    Unsupported,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// Durable operation stages shared by polling/SSE adapters.
pub enum Stage {
    #[default]
    /// No active operation.
    Idle,
    /// Fetching or rechecking metadata.
    Checking,
    /// A newer signed candidate is available.
    Available,
    /// Streaming the signed artifact.
    Downloading,
    /// Verifying final bytes.
    Verifying,
    /// Downloaded and preflighted; awaiting installation.
    Prepared,
    /// Application graceful shutdown requested.
    Stopping,
    /// Durable intent saved before atomic replacement.
    Switching,
    /// Starting the new binary.
    Starting,
    /// Checking application readiness and instance nonce.
    HealthCheck,
    /// New binary passed readiness.
    Completed,
    /// Stopping a failed child and restoring the old binary.
    RollingBack,
    /// Previous binary restored.
    RolledBack,
    /// Operation failed; inspect recovery_required.
    Failed,
}
impl Stage {
    /// Whether the stage owns an unfinished operation.
    pub fn busy(self) -> bool {
        !matches!(
            self,
            Self::Idle | Self::Available | Self::Completed | Self::RolledBack | Self::Failed
        )
    }
    /// Whether binary replacement may have happened before an interruption.
    pub fn may_have_switched(self) -> bool {
        matches!(
            self,
            Self::Switching | Self::Starting | Self::HealthCheck | Self::RollingBack
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Redacted release description safe to retain with operation state.
pub struct ReleaseInfo {
    /// Exact selected stable version.
    pub version: String,
    /// Signed expected artifact length.
    pub size_bytes: u64,
    /// Signed expected SHA-256.
    pub sha256: String,
    /// Untrusted manifest text; render as text, not HTML.
    pub notes: String,
    /// Metadata signature verified; this says nothing about downloaded bytes yet.
    pub signature_verified: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
/// Redacted, serializable progress snapshot retained across restarts.
pub struct OperationStatus {
    /// Locally generated operation identifier.
    pub operation_id: Option<String>,
    /// Current durable lifecycle stage.
    pub state: Stage,
    /// Independent outcome of the last check.
    pub check_outcome: CheckOutcome,
    /// Last check time as Unix seconds.
    pub last_checked: Option<u64>,
    /// Snapshot update time as Unix seconds.
    pub updated_at: u64,
    /// Redacted description of the selected signed release.
    pub available: Option<ReleaseInfo>,
    /// Manifest hint without a potentially sensitive download URL.
    pub manual_release: Option<ManualReleaseInfo>,
    /// Actual streamed bytes received, not an estimated installation percentage.
    pub downloaded_bytes: u64,
    /// Signed artifact length when known.
    pub total_bytes: Option<u64>,
    /// Bounded local diagnostic message, never a raw remote error.
    pub message: String,
    /// Installation is blocked until the interrupted switch is reviewed/recovered.
    pub recovery_required: bool,
    /// PID plus Linux start time of the operation owner.
    pub worker: Option<ProcessIdentity>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// A process identity bound to its kernel start time.
pub struct ProcessIdentity {
    /// Linux process ID.
    pub pid: u32,
    /// Linux `/proc/PID/stat` start time; prevents PID-reuse confusion.
    pub start_ticks: u64,
}

/// Persistent manifest hints; download URLs are intentionally excluded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManualReleaseInfo {
    /// Untrusted release version.
    pub version: String,
    /// Untrusted bounded notes; no artifact URL is persisted.
    pub notes: String,
}
impl std::fmt::Debug for UpdateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateSource")
            .field("product_id", &self.product_id)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Descriptor")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ManualRelease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualRelease")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}
