//! Optional redacted check cache. It is never an installation/recovery journal.
use crate::local_state::PrivateDirectory;
use crate::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Identity {
    pub product_id: String,
    pub current_version: String,
    pub target: String,
    pub key_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cached {
    schema_version: u32,
    identity: Identity,
    status: StoredCheck,
}
#[derive(Clone)]
pub(crate) struct Cache {
    directory: PrivateDirectory,
    identity: Identity,
    source_id: String,
}
impl Cache {
    pub fn open(directory: &Path, identity: Identity, source_id: String) -> Result<Self> {
        Ok(Self {
            directory: PrivateDirectory::open(directory)?,
            identity,
            source_id,
        })
    }
    pub fn load(&self) -> Result<OperationStatus> {
        let Some(cached) = self.directory.read::<Cached>("checks.json")? else {
            return Ok(OperationStatus::default());
        };
        if cached.schema_version != 2
            || cached.identity != self.identity
            || cached.status.check_source_id != self.source_id
        {
            return Ok(OperationStatus::default());
        }
        let mut status = cached.status.status;
        // A check cache must never import an installation stage or recovery job.
        if !matches!(
            status.state,
            Stage::Idle | Stage::Checking | Stage::Available | Stage::Failed
        ) || status.recovery_required
            || status.worker.is_some()
        {
            return Err(UpdateError::Document);
        }
        if status.state == Stage::Checking {
            status.state = Stage::Failed;
            status.message = "Проверка прервана; выполните её повторно".into();
        }
        Ok(status)
    }
    pub fn save(&self, status: &OperationStatus) -> Result<()> {
        self.directory.write(
            "checks.json",
            &Cached {
                schema_version: 2,
                identity: self.identity.clone(),
                status: StoredCheck::new(status, &self.source_id),
            },
        )
    }
}
