use std::{fs, io::Write, path::PathBuf};

use async_trait::async_trait;

use crate::model::{RunId, RunRecord};

use super::{RunStore, StoreError};

#[derive(Debug, Clone)]
pub struct FileRunStore {
    root: PathBuf,
}

impl FileRunStore {
    pub async fn new(root: PathBuf) -> Result<Self, StoreError> {
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|error| StoreError::Io(error.to_string()))?;
        Ok(Self { root })
    }

    fn path(&self, run_id: &RunId) -> PathBuf {
        self.root.join(format!("{}.json", run_id.as_str()))
    }

    async fn atomic_write(&self, record: &RunRecord, create_only: bool) -> Result<(), StoreError> {
        let root = self.root.clone();
        let destination = self.path(&record.request.run_id);
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let mut temporary = tempfile::NamedTempFile::new_in(&root)
                .map_err(|error| StoreError::Io(error.to_string()))?;
            temporary
                .write_all(&bytes)
                .and_then(|()| temporary.as_file().sync_all())
                .map_err(|error| StoreError::Io(error.to_string()))?;
            let persisted = if create_only {
                temporary.persist_noclobber(destination)
            } else {
                temporary.persist(destination)
            };
            persisted.map_err(|error| {
                if create_only && error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists
                } else {
                    StoreError::Io(error.error.to_string())
                }
            })?;
            Ok(())
        })
        .await
        .map_err(|error| StoreError::Io(error.to_string()))?
    }
}

#[async_trait]
impl RunStore for FileRunStore {
    async fn create(&self, record: &RunRecord) -> Result<(), StoreError> {
        self.atomic_write(record, true).await
    }

    async fn save(&self, record: &RunRecord) -> Result<(), StoreError> {
        self.atomic_write(record, false).await
    }

    async fn get(&self, run_id: &RunId) -> Result<Option<RunRecord>, StoreError> {
        match tokio::fs::read(self.path(run_id)).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|error| StoreError::Invalid(error.to_string())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error.to_string())),
        }
    }

    async fn load_all(&self) -> Result<Vec<RunRecord>, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let entries = fs::read_dir(root).map_err(|error| StoreError::Io(error.to_string()))?;
            let mut records = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| StoreError::Io(error.to_string()))?;
                if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let bytes =
                    fs::read(entry.path()).map_err(|error| StoreError::Io(error.to_string()))?;
                let record = serde_json::from_slice(&bytes)
                    .map_err(|error| StoreError::Invalid(error.to_string()))?;
                records.push(record);
            }
            records.sort_by_key(|record: &RunRecord| record.created_at);
            Ok(records)
        })
        .await
        .map_err(|error| StoreError::Io(error.to_string()))?
    }
}
