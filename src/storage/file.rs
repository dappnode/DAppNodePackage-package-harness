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
        tokio::fs::create_dir_all(&root).await.map_err(|error| {
            StoreError::Io(format!(
                "cannot create data directory {}: {error}",
                root.display()
            ))
        })?;
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
            let mut temporary = tempfile::NamedTempFile::new_in(&root).map_err(|error| {
                StoreError::Io(format!("cannot create temporary file: {error}"))
            })?;
            temporary
                .write_all(&bytes)
                .and_then(|()| temporary.as_file().sync_all())
                .map_err(|error| StoreError::Io(format!("cannot sync run record: {error}")))?;
            let persisted = if create_only {
                temporary.persist_noclobber(&destination)
            } else {
                temporary.persist(&destination)
            };
            persisted.map_err(|error| {
                if create_only && error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists
                } else {
                    StoreError::Io(format!(
                        "cannot persist {}: {}",
                        destination.display(),
                        error.error
                    ))
                }
            })?;
            fs::File::open(&root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| StoreError::Io(format!("cannot sync data directory: {error}")))?;
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
        let path = self.path(run_id);
        match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                StoreError::Invalid(format!("invalid run record {}: {error}", path.display()))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(format!(
                "cannot read {}: {error}",
                path.display()
            ))),
        }
    }

    async fn load_all(&self) -> Result<Vec<RunRecord>, StoreError> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let entries = fs::read_dir(&root).map_err(|error| {
                StoreError::Io(format!("cannot read {}: {error}", root.display()))
            })?;
            let mut records = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| StoreError::Io(error.to_string()))?;
                if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let path = entry.path();
                let bytes = fs::read(&path).map_err(|error| {
                    StoreError::Io(format!("cannot read {}: {error}", path.display()))
                })?;
                let record = serde_json::from_slice(&bytes).map_err(|error| {
                    StoreError::Invalid(format!("invalid run record {}: {error}", path.display()))
                })?;
                records.push(record);
            }
            records.sort_by_key(|record: &RunRecord| record.created_at);
            Ok(records)
        })
        .await
        .map_err(|error| StoreError::Io(error.to_string()))?
    }
}
