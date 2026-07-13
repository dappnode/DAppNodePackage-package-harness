//! Run persistence.
//!
//! The runner writes after each phase transition so a restart can report
//! interrupted runs instead of silently losing in-flight state.

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{RunId, RunRecord};

pub mod file;

pub use file::FileRunStore;

/// Persistence error for run records.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("run already exists")]
    AlreadyExists,
    #[error("I/O error while persisting run: {0}")]
    Io(String),
    #[error("invalid persisted run: {0}")]
    Invalid(String),
}

/// Storage used by the API and runner for durable run records.
#[async_trait]
pub trait RunStore: Send + Sync {
    /// Creates a new run record and fails if the run id already exists.
    async fn create(&self, record: &RunRecord) -> Result<(), StoreError>;

    /// Replaces an existing run record with its latest state.
    async fn save(&self, record: &RunRecord) -> Result<(), StoreError>;

    /// Loads one run by id.
    async fn get(&self, run_id: &RunId) -> Result<Option<RunRecord>, StoreError>;

    /// Loads all known runs, used on startup to mark active records interrupted.
    async fn load_all(&self) -> Result<Vec<RunRecord>, StoreError>;
}
