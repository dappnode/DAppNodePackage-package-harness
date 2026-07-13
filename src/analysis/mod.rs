//! Log analysis implementations.
//!
//! The harness always has a deterministic heuristic analyzer available. When a
//! Nexus API key is configured, the composite analyzer can add model-assisted
//! findings while preserving the heuristic result as a fallback component.

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{LogAnalysisInput, LogAnalysisResult};

pub mod heuristic;
pub mod nexus;
pub mod redaction;

pub use heuristic::HeuristicLogAnalyzer;
pub use nexus::{CompositeLogAnalyzer, NexusLogAnalyzer};

/// Failure returned by an analyzer implementation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalyzerError {
    #[error("analyzer timed out")]
    Timeout,
    #[error("analyzer transport failed: {0}")]
    Transport(String),
    #[error("analyzer returned invalid data: {0}")]
    InvalidResponse(String),
}

/// Compares baseline and candidate logs and emits a bounded result.
#[async_trait]
pub trait LogAnalyzer: Send + Sync {
    /// Runs the analyzer against already-redacted log excerpts.
    async fn analyze(&self, input: &LogAnalysisInput) -> Result<LogAnalysisResult, AnalyzerError>;
}
