//! Result delivery.
//!
//! Reporting is optional: the run result is always persisted first, and this
//! module only concerns pushing that final result to an external callback.

use async_trait::async_trait;
use thiserror::Error;

use crate::model::HarnessResult;

pub mod github;
pub mod webhook;

pub use github::{GithubPrCommentReporter, markdown_comment};
pub use webhook::{WebhookResultReporter, signature};

/// Successful delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportOutcome {
    pub attempts: u8,
    pub http_status: Option<u16>,
}

/// Failure returned after all delivery attempts are exhausted.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("result delivery failed after {attempts} attempt(s): {message}")]
pub struct ReporterError {
    pub attempts: u8,
    pub http_status: Option<u16>,
    pub message: String,
}

/// Pushes a completed harness result to an external sink.
#[async_trait]
pub trait ResultReporter: Send + Sync {
    /// Delivers one final result.
    async fn report(&self, result: &HarnessResult) -> Result<ReportOutcome, ReporterError>;
}
