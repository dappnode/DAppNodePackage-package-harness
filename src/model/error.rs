use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    CandidateContainersStable,
    CandidateContainersUnstable,
    CandidateInstallFailed,
    BaselineContainersUnstable,
    BaselineInstallFailed,
    BaselineUnavailable,
    UnsupportedRequiredSetup,
    CorePackageRefused,
    HarnessPackageRefused,
    CleanupFailed,
    McpUnavailable,
    RequiredMcpToolsMissing,
    PersistenceFailed,
    InterruptedOnRestart,
    CancellationRequested,
    ClaimLost,
    UnexpectedError,
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("invalid {field}: {message}")]
    Validation {
        field: &'static str,
        message: String,
    },
    #[error("run ID already exists with a different request")]
    RunConflict,
    #[error("run was not found")]
    NotFound,
    #[error("target package is the harness package")]
    HarnessPackage,
    #[error("core packages cannot be tested")]
    CorePackage,
}
