use serde::{Deserialize, Serialize};

use crate::model::{
    CleanupStatus, HarnessResult, PackageRequestDto, RunRequest, RunRequestDto, SourceDto,
    WorkerError, WorkerErrorCode,
};

/// Request body for atomically claiming one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimRequest<'a> {
    pub schema_version: u8,
    pub worker_id: &'a str,
}

/// Validated claim retained by the local worker record before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedJob {
    pub request: RunRequest,
    pub claim_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimResponse {
    pub schema_version: u8,
    pub job_id: String,
    pub claim_token: String,
    pub source: SourceDto,
    pub package: PackageRequestDto,
}

impl TryFrom<ClaimResponse> for ClaimedJob {
    type Error = String;

    fn try_from(response: ClaimResponse) -> Result<Self, Self::Error> {
        if response.schema_version != 1 {
            return Err("claim schemaVersion must be 1".to_owned());
        }
        if response.claim_token.is_empty()
            || response.claim_token.len() > 4_096
            || response.claim_token.chars().any(char::is_whitespace)
        {
            return Err("claimToken must be a non-empty opaque token up to 4096 bytes".to_owned());
        }
        let request = RunRequest::try_from(RunRequestDto {
            schema_version: response.schema_version,
            run_id: response.job_id,
            source: response.source,
            package: response.package,
        })
        .map_err(|error| error.to_string())?;
        Ok(Self {
            request,
            claim_token: response.claim_token,
        })
    }
}

/// Periodic state sent while a claimed job is executing or cleaning up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest<'a> {
    pub schema_version: u8,
    pub worker_id: &'a str,
    pub claim_token: &'a str,
    pub phase: &'a str,
    pub cleanup_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeartbeatResponse {
    pub schema_version: u8,
    pub cancel_requested: bool,
}

/// Completion payload. Its serialized form is persisted exactly before the
/// first network attempt and reused verbatim for all retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteRequest {
    pub schema_version: u8,
    pub worker_id: String,
    pub claim_token: String,
    pub outcome: CompletionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CompletionOutcome {
    Result { result: Box<HarnessResult> },
    WorkerError(WorkerErrorCompletion),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerErrorCompletion {
    pub code: WorkerErrorCode,
    pub summary: String,
    pub cleanup_status: CleanupStatus,
}

impl From<&WorkerError> for WorkerErrorCompletion {
    fn from(error: &WorkerError) -> Self {
        Self {
            code: error.code,
            summary: error.summary.clone(),
            cleanup_status: error.cleanup_status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletionResponse {
    pub schema_version: u8,
    pub disposition: String,
}

impl CompletionResponse {
    pub fn validate(self) -> Result<String, String> {
        if self.schema_version != 1 {
            return Err("completion schemaVersion must be 1".to_owned());
        }
        match self.disposition.as_str() {
            "recorded" | "duplicate" => Ok(self.disposition),
            value => Err(format!("unknown completion disposition '{value}'")),
        }
    }
}
