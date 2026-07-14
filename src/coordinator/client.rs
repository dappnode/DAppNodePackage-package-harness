use std::time::Duration;

use futures_util::StreamExt;
use reqwest::{Client, StatusCode, Url, header};
use thiserror::Error;

use crate::analysis::redaction::redact_and_bound;

use super::protocol::{
    ClaimRequest, ClaimResponse, ClaimedJob, CompletionResponse, HeartbeatRequest,
    HeartbeatResponse,
};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const ERROR_PREVIEW_BYTES: usize = 500;

/// Outcome of a successful claim request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    NoWork,
    Claimed(ClaimedJob),
}

/// Result of one heartbeat request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatOutcome {
    Continue,
    CancelRequested,
    ClaimLost,
}

/// Acknowledged completion disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionDisposition {
    Recorded,
    Duplicate,
}

/// Bounded, protocol-aware HTTP failures.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("coordinator authentication was rejected ({status})")]
    Authentication { status: StatusCode },
    #[error("coordinator reports this worker already has an unresolved job")]
    UnresolvedJob,
    #[error("coordinator no longer recognizes the current claim ({status})")]
    ClaimLost { status: StatusCode },
    #[error("coordinator rejected completion ({status}): {message}")]
    CompletionConflict { status: StatusCode, message: String },
    #[error("transient coordinator failure: {message}")]
    Transient { message: String },
    #[error("coordinator rejected request ({status}): {message}")]
    Rejected { status: StatusCode, message: String },
    #[error("invalid coordinator protocol: {0}")]
    Protocol(String),
    #[error("invalid coordinator URL: {0}")]
    Url(String),
}

impl CoordinatorError {
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Transient { .. })
    }
}

/// Small typed client for Tropibot's package-harness worker protocol.
#[derive(Clone)]
pub struct CoordinatorClient {
    client: Client,
    base_url: Url,
    worker_id: String,
    token: String,
    user_agent: String,
}

impl CoordinatorClient {
    pub fn new(
        base_url: &str,
        worker_id: String,
        token: String,
        timeout: Duration,
    ) -> Result<Self, CoordinatorError> {
        crate::tls::ensure_crypto_provider();
        let mut base_url =
            Url::parse(base_url).map_err(|error| CoordinatorError::Url(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(CoordinatorError::Url(
                "URL scheme must be http or https".to_owned(),
            ));
        }
        if base_url.host_str().is_none() {
            return Err(CoordinatorError::Url("URL must contain a host".to_owned()));
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let client = Client::builder()
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .timeout(timeout)
            .build()
            .map_err(|error| CoordinatorError::Protocol(error.to_string()))?;
        Ok(Self {
            client,
            base_url,
            worker_id,
            token,
            user_agent: format!("dappnode-package-harness/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    pub async fn claim(&self) -> Result<ClaimOutcome, CoordinatorError> {
        let body = serde_json::to_vec(&ClaimRequest {
            schema_version: 1,
            worker_id: &self.worker_id,
        })
        .map_err(|error| CoordinatorError::Protocol(error.to_string()))?;
        let (status, body) = self.request("v1/package-harness/jobs/claim", body).await?;
        match status {
            StatusCode::NO_CONTENT => Ok(ClaimOutcome::NoWork),
            StatusCode::OK => serde_json::from_slice::<ClaimResponse>(&body)
                .map_err(|error| CoordinatorError::Protocol(error.to_string()))
                .and_then(|response| {
                    ClaimedJob::try_from(response).map_err(CoordinatorError::Protocol)
                })
                .map(ClaimOutcome::Claimed),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(CoordinatorError::Authentication { status })
            }
            StatusCode::CONFLICT => Err(CoordinatorError::UnresolvedJob),
            status if transient_status(status) => Err(CoordinatorError::Transient {
                message: status_message(status, &body),
            }),
            _ => Err(CoordinatorError::Rejected {
                status,
                message: status_message(status, &body),
            }),
        }
    }

    pub async fn heartbeat(
        &self,
        job_id: &str,
        claim_token: &str,
        phase: &str,
        cleanup_required: bool,
    ) -> Result<HeartbeatOutcome, CoordinatorError> {
        let body = serde_json::to_vec(&HeartbeatRequest {
            schema_version: 1,
            worker_id: &self.worker_id,
            claim_token,
            phase,
            cleanup_required,
        })
        .map_err(|error| CoordinatorError::Protocol(error.to_string()))?;
        let (status, body) = self
            .request(&format!("v1/package-harness/jobs/{job_id}/heartbeat"), body)
            .await?;
        match status {
            StatusCode::OK => {
                let response: HeartbeatResponse = serde_json::from_slice(&body)
                    .map_err(|error| CoordinatorError::Protocol(error.to_string()))?;
                if response.schema_version != 1 {
                    return Err(CoordinatorError::Protocol(
                        "heartbeat schemaVersion must be 1".to_owned(),
                    ));
                }
                Ok(if response.cancel_requested {
                    HeartbeatOutcome::CancelRequested
                } else {
                    HeartbeatOutcome::Continue
                })
            }
            StatusCode::NOT_FOUND | StatusCode::CONFLICT => Ok(HeartbeatOutcome::ClaimLost),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(CoordinatorError::Authentication { status })
            }
            status if transient_status(status) => Err(CoordinatorError::Transient {
                message: status_message(status, &body),
            }),
            _ => Err(CoordinatorError::Rejected {
                status,
                message: status_message(status, &body),
            }),
        }
    }

    /// Sends already-persisted JSON without reserializing it.
    pub async fn complete_raw(
        &self,
        job_id: &str,
        body: Vec<u8>,
    ) -> Result<CompletionDisposition, CoordinatorError> {
        let (status, response_body) = self
            .request(&format!("v1/package-harness/jobs/{job_id}/complete"), body)
            .await?;
        match status {
            StatusCode::OK => {
                let disposition = serde_json::from_slice::<CompletionResponse>(&response_body)
                    .map_err(|error| CoordinatorError::Protocol(error.to_string()))?
                    .validate()
                    .map_err(CoordinatorError::Protocol)?;
                Ok(match disposition.as_str() {
                    "recorded" => CompletionDisposition::Recorded,
                    "duplicate" => CompletionDisposition::Duplicate,
                    _ => {
                        return Err(CoordinatorError::Protocol(
                            "unreachable disposition".to_owned(),
                        ));
                    }
                })
            }
            StatusCode::CONFLICT => Err(CoordinatorError::CompletionConflict {
                status,
                message: status_message(status, &response_body),
            }),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                Err(CoordinatorError::Authentication { status })
            }
            status if transient_status(status) => Err(CoordinatorError::Transient {
                message: status_message(status, &response_body),
            }),
            _ => Err(CoordinatorError::Rejected {
                status,
                message: status_message(status, &response_body),
            }),
        }
    }

    async fn request(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<(StatusCode, Vec<u8>), CoordinatorError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|error| CoordinatorError::Url(error.to_string()))?;
        let response = self
            .client
            .post(url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::USER_AGENT, &self.user_agent)
            .body(body)
            .send()
            .await
            .map_err(|error| CoordinatorError::Transient {
                message: redact_and_bound(&error.to_string(), ERROR_PREVIEW_BYTES),
            })?;
        let status = response.status();
        let body = response_bytes(response).await?;
        Ok((status, body))
    }
}

async fn response_bytes(response: reqwest::Response) -> Result<Vec<u8>, CoordinatorError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(CoordinatorError::Protocol(format!(
            "coordinator response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| CoordinatorError::Transient {
            message: redact_and_bound(&error.to_string(), ERROR_PREVIEW_BYTES),
        })?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(CoordinatorError::Protocol(format!(
                "coordinator response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn transient_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

fn status_message(status: StatusCode, body: &[u8]) -> String {
    let preview = String::from_utf8_lossy(body);
    let preview = redact_and_bound(&preview, ERROR_PREVIEW_BYTES);
    if preview.is_empty() {
        status.to_string()
    } else {
        format!("{status}: {preview}")
    }
}
