use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::{
    analysis::redaction::truncate_utf8,
    config::Config,
    coordinator::{CoordinatorClient, CoordinatorError},
    model::{
        CaptureEvidence, CleanupStatus, ComparisonEvidence, ContainerSnapshot, ExecutionPhase,
        ExecutionStatus, LogAnalysisResult, ManualRecoveryKind, PackageSummary, PhaseTransition,
        PreviewSummary, ReasonCode, RunError, RunId, RunRecord, StabilizationResult, StepStatus,
        TargetRecoveryPlan, Verdict, WorkerError,
    },
    package_manager::PackageManager,
    storage::RunStore,
    worker::{WorkerDrainControl, WorkerDrainState, WorkerReadiness, WorkerRecoveryControl},
};

/// State for local process supervision and explicit operator recovery.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub package_manager: Arc<dyn PackageManager>,
    pub store: Arc<dyn RunStore>,
    pub coordinator: CoordinatorClient,
    pub worker_readiness: WorkerReadiness,
    pub worker_recovery_control: WorkerRecoveryControl,
    pub worker_drain_control: WorkerDrainControl,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard.css", get(dashboard_css))
        .route("/dashboard.js", get(dashboard_js))
        .route("/api/jobs", get(jobs))
        .route("/api/coordinator/lost-job", get(coordinator_lost_job))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/operator/recovery/continue", post(continue_recovery))
        .route("/operator/recovery/action", post(recovery_action))
        .route("/operator/coordinator/ready", post(coordinator_ready))
        .route("/operator/worker/drain", post(worker_drain))
        .route("/operator/worker/resume", post(worker_resume))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn dashboard() -> impl IntoResponse {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; img-src 'self'; script-src 'self'; style-src 'self'",
            ),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        Html(include_str!("dashboard/index.html")),
    )
}

async fn dashboard_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("dashboard/dashboard.css"),
    )
}

async fn dashboard_js() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-store"),
        ],
        include_str!("dashboard/dashboard.js"),
    )
}

#[derive(Serialize)]
struct HealthResponse<'a> {
    status: &'a str,
}

async fn health() -> Json<HealthResponse<'static>> {
    Json(HealthResponse { status: "ok" })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: &'static str,
    message: String,
}

async fn ready(State(state): State<ApiState>) -> Response {
    if let Some(message) = state.config.acceptance_error() {
        return not_ready(message);
    }
    if let Some(message) = state.worker_readiness.reason() {
        return not_ready(message);
    }
    match state.worker_drain_control.state() {
        WorkerDrainState::Accepting => {}
        WorkerDrainState::Draining => return not_ready("worker is draining".to_owned()),
        WorkerDrainState::Drained => {
            return not_ready("worker is drained and safe to restart".to_owned());
        }
    }
    match state.package_manager.verify_tools().await {
        Ok(tools) if tools.ready() => Json(ReadyResponse {
            status: "ready",
            message: tools.message(),
        })
        .into_response(),
        Ok(tools) => not_ready(tools.message()),
        Err(error) => not_ready(truncate_utf8(&error.to_string(), 500)),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobsResponse {
    worker: WorkerSummary,
    jobs: Vec<JobSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerSummary {
    status: &'static str,
    message: String,
    lifecycle: &'static str,
    safe_to_restart: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobSummary {
    run_id: String,
    dnp_name: String,
    repository: String,
    pull_request: u64,
    head_sha: String,
    candidate_ref: String,
    baseline_ref: Option<String>,
    status: ExecutionStatus,
    phase: ExecutionPhase,
    verdict: Option<Verdict>,
    reason_code: Option<ReasonCode>,
    summary: Option<String>,
    cleanup_status: CleanupStatus,
    cleanup_error: Option<String>,
    leftover_packages: Vec<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    error_count: usize,
    requires_attention: bool,
    manual_recovery_reason: Option<String>,
    recovery_kind: Option<&'static str>,
    can_continue_after_cleanup: bool,
    pending_completion: bool,
    has_claim: bool,
    completion_acknowledged: bool,
    completion_disposition: Option<String>,
    diagnostics: ExpertDiagnostics,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpertDiagnostics {
    phase_history: Vec<PhaseTransition>,
    errors: Vec<RunError>,
    worker_error: Option<WorkerError>,
    cleanup_required: bool,
    blocks_worker: bool,
    target_recovery: Option<TargetRecoveryPlan>,
    initial_packages: Vec<PackageSummary>,
    final_packages: Vec<PackageSummary>,
    baseline: Option<CaptureDiagnostics>,
    candidate: Option<CaptureDiagnostics>,
    comparison: Option<ComparisonEvidence>,
    log_analysis: Option<LogAnalysisResult>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureDiagnostics {
    install_status: StepStatus,
    install_duration_ms: u64,
    preview: Option<PreviewSummary>,
    containers: Vec<ContainerSnapshot>,
    stabilization: StabilizationResult,
    log_entry_count: usize,
    log_error: Option<String>,
    started_at: String,
    finished_at: String,
}

async fn jobs(State(state): State<ApiState>) -> Response {
    let mut records = match state.store.load_all().await {
        Ok(records) => records,
        Err(error) => {
            return operator_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cannot load job records: {error}"),
            );
        }
    };
    records.reverse();
    let drain_state = state.worker_drain_control.state();
    let worker = if let Some(message) = state.config.acceptance_error() {
        WorkerSummary {
            status: "blocked",
            message,
            lifecycle: drain_state_name(drain_state),
            safe_to_restart: false,
        }
    } else if let Some(message) = state.worker_readiness.reason() {
        WorkerSummary {
            status: "paused",
            message,
            lifecycle: drain_state_name(drain_state),
            safe_to_restart: false,
        }
    } else if drain_state == WorkerDrainState::Draining {
        WorkerSummary {
            status: "draining",
            message: "Finishing the current job before restart".to_owned(),
            lifecycle: "draining",
            safe_to_restart: false,
        }
    } else if drain_state == WorkerDrainState::Drained {
        WorkerSummary {
            status: "drained",
            message: "No job is active; the worker is safe to restart".to_owned(),
            lifecycle: "drained",
            safe_to_restart: true,
        }
    } else {
        WorkerSummary {
            status: "ready",
            message: "Polling Tropibot for package jobs".to_owned(),
            lifecycle: "accepting",
            safe_to_restart: false,
        }
    };
    Json(JobsResponse {
        worker,
        jobs: records.into_iter().map(job_summary).collect(),
    })
    .into_response()
}

fn drain_state_name(state: WorkerDrainState) -> &'static str {
    match state {
        WorkerDrainState::Accepting => "accepting",
        WorkerDrainState::Draining => "draining",
        WorkerDrainState::Drained => "drained",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkerLifecycleResponse {
    lifecycle: &'static str,
    safe_to_restart: bool,
    message: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerLifecycleRequest {}

async fn worker_drain(
    State(state): State<ApiState>,
    Json(_request): Json<WorkerLifecycleRequest>,
) -> Json<WorkerLifecycleResponse> {
    state.worker_drain_control.request_drain();
    let lifecycle = drain_state_name(state.worker_drain_control.state());
    info!(
        event = "operator_worker_drain_requested",
        lifecycle, "Operator requested a safe worker drain"
    );
    Json(WorkerLifecycleResponse {
        lifecycle,
        safe_to_restart: lifecycle == "drained",
        message: "drain requested; active work will finish before restart is safe",
    })
}

async fn worker_resume(
    State(state): State<ApiState>,
    Json(_request): Json<WorkerLifecycleRequest>,
) -> Json<WorkerLifecycleResponse> {
    state.worker_drain_control.resume();
    info!(
        event = "operator_worker_resume_requested",
        "Operator resumed worker polling"
    );
    Json(WorkerLifecycleResponse {
        lifecycle: "accepting",
        safe_to_restart: false,
        message: "worker resumed accepting package jobs",
    })
}

async fn coordinator_lost_job(State(state): State<ApiState>) -> Response {
    match state.coordinator.worker_lost_job().await {
        Ok(Some(job)) => Json(job).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => coordinator_operator_error(error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CoordinatorReadyRequest {
    job_id: String,
    retry: bool,
}

async fn coordinator_ready(
    State(state): State<ApiState>,
    Json(request): Json<CoordinatorReadyRequest>,
) -> Response {
    if let Err(error) = RunId::parse(&request.job_id) {
        return operator_error(StatusCode::BAD_REQUEST, format!("invalid jobId: {error}"));
    }
    match state
        .coordinator
        .worker_ready(&request.job_id, request.retry)
        .await
    {
        Ok(response) => {
            info!(
                event = "operator_coordinator_worker_ready",
                job_id = %response.job_id,
                worker_id = %response.worker_id,
                package = %response.package,
                retry = request.retry,
                disposition = ?response.disposition,
                retry_disposition = ?response.retry_disposition,
                "Operator confirmed cleanup and released the Tropibot worker"
            );
            state.worker_recovery_control.resume();
            Json(response).into_response()
        }
        Err(error) => coordinator_operator_error(error),
    }
}

fn job_summary(record: RunRecord) -> JobSummary {
    let manual_recovery_reason = record.worker.manual_recovery_reason.clone();
    // "Needs action" is an operator-facing classification. A normal running
    // claim blocks the worker from claiming a second job, but needs no human
    // intervention and must remain only in the Active classification.
    let requires_attention = manual_recovery_reason.is_some();
    let manual_recovery_kind = record.worker.manual_recovery_kind();
    let can_continue_after_cleanup =
        record.worker.cleanup_required && manual_recovery_kind == Some(ManualRecoveryKind::Cleanup);
    let recovery_kind = manual_recovery_kind.map(recovery_kind_name);
    // Versions before 0.1.2 could acknowledge an early worker error while
    // leaving the execution fields at their initial queued/pending values.
    // Normalize those persisted records for the dashboard as well as fixing
    // the write path for all new records.
    let terminal_worker_error =
        record.worker.completion_acknowledged && record.worker.worker_error.is_some();
    let status = if terminal_worker_error {
        ExecutionStatus::Completed
    } else {
        record.status
    };
    let phase = if terminal_worker_error {
        ExecutionPhase::Finished
    } else {
        record.phase
    };
    let cleanup_status = if terminal_worker_error && record.cleanup.status == CleanupStatus::Pending
    {
        record
            .worker
            .worker_error
            .as_ref()
            .map_or(record.cleanup.status, |error| error.cleanup_status)
    } else {
        record.cleanup.status
    };
    let summary = record.result.as_ref().map_or_else(
        || {
            record
                .worker
                .worker_error
                .as_ref()
                .map(|error| error.summary.clone())
        },
        |result| Some(result.summary.clone()),
    );
    let diagnostics = expert_diagnostics(&record);
    JobSummary {
        run_id: record.request.run_id.to_string(),
        dnp_name: record.request.package.dnp_name.to_string(),
        repository: record.request.source.repository.to_string(),
        pull_request: record.request.source.pull_request,
        head_sha: record.request.source.head_sha.to_string(),
        candidate_ref: record.request.package.candidate_ref.to_string(),
        baseline_ref: record
            .request
            .package
            .baseline_ref
            .as_ref()
            .map(ToString::to_string),
        status,
        phase,
        verdict: record.result.as_ref().map(|result| result.verdict),
        reason_code: record
            .result
            .as_ref()
            .map(|result| result.reason_code.clone()),
        summary,
        cleanup_status,
        cleanup_error: record.cleanup.error,
        leftover_packages: record.cleanup.leftover_packages,
        created_at: record.created_at,
        started_at: record.started_at,
        finished_at: record.finished_at,
        error_count: record.errors.len() + usize::from(record.worker.worker_error.is_some()),
        requires_attention,
        manual_recovery_reason,
        recovery_kind,
        can_continue_after_cleanup,
        pending_completion: record.worker.pending_completion_body.is_some(),
        has_claim: record.worker.claim_token.is_some() && !record.worker.completion_acknowledged,
        completion_acknowledged: record.worker.completion_acknowledged,
        completion_disposition: record.worker.completion_disposition,
        diagnostics,
    }
}

const fn recovery_kind_name(kind: ManualRecoveryKind) -> &'static str {
    match kind {
        ManualRecoveryKind::Cleanup => "cleanup",
        ManualRecoveryKind::CompletionConflict => "completion_conflict",
        ManualRecoveryKind::Manual => "manual",
    }
}

fn expert_diagnostics(record: &RunRecord) -> ExpertDiagnostics {
    ExpertDiagnostics {
        phase_history: record.phase_history.clone(),
        errors: record.errors.clone(),
        worker_error: record.worker.worker_error.clone(),
        cleanup_required: record.worker.cleanup_required,
        blocks_worker: record.requires_worker_attention(),
        target_recovery: record.worker.target_recovery.clone(),
        initial_packages: record.evidence.initial_packages.clone(),
        final_packages: record.evidence.final_packages.clone(),
        baseline: record.evidence.baseline.as_ref().map(capture_diagnostics),
        candidate: record.evidence.candidate.as_ref().map(capture_diagnostics),
        comparison: record.evidence.comparison.clone(),
        log_analysis: record.evidence.log_analysis.clone(),
    }
}

fn capture_diagnostics(capture: &CaptureEvidence) -> CaptureDiagnostics {
    CaptureDiagnostics {
        install_status: capture.install_status,
        install_duration_ms: capture.install_duration_ms,
        preview: capture.preview.clone(),
        containers: capture
            .details
            .as_ref()
            .map_or_else(Vec::new, |details| details.containers.clone()),
        stabilization: capture.stabilization.clone(),
        log_entry_count: capture.logs.as_ref().map_or(0, |logs| logs.entries.len()),
        log_error: capture.log_error.clone(),
        started_at: capture.started_at.clone(),
        finished_at: capture.finished_at.clone(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContinueRecoveryRequest {
    run_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContinueRecoveryResponse {
    status: &'static str,
    run_id: String,
    message: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum RecoveryAction {
    ContinueAfterCleanup,
    ConfirmCleanup,
    RetryCompletion,
    AcceptCoordinatorResult,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryActionRequest {
    run_id: String,
    action: RecoveryAction,
}

async fn recovery_action(
    State(state): State<ApiState>,
    Json(request): Json<RecoveryActionRequest>,
) -> Response {
    let run_id = match RunId::parse(&request.run_id) {
        Ok(run_id) => run_id,
        Err(error) => {
            return operator_error(StatusCode::BAD_REQUEST, format!("invalid runId: {error}"));
        }
    };
    let result = match request.action {
        RecoveryAction::ContinueAfterCleanup => acknowledge_cleanup_recovery(
            state.store.as_ref(),
            &state.worker_recovery_control,
            &run_id,
        )
        .await
        .map(|()| "manual cleanup acknowledged; worker recovery resumed"),
        RecoveryAction::ConfirmCleanup => confirm_manual_cleanup(state.store.as_ref(), &run_id)
            .await
            .map(|()| "manual cleanup recorded; choose how to resolve the completion conflict"),
        RecoveryAction::RetryCompletion => resolve_completion_conflict(
            state.store.as_ref(),
            &state.worker_recovery_control,
            &run_id,
            false,
        )
        .await
        .map(|()| "persisted completion queued for another delivery attempt"),
        RecoveryAction::AcceptCoordinatorResult => resolve_completion_conflict(
            state.store.as_ref(),
            &state.worker_recovery_control,
            &run_id,
            true,
        )
        .await
        .map(|()| "coordinator result accepted; local conflict released"),
    };
    match result {
        Ok(message) => Json(ContinueRecoveryResponse {
            status: "accepted",
            run_id: run_id.to_string(),
            message,
        })
        .into_response(),
        Err(error) => operator_error(error.status(), error.to_string()),
    }
}

async fn continue_recovery(
    State(state): State<ApiState>,
    Json(request): Json<ContinueRecoveryRequest>,
) -> Response {
    let run_id = match RunId::parse(&request.run_id) {
        Ok(run_id) => run_id,
        Err(error) => {
            return operator_error(StatusCode::BAD_REQUEST, format!("invalid runId: {error}"));
        }
    };
    if let Err(error) = acknowledge_cleanup_recovery(
        state.store.as_ref(),
        &state.worker_recovery_control,
        &run_id,
    )
    .await
    {
        return operator_error(error.status(), error.to_string());
    }
    (
        StatusCode::OK,
        Json(ContinueRecoveryResponse {
            status: "accepted",
            run_id: run_id.to_string(),
            message: "manual cleanup acknowledged; worker recovery resumed",
        }),
    )
        .into_response()
}

#[derive(Debug, Error)]
pub enum OperatorRecoveryError {
    #[error("run record was not found")]
    NotFound,
    #[error("run is not waiting for manual recovery")]
    NotWaiting,
    #[error("manual recovery hold is not a cleanup hold")]
    NotCleanup,
    #[error("manual recovery hold is not a completion conflict")]
    NotCompletionConflict,
    #[error("completion conflict cannot be released until cleanup is confirmed")]
    CleanupNotConfirmed,
    #[error("persisted completion is missing")]
    MissingCompletion,
    #[error("cannot access run record: {0}")]
    Store(String),
}

impl OperatorRecoveryError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::NotWaiting
            | Self::NotCleanup
            | Self::NotCompletionConflict
            | Self::CleanupNotConfirmed
            | Self::MissingCompletion => StatusCode::CONFLICT,
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub async fn acknowledge_cleanup_recovery(
    store: &dyn RunStore,
    worker_recovery_control: &WorkerRecoveryControl,
    run_id: &RunId,
) -> Result<(), OperatorRecoveryError> {
    let mut record = store
        .get(run_id)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?
        .ok_or(OperatorRecoveryError::NotFound)?;
    if record.worker.manual_recovery_reason.is_none() {
        return Err(OperatorRecoveryError::NotWaiting);
    }
    if !record.worker.cleanup_required
        || record.worker.manual_recovery_kind() != Some(ManualRecoveryKind::Cleanup)
    {
        return Err(OperatorRecoveryError::NotCleanup);
    }

    record_manual_cleanup(&mut record);
    record.worker.clear_manual_recovery();
    store
        .save(&record)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?;
    info!(
        event = "operator_cleanup_acknowledged",
        run_id = %run_id,
        dnp_name = %record.request.package.dnp_name,
        "Operator confirmed manual cleanup; worker recovery will continue"
    );
    worker_recovery_control.resume();
    Ok(())
}

async fn confirm_manual_cleanup(
    store: &dyn RunStore,
    run_id: &RunId,
) -> Result<(), OperatorRecoveryError> {
    let mut record = store
        .get(run_id)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?
        .ok_or(OperatorRecoveryError::NotFound)?;
    if record.worker.manual_recovery_reason.is_none() {
        return Err(OperatorRecoveryError::NotWaiting);
    }
    if !record.worker.cleanup_required {
        return Err(OperatorRecoveryError::NotCleanup);
    }
    record_manual_cleanup(&mut record);
    store
        .save(&record)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?;
    info!(
        event = "operator_cleanup_confirmed",
        run_id = %run_id,
        dnp_name = %record.request.package.dnp_name,
        "Operator recorded verified manual cleanup while preserving the recovery hold"
    );
    Ok(())
}

fn record_manual_cleanup(record: &mut RunRecord) {
    record.cleanup.status = CleanupStatus::Passed;
    record.cleanup.error = None;
    record.cleanup.leftover_packages.clear();
}

async fn resolve_completion_conflict(
    store: &dyn RunStore,
    worker_recovery_control: &WorkerRecoveryControl,
    run_id: &RunId,
    accept_coordinator_result: bool,
) -> Result<(), OperatorRecoveryError> {
    let mut record = store
        .get(run_id)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?
        .ok_or(OperatorRecoveryError::NotFound)?;
    if record.worker.manual_recovery_reason.is_none() {
        return Err(OperatorRecoveryError::NotWaiting);
    }
    if record.worker.manual_recovery_kind() != Some(ManualRecoveryKind::CompletionConflict) {
        return Err(OperatorRecoveryError::NotCompletionConflict);
    }
    if !matches!(
        record.cleanup.status,
        CleanupStatus::Passed | CleanupStatus::Skipped
    ) {
        return Err(OperatorRecoveryError::CleanupNotConfirmed);
    }
    if record.worker.pending_completion_body.is_none() {
        return Err(OperatorRecoveryError::MissingCompletion);
    }

    record.worker.clear_manual_recovery();
    if accept_coordinator_result {
        record.worker.pending_completion_body = None;
        record.worker.claim_token = None;
        record.worker.completion_acknowledged = true;
        record.worker.completion_disposition = Some("operator_accepted_coordinator".to_owned());
    }
    store
        .save(&record)
        .await
        .map_err(|error| OperatorRecoveryError::Store(error.to_string()))?;
    info!(
        event = "operator_completion_conflict_resolved",
        run_id = %run_id,
        dnp_name = %record.request.package.dnp_name,
        resolution = if accept_coordinator_result { "accept_coordinator" } else { "retry_local" },
        "Operator resolved a conflicting completion hold"
    );
    worker_recovery_control.resume();
    Ok(())
}

#[derive(Serialize)]
struct OperatorErrorResponse {
    error: String,
}

fn operator_error(status: StatusCode, error: impl Into<String>) -> Response {
    (
        status,
        Json(OperatorErrorResponse {
            error: truncate_utf8(&error.into(), 500),
        }),
    )
        .into_response()
}

fn coordinator_operator_error(error: CoordinatorError) -> Response {
    let status = match &error {
        CoordinatorError::Transient { .. } => StatusCode::SERVICE_UNAVAILABLE,
        CoordinatorError::Rejected { status, .. } if status.is_client_error() => *status,
        CoordinatorError::UnresolvedJob
        | CoordinatorError::ClaimLost { .. }
        | CoordinatorError::CompletionConflict { .. } => StatusCode::CONFLICT,
        CoordinatorError::Authentication { .. }
        | CoordinatorError::Rejected { .. }
        | CoordinatorError::Protocol(_)
        | CoordinatorError::Url(_) => StatusCode::BAD_GATEWAY,
    };
    operator_error(status, error.to_string())
}

fn not_ready(message: String) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ReadyResponse {
            status: "not_ready",
            message,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet, error::Error, net::SocketAddr, path::PathBuf, time::Duration,
    };

    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        config::PackageManagerMode,
        model::{PackageRequestDto, RunRequest, RunRequestDto, SourceDto, TargetRecoveryPlan},
        package_manager::FakePackageManager,
        storage::FileRunStore,
    };

    fn config() -> Result<Config, Box<dyn Error>> {
        Ok(Config {
            listen_addr: "127.0.0.1:8080".parse::<SocketAddr>()?,
            data_dir: PathBuf::from("/data"),
            harness_dnp_name: "package-harness.dnp.dappnode.eth".to_owned(),
            allow_destructive_tests: true,
            package_manager_mode: PackageManagerMode::Fake,
            dappmanager_mcp_url: None,
            dappmanager_mcp_token: None,
            mcp_timeout: Duration::from_secs(1),
            mcp_mutation_timeout: Duration::from_secs(1),
            mcp_mutation_attempts: 1,
            mcp_mutation_retry_delay: Duration::from_millis(1),
            stabilization_timeout: Duration::from_secs(1),
            stabilization_poll: Duration::from_millis(1),
            stabilization_required_samples: 1,
            log_tail: 1,
            cleanup_enabled: true,
            cleanup_timeout: Duration::from_secs(1),
            retain_baseline_packages: BTreeSet::new(),
            nexus_api_key: None,
            nexus_base_url: "https://nexus.example/v1".to_owned(),
            nexus_model: "nexus/auto".to_owned(),
            nexus_timeout: Duration::from_secs(1),
            nexus_max_input_bytes: 1_024,
            tropibot_url: "https://tropibot.example".to_owned(),
            package_harness_worker_id: "worker-01".to_owned(),
            package_harness_worker_token: "worker-token".to_owned(),
            package_harness_poll: Duration::from_secs(1),
            package_harness_heartbeat: Duration::from_secs(1),
            tropibot_timeout: Duration::from_secs(1),
        })
    }

    fn request(run_id: &str) -> Result<RunRequest, Box<dyn Error>> {
        Ok(RunRequest::try_from(RunRequestDto {
            schema_version: 1,
            run_id: run_id.to_owned(),
            source: SourceDto {
                repository: "dappnode/example".to_owned(),
                pull_request: 42,
                head_sha: "abcdef0123456789".to_owned(),
            },
            package: PackageRequestDto {
                dnp_name: "example.dnp.dappnode.eth".to_owned(),
                candidate_ref: "/ipfs/QmCandidate".to_owned(),
                baseline_ref: None,
            },
        })?)
    }

    #[tokio::test]
    async fn dashboard_lists_jobs_and_continues_cleanup_recovery() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let file_store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
        let request = request("dashboard-recovery")?;
        let mut record = RunRecord::claimed(request.clone(), "secret-claim-token".to_owned());
        record.worker.cleanup_required = true;
        record.worker.set_recovery_plan(TargetRecoveryPlan::Remove);
        record.worker.set_manual_recovery(
            ManualRecoveryKind::Cleanup,
            "operator verification is required".to_owned(),
        );
        record.cleanup.status = CleanupStatus::Failed;
        record.cleanup.error = Some("target remained installed".to_owned());
        file_store.create(&record).await?;
        let store: Arc<dyn RunStore> = file_store.clone();
        let package_manager: Arc<dyn PackageManager> = Arc::new(FakePackageManager::new());
        let app = router(ApiState {
            config: Arc::new(config()?),
            package_manager,
            store: Arc::clone(&store),
            coordinator: CoordinatorClient::new(
                "https://tropibot.example",
                "worker-01".to_owned(),
                "worker-token".to_owned(),
                Duration::from_secs(1),
            )?,
            worker_readiness: WorkerReadiness::default(),
            worker_recovery_control: WorkerRecoveryControl::default(),
            worker_drain_control: WorkerDrainControl::default(),
        });

        let dashboard = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty())?)
            .await?;
        assert_eq!(dashboard.status(), StatusCode::OK);
        assert_eq!(
            dashboard.headers().get(header::CONTENT_TYPE),
            Some(&header::HeaderValue::from_static(
                "text/html; charset=utf-8"
            ))
        );
        assert!(
            dashboard
                .headers()
                .get(header::CONTENT_SECURITY_POLICY)
                .is_some()
        );

        let jobs = app
            .clone()
            .oneshot(Request::builder().uri("/api/jobs").body(Body::empty())?)
            .await?;
        assert_eq!(jobs.status(), StatusCode::OK);
        let jobs_body = to_bytes(jobs.into_body(), 64 * 1024).await?;
        let jobs_json: Value = serde_json::from_slice(&jobs_body)?;
        assert_eq!(jobs_json["jobs"][0]["runId"], "dashboard-recovery");
        assert_eq!(jobs_json["jobs"][0]["canContinueAfterCleanup"], true);
        assert!(!String::from_utf8_lossy(&jobs_body).contains("secret-claim-token"));

        let continued = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/recovery/continue")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "runId": "dashboard-recovery" }).to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(continued.status(), StatusCode::OK);
        let updated = store
            .get(&request.run_id)
            .await?
            .ok_or("updated record missing")?;
        assert!(updated.worker.manual_recovery_reason.is_none());
        assert_eq!(updated.cleanup.status, CleanupStatus::Passed);
        Ok(())
    }

    #[tokio::test]
    async fn completion_conflict_can_be_retried_or_explicitly_released()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
        let request = request("dashboard-conflict")?;
        let mut record = RunRecord::claimed(request.clone(), "claim-token".to_owned());
        record.cleanup.status = CleanupStatus::Passed;
        record.worker.cleanup_required = true;
        record.worker.pending_completion_body = Some("{\"saved\":true}".to_owned());
        record.worker.manual_recovery_reason = Some(
            "Tropibot rejected the persisted completion as conflicting; operator recovery is required"
                .to_owned(),
        );
        store.create(&record).await?;
        let control = WorkerRecoveryControl::default();

        resolve_completion_conflict(store.as_ref(), &control, &request.run_id, false).await?;
        let retried = store.get(&request.run_id).await?.ok_or("record missing")?;
        assert!(retried.worker.manual_recovery_reason.is_none());
        assert_eq!(
            retried.worker.pending_completion_body.as_deref(),
            Some("{\"saved\":true}")
        );
        assert!(!retried.worker.completion_acknowledged);

        let mut conflicted_again = retried;
        conflicted_again.worker.manual_recovery_reason =
            Some("persisted completion is conflicting".to_owned());
        store.save(&conflicted_again).await?;
        resolve_completion_conflict(store.as_ref(), &control, &request.run_id, true).await?;
        let released = store.get(&request.run_id).await?.ok_or("record missing")?;
        assert!(released.worker.pending_completion_body.is_none());
        assert!(released.worker.claim_token.is_none());
        assert!(released.worker.completion_acknowledged);
        assert_eq!(
            released.worker.completion_disposition.as_deref(),
            Some("operator_accepted_coordinator")
        );
        assert!(!released.requires_worker_attention());
        Ok(())
    }

    #[test]
    fn legacy_acknowledged_worker_error_is_reported_as_terminal() -> Result<(), Box<dyn Error>> {
        let request = request("legacy-worker-error")?;
        let mut record = RunRecord::claimed(request, "old-claim-token".to_owned());
        record.worker.worker_error = Some(WorkerError {
            code: crate::model::WorkerErrorCode::UnsupportedJob,
            summary: "refused to test a core Dappnode package".to_owned(),
            cleanup_status: CleanupStatus::Skipped,
        });
        record.worker.completion_acknowledged = true;
        record.worker.completion_disposition = Some("recorded".to_owned());

        let summary = job_summary(record);
        assert_eq!(summary.status, ExecutionStatus::Completed);
        assert_eq!(summary.phase, ExecutionPhase::Finished);
        assert_eq!(summary.cleanup_status, CleanupStatus::Skipped);
        assert_eq!(
            summary.summary.as_deref(),
            Some("refused to test a core Dappnode package")
        );
        assert_eq!(summary.error_count, 1);
        assert!(!summary.has_claim);
        Ok(())
    }

    #[test]
    fn normal_running_claim_is_active_without_operator_attention() -> Result<(), Box<dyn Error>> {
        let request = request("normal-running")?;
        let mut record = RunRecord::claimed(request, "active-claim-token".to_owned());
        record.start();
        record.transition(ExecutionPhase::CandidateInstall);

        let summary = job_summary(record);
        assert_eq!(summary.status, ExecutionStatus::Running);
        assert!(!summary.requires_attention);
        assert!(summary.diagnostics.blocks_worker);
        assert!(summary.has_claim);
        Ok(())
    }

    #[tokio::test]
    async fn operator_can_drain_and_resume_worker_lifecycle() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store: Arc<dyn RunStore> =
            Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
        let drain_control = WorkerDrainControl::default();
        let app = router(ApiState {
            config: Arc::new(config()?),
            package_manager: Arc::new(FakePackageManager::new()),
            store,
            coordinator: CoordinatorClient::new(
                "https://tropibot.example",
                "worker-01".to_owned(),
                "worker-token".to_owned(),
                Duration::from_secs(1),
            )?,
            worker_readiness: WorkerReadiness::default(),
            worker_recovery_control: WorkerRecoveryControl::default(),
            worker_drain_control: drain_control.clone(),
        });

        let bodyless = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/worker/drain")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(bodyless.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(drain_control.state(), WorkerDrainState::Accepting);

        let drained = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/worker/drain")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(drained.status(), StatusCode::OK);
        assert_eq!(drain_control.state(), WorkerDrainState::Draining);

        let ready = app
            .clone()
            .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
            .await?;
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);

        let resumed = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/operator/worker/resume")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(resumed.status(), StatusCode::OK);
        assert_eq!(drain_control.state(), WorkerDrainState::Accepting);
        Ok(())
    }
}
