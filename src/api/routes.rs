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
    model::{
        CleanupStatus, ExecutionPhase, ExecutionStatus, ReasonCode, RunId, RunRecord, Verdict,
    },
    package_manager::PackageManager,
    storage::RunStore,
    worker::{WorkerReadiness, WorkerRecoveryControl},
};

/// State for local process supervision and explicit operator recovery.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub package_manager: Arc<dyn PackageManager>,
    pub store: Arc<dyn RunStore>,
    pub worker_readiness: WorkerReadiness,
    pub worker_recovery_control: WorkerRecoveryControl,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/dashboard.css", get(dashboard_css))
        .route("/dashboard.js", get(dashboard_js))
        .route("/api/jobs", get(jobs))
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/operator/recovery/continue", post(continue_recovery))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard/index.html"))
}

async fn dashboard_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("dashboard/dashboard.css"),
    )
}

async fn dashboard_js() -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobSummary {
    run_id: String,
    dnp_name: String,
    repository: String,
    pull_request: u64,
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
    can_continue_after_cleanup: bool,
    completion_acknowledged: bool,
    completion_disposition: Option<String>,
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
    let worker = if let Some(message) = state.config.acceptance_error() {
        WorkerSummary {
            status: "blocked",
            message,
        }
    } else if let Some(message) = state.worker_readiness.reason() {
        WorkerSummary {
            status: "paused",
            message,
        }
    } else {
        WorkerSummary {
            status: "ready",
            message: "Polling Tropibot for package jobs".to_owned(),
        }
    };
    Json(JobsResponse {
        worker,
        jobs: records.into_iter().map(job_summary).collect(),
    })
    .into_response()
}

fn job_summary(record: RunRecord) -> JobSummary {
    let manual_recovery_reason = record.worker.manual_recovery_reason.clone();
    let requires_attention = record.requires_worker_attention();
    let can_continue_after_cleanup = record.worker.cleanup_required
        && manual_recovery_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("cleanup"));
    JobSummary {
        run_id: record.request.run_id.to_string(),
        dnp_name: record.request.package.dnp_name.to_string(),
        repository: record.request.source.repository.to_string(),
        pull_request: record.request.source.pull_request,
        candidate_ref: record.request.package.candidate_ref.to_string(),
        baseline_ref: record
            .request
            .package
            .baseline_ref
            .as_ref()
            .map(ToString::to_string),
        status: record.status,
        phase: record.phase,
        verdict: record.result.as_ref().map(|result| result.verdict),
        reason_code: record
            .result
            .as_ref()
            .map(|result| result.reason_code.clone()),
        summary: record.result.as_ref().map(|result| result.summary.clone()),
        cleanup_status: record.cleanup.status,
        cleanup_error: record.cleanup.error,
        leftover_packages: record.cleanup.leftover_packages,
        created_at: record.created_at,
        started_at: record.started_at,
        finished_at: record.finished_at,
        error_count: record.errors.len(),
        requires_attention,
        manual_recovery_reason,
        can_continue_after_cleanup,
        completion_acknowledged: record.worker.completion_acknowledged,
        completion_disposition: record.worker.completion_disposition,
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
    #[error("cannot access run record: {0}")]
    Store(String),
}

impl OperatorRecoveryError {
    fn status(&self) -> StatusCode {
        match self {
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::NotWaiting | Self::NotCleanup => StatusCode::CONFLICT,
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
    let reason = record
        .worker
        .manual_recovery_reason
        .as_deref()
        .ok_or(OperatorRecoveryError::NotWaiting)?;
    if !record.worker.cleanup_required || !reason.contains("cleanup") {
        return Err(OperatorRecoveryError::NotCleanup);
    }

    record.worker.manual_recovery_reason = None;
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
        record.worker.manual_recovery_reason =
            Some("target cleanup failed; operator action is required".to_owned());
        record.cleanup.status = CleanupStatus::Failed;
        record.cleanup.error = Some("target remained installed".to_owned());
        file_store.create(&record).await?;
        let store: Arc<dyn RunStore> = file_store.clone();
        let package_manager: Arc<dyn PackageManager> = Arc::new(FakePackageManager::new());
        let app = router(ApiState {
            config: Arc::new(config()?),
            package_manager,
            store: Arc::clone(&store),
            worker_readiness: WorkerReadiness::default(),
            worker_recovery_control: WorkerRecoveryControl::default(),
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
        Ok(())
    }
}
