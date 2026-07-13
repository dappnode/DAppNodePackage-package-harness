use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tokio::sync::mpsc;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

use crate::{
    analysis::redaction::truncate_utf8,
    api::auth::bearer_is_valid,
    config::Config,
    model::{ExecutionPhase, ExecutionStatus, RunId, RunRecord, RunRequest, RunRequestDto},
    package_manager::PackageManager,
    storage::{RunStore, StoreError},
};

#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub store: Arc<dyn RunStore>,
    pub package_manager: Arc<dyn PackageManager>,
    pub queue: mpsc::Sender<RunId>,
    pub accepting: Arc<AtomicBool>,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
        .route("/v1/runs", post(create_run))
        .route("/v1/runs/{run_id}", get(get_run))
        .layer(RequestBodyLimitLayer::new(256 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                message,
            }),
        )
            .into_response();
    }
    match state.package_manager.verify_tools().await {
        Ok(tools) if tools.ready() => Json(ReadyResponse {
            status: "ready",
            message: tools.message(),
        })
        .into_response(),
        Ok(tools) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                message: tools.message(),
            }),
        )
            .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                message: truncate_utf8(&error.to_string(), 500),
            }),
        )
            .into_response(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedResponse {
    run_id: RunId,
    status: ExecutionStatus,
    phase: ExecutionPhase,
}

async fn create_run(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
    if !bearer_is_valid(&headers, state.config.harness_api_token.as_deref()) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    if !state.accepting.load(Ordering::SeqCst) {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "server is shutting down");
    }
    if let Some(message) = state.config.acceptance_error() {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, &message);
    }
    let dto: RunRequestDto = match serde_json::from_slice(&body) {
        Ok(dto) => dto,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let request = match RunRequest::try_from(dto) {
        Ok(request) => request,
        Err(error) => return error_response(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    if request.package.dnp_name.as_str() == state.config.harness_dnp_name {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "cannot test the harness package",
        );
    }
    match state.store.get(&request.run_id).await {
        Ok(Some(existing)) => return duplicate_response(&request, existing),
        Ok(None) => {}
        Err(error) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
        }
    }
    let permit = match state.queue.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "run queue is full"),
    };
    let record = RunRecord::new(request.clone());
    match state.store.create(&record).await {
        Ok(()) => {
            permit.send(request.run_id.clone());
            (
                StatusCode::ACCEPTED,
                Json(AcceptedResponse {
                    run_id: request.run_id,
                    status: ExecutionStatus::Queued,
                    phase: ExecutionPhase::Queued,
                }),
            )
                .into_response()
        }
        Err(StoreError::AlreadyExists) => match state.store.get(&request.run_id).await {
            Ok(Some(existing)) => duplicate_response(&request, existing),
            Ok(None) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "run appeared concurrently but could not be loaded",
            ),
            Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
        },
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

async fn get_run(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Response {
    if !bearer_is_valid(&headers, state.config.harness_api_token.as_deref()) {
        return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let run_id = match RunId::parse(&run_id) {
        Ok(run_id) => run_id,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    match state.store.get(&run_id).await {
        Ok(Some(record)) => Json(record).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "run not found"),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

fn duplicate_response(request: &RunRequest, existing: RunRecord) -> Response {
    if &existing.request == request {
        return Json(existing).into_response();
    }
    error_response(
        StatusCode::CONFLICT,
        "runId already exists with a different request",
    )
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.to_owned(),
        }),
    )
        .into_response()
}
