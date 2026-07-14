use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tower_http::trace::TraceLayer;

use crate::{
    analysis::redaction::truncate_utf8, config::Config, package_manager::PackageManager,
    worker::WorkerReadiness,
};

/// State only for local process supervision. This API deliberately has no
/// mutation route: jobs are claimed outbound from Tropibot.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub package_manager: Arc<dyn PackageManager>,
    pub worker_readiness: WorkerReadiness,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(ready))
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
