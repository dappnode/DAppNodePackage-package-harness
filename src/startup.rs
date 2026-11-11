//! Read-only dependency checks that must finish before the worker can claim jobs.

use thiserror::Error;
use tracing::info;

use crate::{
    analysis::{NexusLogAnalyzer, redaction::redact_and_bound_single_line},
    config::{Config, PackageManagerMode},
    coordinator::CoordinatorClient,
    package_manager::PackageManager,
};

#[derive(Debug, Error)]
#[error("startup validation failed ({check}): {message}")]
pub struct StartupError {
    check: &'static str,
    message: String,
}

impl StartupError {
    fn new(config: &Config, check: &'static str, error: impl std::fmt::Display) -> Self {
        let mut message = error.to_string();
        for secret in [
            Some(config.package_harness_worker_token.as_str()),
            config.dappmanager_mcp_token.as_deref(),
            config.nexus_api_key.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|secret| !secret.is_empty())
        {
            message = message.replace(secret, "[REDACTED]");
        }
        Self {
            check,
            message: redact_and_bound_single_line(&message, 500),
        }
    }
}

/// Checks authenticated MCP capabilities and coordinator access without claiming
/// a job or changing any package. Existing lost jobs remain for worker recovery.
pub async fn validate_dependencies(
    config: &Config,
    package_manager: &dyn PackageManager,
    coordinator: &CoordinatorClient,
) -> Result<(), StartupError> {
    if let Some(error) = config.acceptance_error() {
        return Err(StartupError::new(config, "configuration", error));
    }
    let tools = package_manager
        .verify_tools()
        .await
        .map_err(|error| StartupError::new(config, "Dappmanager tools and token", error))?;
    if !tools.ready() {
        return Err(StartupError::new(
            config,
            "Dappmanager tools and token",
            tools.message(),
        ));
    }
    let packages = package_manager
        .list_packages()
        .await
        .map_err(|error| StartupError::new(config, "Dappmanager package inventory", error))?;
    if config.package_manager_mode == PackageManagerMode::Mcp {
        let package = packages
            .iter()
            .find(|package| package.is_core)
            .or_else(|| packages.first())
            .ok_or_else(|| {
                StartupError::new(
                    config,
                    "Dappmanager package inventory",
                    "no installed packages returned",
                )
            })?;
        package_manager
            .get_package_details(&package.dnp_name)
            .await
            .map_err(|error| StartupError::new(config, "Dappmanager package details", error))?;
        // Discard the bounded sample; startup never logs or persists package logs.
        package_manager
            .get_package_logs(&package.dnp_name, 1)
            .await
            .map_err(|error| StartupError::new(config, "Dappmanager package logs", error))?;
        package_manager
            .preview_install(&package.dnp_name, None)
            .await
            .map_err(|error| StartupError::new(config, "Dappmanager install preview", error))?;
    }
    info!(
        event = "startup_dappmanager_validated",
        "Dappmanager authentication, required tools, and reads verified"
    );
    coordinator.worker_lost_job().await.map_err(|error| {
        StartupError::new(config, "Tropibot authentication and worker protocol", error)
    })?;
    info!(
        event = "startup_coordinator_validated",
        "Tropibot authentication and worker protocol verified without claiming work"
    );
    if let Some(key) = &config.nexus_api_key {
        let nexus = NexusLogAnalyzer::new(
            key.clone(),
            &config.nexus_base_url,
            config.nexus_model.clone(),
            config.nexus_timeout,
            config.nexus_max_input_bytes,
        )
        .map_err(|error| StartupError::new(config, "Nexus configuration", error))?;
        nexus
            .validate_access()
            .await
            .map_err(|error| StartupError::new(config, "Nexus inference access", error))?;
        info!(
            event = "startup_nexus_validated",
            "Nexus inference access verified"
        );
    }
    Ok(())
}
