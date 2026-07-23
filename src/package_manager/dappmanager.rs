use std::{
    future::Future,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use dappnode_mcp_client::{DappnodeMcpClient, DappnodeMcpError};
use dappnode_types::{ContainerState, InstallOptions};
use tracing::{info, warn};

use crate::{
    analysis::redaction::{redact_and_bound_single_line, truncate_utf8},
    model::{
        ContainerLog, ContainerSnapshot, DnpName, PackageDetails, PackageLogs, PackageRef,
        PackageSummary, PreviewSummary,
    },
};

use super::{
    PackageManager, PackageManagerError, REQUIRED_MCP_TOOLS, ToolAvailability,
    retryable_tool_message, retryable_transport_message,
};

#[derive(Clone)]
pub struct DappmanagerPackageManager {
    client: DappnodeMcpClient,
    mutation_client: DappnodeMcpClient,
    mutation_timeout: Duration,
    mutation_attempts: usize,
    mutation_retry_delay: Duration,
}

impl DappmanagerPackageManager {
    pub fn new(
        url: String,
        token: String,
        timeout: Duration,
        mutation_timeout: Duration,
        mutation_attempts: usize,
        mutation_retry_delay: Duration,
    ) -> Result<Self, PackageManagerError> {
        crate::tls::ensure_crypto_provider();
        let client =
            DappnodeMcpClient::with_timeout(&url, &token, timeout).map_err(package_error)?;
        let mutation_client =
            DappnodeMcpClient::with_timeout(url, token, mutation_timeout).map_err(package_error)?;
        Ok(Self {
            client,
            mutation_client,
            mutation_timeout,
            mutation_attempts,
            mutation_retry_delay,
        })
    }

    async fn retry_mutation<Operation, OperationFuture, Reconcile, ReconcileFuture>(
        &self,
        tool: &'static str,
        dnp_name: &DnpName,
        requested_ref: Option<&str>,
        mut operation: Operation,
        mut reconcile: Reconcile,
    ) -> Result<(), DappnodeMcpError>
    where
        Operation: FnMut() -> OperationFuture,
        OperationFuture: Future<Output = Result<(), DappnodeMcpError>>,
        Reconcile: FnMut() -> ReconcileFuture,
        ReconcileFuture: Future<Output = bool>,
    {
        for attempt in 1..=self.mutation_attempts {
            let started = Instant::now();
            info!(
                event = "mcp_mutation_attempt_started",
                tool,
                dnp_name = %dnp_name,
                requested_ref = requested_ref.unwrap_or("none"),
                attempt,
                max_attempts = self.mutation_attempts,
                timeout_ms = self.mutation_timeout.as_millis() as u64,
                "Dappmanager attempt started"
            );
            match operation().await {
                Ok(()) => {
                    info!(
                        event = "mcp_mutation_attempt_succeeded",
                        tool,
                        dnp_name = %dnp_name,
                        requested_ref = requested_ref.unwrap_or("none"),
                        attempt,
                        duration_ms = started.elapsed().as_millis() as u64,
                        "Dappmanager mutation completed"
                    );
                    return Ok(());
                }
                Err(error)
                    if attempt < self.mutation_attempts && retryable_mutation_error(&error) =>
                {
                    let safe_error = redact_and_bound_single_line(&error.to_string(), 500);
                    if reconcile().await {
                        info!(
                            event = "mcp_mutation_reconciled",
                            tool,
                            dnp_name = %dnp_name,
                            requested_ref = requested_ref.unwrap_or("none"),
                            attempt,
                            duration_ms = started.elapsed().as_millis() as u64,
                            error = %safe_error,
                            "Timed-out mutation had already reached the requested state"
                        );
                        return Ok(());
                    }
                    let delay = retry_delay(self.mutation_retry_delay, attempt);
                    warn!(
                        event = "mcp_mutation_retry",
                        tool,
                        dnp_name = %dnp_name,
                        requested_ref = requested_ref.unwrap_or("none"),
                        attempt,
                        max_attempts = self.mutation_attempts,
                        attempt_duration_ms = started.elapsed().as_millis() as u64,
                        retry_delay_ms = delay.as_millis(),
                        error = %safe_error,
                        "Transient Dappmanager mutation failure; retry scheduled"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    let safe_error = redact_and_bound_single_line(&error.to_string(), 500);
                    warn!(
                        event = "mcp_mutation_attempt_failed",
                        tool,
                        dnp_name = %dnp_name,
                        requested_ref = requested_ref.unwrap_or("none"),
                        attempt,
                        max_attempts = self.mutation_attempts,
                        duration_ms = started.elapsed().as_millis() as u64,
                        retryable = retryable_mutation_error(&error),
                        error = %safe_error,
                        "Dappmanager mutation failed"
                    );
                    return Err(error);
                }
            }
        }
        unreachable!("mutation attempts are validated to be non-zero")
    }

    async fn install_package_with_options(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
        bypass_signature: bool,
    ) -> Result<(), PackageManagerError> {
        let options = install_options(version, bypass_signature);
        let user_settings = serde_json::Map::new();
        match self
            .retry_mutation(
                "dappnode_install_package",
                dnp_name,
                version.map(PackageRef::as_str),
                || {
                    self.mutation_client
                        .install_package(dnp_name, version, &user_settings, options)
                },
                || async { self.client.get_package_details(dnp_name).await.is_ok() },
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if required_setup_error(&error.to_string()) => {
                Err(PackageManagerError::RequiredSetup)
            }
            Err(error) if operation_in_progress_error(&error.to_string()) => Ok(()),
            Err(error) => Err(package_error(error)),
        }
    }

    async fn update_package_with_options(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
        bypass_signature: bool,
    ) -> Result<(), PackageManagerError> {
        let options = install_options(Some(version), bypass_signature);
        self.retry_mutation(
            "dappnode_update_package",
            dnp_name,
            Some(version.as_str()),
            || {
                self.mutation_client
                    .update_package(dnp_name, Some(version), options)
            },
            || async {
                self.client
                    .get_package_details(dnp_name)
                    .await
                    .ok()
                    .and_then(|details| details.version)
                    .is_some_and(|installed| installed.to_string() == version.as_str())
            },
        )
        .await
        .or_else(|error| {
            if operation_in_progress_error(&error.to_string()) {
                Ok(())
            } else {
                Err(package_error(error))
            }
        })
    }
}

#[async_trait]
impl PackageManager for DappmanagerPackageManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        let availability = self
            .client
            .verify_tools(&REQUIRED_MCP_TOOLS)
            .await
            .map_err(package_error)?;
        Ok(ToolAvailability {
            available: availability
                .available
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
            missing: availability
                .missing
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
        })
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        self.client
            .list_packages()
            .await
            .map_err(package_error)?
            .into_iter()
            .map(|package| {
                Ok(PackageSummary {
                    dnp_name: package.dnp_name,
                    version: package.version.map(|version| version.to_string()),
                    is_core: package.is_core,
                })
            })
            .collect()
    }

    async fn get_package_details(
        &self,
        dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        let details = self
            .client
            .get_package_details(dnp_name)
            .await
            .map_err(package_error)?;
        Ok(PackageDetails {
            dnp_name: details.dnp_name,
            version: details.version.map(|version| version.to_string()),
            containers: details
                .containers
                .into_iter()
                .map(|container| ContainerSnapshot {
                    name: container.name,
                    service_name: container.service_name,
                    state: container.state.map(container_state),
                    running: container.running,
                    image: container.image,
                    created: container.created,
                })
                .collect(),
        })
    }

    async fn get_package_logs(
        &self,
        dnp_name: &DnpName,
        tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        let tail = u16::try_from(tail).map_err(|error| PackageManagerError::InvalidResponse {
            tool: "dappnode_get_package_logs".to_owned(),
            message: format!("log tail is outside Dappmanager's accepted range: {error}"),
        })?;
        let logs = self
            .client
            .get_package_logs(dnp_name, tail)
            .await
            .map_err(package_error)?;
        Ok(PackageLogs {
            entries: logs
                .entries
                .into_iter()
                .map(|entry| ContainerLog {
                    container: Some(entry.container),
                    text: entry.text,
                })
                .collect(),
        })
    }

    async fn preview_install(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        let preview = self
            .client
            .fetch_install_preview(dnp_name, version)
            .await
            .map_err(package_error)?;
        let resolved_ref = preview.origin.clone();
        let summary = serde_json::to_string(&preview)
            .map(|text| truncate_utf8(&text, 2_000))
            .unwrap_or_else(|_| "preview received".to_owned());
        Ok(PreviewSummary {
            package_name: preview.dnp_name.map(|name| name.to_string()),
            version: preview
                .semantic_version
                .map(|version| version.to_string())
                .or_else(|| preview.requested_version.map(|version| version.to_string())),
            resolved_ref,
            image_count: None,
            requires_user_input: preview.requires_user_input,
            summary,
        })
    }

    async fn install_package(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        self.install_package_with_options(dnp_name, version, false)
            .await
    }

    async fn install_package_bypassing_signature(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        self.install_package_with_options(dnp_name, version, true)
            .await
    }

    async fn update_package(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        self.update_package_with_options(dnp_name, version, false)
            .await
    }

    async fn update_package_bypassing_signature(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        self.update_package_with_options(dnp_name, version, true)
            .await
    }

    async fn remove_package(
        &self,
        dnp_name: &DnpName,
        delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        self.retry_mutation(
            "dappnode_remove_package",
            dnp_name,
            None,
            || {
                self.mutation_client
                    .remove_package(dnp_name, delete_volumes)
            },
            || async {
                self.client.list_packages().await.is_ok_and(|packages| {
                    !packages.iter().any(|package| &package.dnp_name == dnp_name)
                })
            },
        )
        .await
        .or_else(|error| {
            if package_absent_error(&error.to_string()) {
                Ok(())
            } else {
                Err(package_error(error))
            }
        })
    }
}

fn package_error(error: DappnodeMcpError) -> PackageManagerError {
    match error {
        DappnodeMcpError::Configuration { message } => PackageManagerError::Transport(message),
        DappnodeMcpError::InvalidArgument { field, message } => {
            PackageManagerError::InvalidResponse {
                tool: field,
                message,
            }
        }
        DappnodeMcpError::Timeout { operation } => PackageManagerError::Timeout { tool: operation },
        DappnodeMcpError::Transport { message, .. } => PackageManagerError::Transport(message),
        DappnodeMcpError::Tool { tool, message } => PackageManagerError::Tool { tool, message },
        DappnodeMcpError::InvalidResponse { operation, message } => {
            PackageManagerError::InvalidResponse {
                tool: operation,
                message,
            }
        }
    }
}

fn container_state(state: ContainerState) -> String {
    match state {
        ContainerState::Created => "created",
        ContainerState::Restarting => "restarting",
        ContainerState::Running => "running",
        ContainerState::Paused => "paused",
        ContainerState::Exited => "exited",
        ContainerState::Dead => "dead",
        ContainerState::Removing => "removing",
    }
    .to_owned()
}

fn install_options(version: Option<&PackageRef>, bypass_signature: bool) -> InstallOptions {
    let options = match version {
        Some(version) if version.is_ipfs() => {
            InstallOptions::default().with_bypass_signed_restriction()
        }
        _ => InstallOptions::default(),
    };
    if bypass_signature {
        options.with_bypass_signed_restriction()
    } else {
        options
    }
}

fn required_setup_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    (lower.contains("required") || lower.contains("mandatory"))
        && (lower.contains("setting") || lower.contains("configuration") || lower.contains("setup"))
}

fn operation_in_progress_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains(" is installing")
        || lower.contains(" already installing")
        || lower.contains(" is updating")
        || lower.contains(" already updating")
        || lower.contains("operation is already in progress")
}

fn package_absent_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("no dnp was found")
        || lower.contains("package was not found")
        || lower.contains("not installed")
}

fn retryable_mutation_error(error: &DappnodeMcpError) -> bool {
    match error {
        DappnodeMcpError::Timeout { .. } => true,
        DappnodeMcpError::Transport { message, .. } => retryable_transport_message(message),
        DappnodeMcpError::Tool { message, .. } => retryable_tool_message(message),
        DappnodeMcpError::Configuration { .. }
        | DappnodeMcpError::InvalidArgument { .. }
        | DappnodeMcpError::InvalidResponse { .. } => false,
    }
}

fn retry_delay(initial: Duration, failed_attempt: usize) -> Duration {
    let exponent = u32::try_from(failed_attempt.saturating_sub(1).min(6)).unwrap_or(6);
    initial
        .checked_mul(2_u32.saturating_pow(exponent))
        .unwrap_or(Duration::from_secs(60))
        .min(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::model::{RunRequest, RunRequestDto};

    use dappnode_mcp_client::DappnodeMcpError;

    use super::{
        install_options, operation_in_progress_error, package_absent_error,
        retryable_mutation_error,
    };

    #[test]
    fn detects_dappmanager_in_progress_errors() {
        assert!(operation_in_progress_error(
            "MCP tool 'dappnode_install_package' failed: Error: rotki.dnp.dappnode.eth is installing"
        ));
        assert!(operation_in_progress_error(
            "Error: operation is already in progress"
        ));
        assert!(!operation_in_progress_error(
            "Error: failed to download image"
        ));
    }

    #[test]
    fn detects_idempotent_remove_absence_errors() {
        assert!(package_absent_error(
            "MCP tool dappnode_remove_package failed: No DNP was found for name rotki.dnp.dappnode.eth"
        ));
        assert!(package_absent_error("package was not found"));
        assert!(!package_absent_error("permission denied"));
    }

    #[test]
    fn retries_transient_ipfs_and_transport_failures() {
        assert!(retryable_mutation_error(&DappnodeMcpError::Tool {
            tool: "dappnode_install_package".to_owned(),
            message: "Can't download image: Could not get block QmExample".to_owned(),
        }));
        assert!(retryable_mutation_error(&DappnodeMcpError::Tool {
            tool: "dappnode_install_package".to_owned(),
            message: "terminated".to_owned(),
        }));
        assert!(retryable_mutation_error(&DappnodeMcpError::Transport {
            operation: "connect".to_owned(),
            message: "connection reset".to_owned(),
        }));
    }

    #[test]
    fn does_not_retry_authentication_or_validation_failures() {
        assert!(!retryable_mutation_error(&DappnodeMcpError::Transport {
            operation: "connect".to_owned(),
            message: "HTTP 403 Forbidden".to_owned(),
        }));
        assert!(!retryable_mutation_error(&DappnodeMcpError::Tool {
            tool: "dappnode_install_package".to_owned(),
            message: "required setup values are missing".to_owned(),
        }));
    }

    #[test]
    fn ipfs_update_bypasses_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("/ipfs/QmCandidate")?;
        let options = install_options(Some(&request.package.candidate_ref), false);
        assert!(options.bypass_signed_restriction);
        assert!(!options.bypass_core_restriction);
        assert!(!options.bypass_resolver);
        Ok(())
    }

    #[test]
    fn registry_update_does_not_bypass_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("0.1.56")?;
        assert!(install_options(Some(&request.package.candidate_ref), false).is_empty());
        Ok(())
    }

    #[test]
    fn signature_retry_explicitly_bypasses_registry_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("0.1.56")?;
        let options = install_options(Some(&request.package.candidate_ref), true);
        assert!(options.bypass_signed_restriction);
        assert!(!options.bypass_core_restriction);
        assert!(!options.bypass_resolver);
        Ok(())
    }

    #[test]
    fn ipfs_install_bypasses_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("ipfs://QmCandidate")?;
        assert!(
            install_options(Some(&request.package.candidate_ref), false).bypass_signed_restriction
        );
        Ok(())
    }

    #[test]
    fn latest_install_does_not_bypass_signed_restriction() {
        assert!(install_options(None, false).is_empty());
    }

    fn request_with_candidate(candidate_ref: &str) -> Result<RunRequest, Box<dyn Error>> {
        let dto: RunRequestDto = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "runId": "argument-test",
            "source": {
                "repository": "dappnode/example",
                "pullRequest": 1,
                "headSha": "abcdef"
            },
            "package": {
                "dnpName": "rotki.dnp.dappnode.eth",
                "candidateRef": candidate_ref
            }
        }))?;
        Ok(RunRequest::try_from(dto)?)
    }
}
