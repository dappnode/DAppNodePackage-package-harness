use async_trait::async_trait;
use dappnode_mcp_client::{DappnodeMcpClient, DappnodeMcpError};
use dappnode_types::{ContainerState, InstallOptions};

use crate::{
    analysis::redaction::truncate_utf8,
    model::{
        ContainerLog, ContainerSnapshot, DnpName, PackageDetails, PackageLogs, PackageRef,
        PackageSummary, PreviewSummary,
    },
};

use super::{PackageManager, PackageManagerError, REQUIRED_MCP_TOOLS, ToolAvailability};

#[derive(Clone)]
pub struct DappmanagerPackageManager {
    client: DappnodeMcpClient,
}

impl DappmanagerPackageManager {
    pub fn new(
        url: String,
        token: String,
        timeout: std::time::Duration,
    ) -> Result<Self, PackageManagerError> {
        crate::tls::ensure_crypto_provider();
        let client = DappnodeMcpClient::with_timeout(url, token, timeout).map_err(package_error)?;
        Ok(Self { client })
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
        let summary = serde_json::to_string(&preview)
            .map(|text| truncate_utf8(&text, 2_000))
            .unwrap_or_else(|_| "preview received".to_owned());
        Ok(PreviewSummary {
            package_name: preview.dnp_name.map(|name| name.to_string()),
            version: preview
                .semantic_version
                .map(|version| version.to_string())
                .or_else(|| preview.requested_version.map(|version| version.to_string())),
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
        let options = install_options(version);
        let user_settings = serde_json::Map::new();
        match self
            .client
            .install_package(dnp_name, version, &user_settings, options)
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

    async fn update_package(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        let options = install_options(Some(version));
        self.client
            .update_package(dnp_name, Some(version), options)
            .await
            .or_else(|error| {
                if operation_in_progress_error(&error.to_string()) {
                    Ok(())
                } else {
                    Err(package_error(error))
                }
            })
    }

    async fn remove_package(
        &self,
        dnp_name: &DnpName,
        delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        self.client
            .remove_package(dnp_name, delete_volumes)
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

fn install_options(version: Option<&PackageRef>) -> InstallOptions {
    match version {
        Some(version) if version.is_ipfs() => {
            InstallOptions::default().with_bypass_signed_restriction()
        }
        _ => InstallOptions::default(),
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::model::{RunRequest, RunRequestDto};

    use super::{install_options, operation_in_progress_error, package_absent_error};

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
    fn ipfs_update_bypasses_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("/ipfs/QmCandidate")?;
        let options = install_options(Some(&request.package.candidate_ref));
        assert!(options.bypass_signed_restriction);
        assert!(!options.bypass_core_restriction);
        assert!(!options.bypass_resolver);
        Ok(())
    }

    #[test]
    fn registry_update_does_not_bypass_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("0.1.56")?;
        assert!(install_options(Some(&request.package.candidate_ref)).is_empty());
        Ok(())
    }

    #[test]
    fn ipfs_install_bypasses_signed_restriction() -> Result<(), Box<dyn Error>> {
        let request = request_with_candidate("ipfs://QmCandidate")?;
        assert!(install_options(Some(&request.package.candidate_ref)).bypass_signed_restriction);
        Ok(())
    }

    #[test]
    fn latest_install_does_not_bypass_signed_restriction() {
        assert!(install_options(None).is_empty());
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
