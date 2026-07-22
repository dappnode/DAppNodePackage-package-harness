use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::model::{
    ContainerLog, ContainerSnapshot, DnpName, PackageDetails, PackageLogs, PackageRef,
    PackageSummary, PreviewSummary,
};

use super::{PackageManager, PackageManagerError, REQUIRED_MCP_TOOLS, ToolAvailability};

#[derive(Debug, Clone)]
pub struct FakePackageManager {
    state: Arc<Mutex<FakeState>>,
}

#[derive(Debug, Clone, Default)]
struct FakeState {
    installed: Option<(DnpName, String, bool)>,
}

impl FakePackageManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, FakeState>, PackageManagerError> {
        self.state
            .lock()
            .map_err(|_| PackageManagerError::Transport("fake state lock was poisoned".to_owned()))
    }
}

impl Default for FakePackageManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PackageManager for FakePackageManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        Ok(ToolAvailability {
            available: REQUIRED_MCP_TOOLS.iter().map(ToString::to_string).collect(),
            missing: Vec::new(),
        })
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        let installed = self.lock()?.installed.clone();
        let mut packages = vec![PackageSummary {
            dnp_name: DnpName::parse("dappmanager.dnp.dappnode.eth").map_err(|error| {
                PackageManagerError::InvalidResponse {
                    tool: "fake package manager".to_owned(),
                    message: error.to_string(),
                }
            })?,
            version: Some("0.0.0-fake".to_owned()),
            is_core: true,
        }];
        if let Some((dnp_name, version, _)) = installed {
            packages.push(PackageSummary {
                dnp_name,
                version: Some(version),
                is_core: false,
            });
        }
        Ok(packages)
    }

    async fn get_package_details(
        &self,
        dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        let installed = self.lock()?.installed.clone();
        let Some((installed_name, version, running)) = installed else {
            return Err(PackageManagerError::NotFound);
        };
        if &installed_name != dnp_name {
            return Err(PackageManagerError::NotFound);
        }
        Ok(PackageDetails {
            dnp_name: installed_name,
            version: Some(version.clone()),
            containers: vec![ContainerSnapshot {
                name: format!("{}-service", dnp_name.as_str()),
                service_name: Some("service".to_owned()),
                state: Some(if running { "running" } else { "exited" }.to_owned()),
                running,
                image: Some(format!("fake/{dnp_name}:{version}")),
                created: Some("fake".to_owned()),
            }],
        })
    }

    async fn get_package_logs(
        &self,
        dnp_name: &DnpName,
        _tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        let details = self.get_package_details(dnp_name).await?;
        let text = if details.containers.iter().all(|container| container.running) {
            "fake service started normally"
        } else {
            "fatal: fake service stopped"
        };
        Ok(PackageLogs {
            entries: vec![ContainerLog {
                container: details
                    .containers
                    .first()
                    .map(|container| container.name.clone()),
                text: text.to_owned(),
            }],
        })
    }

    async fn preview_install(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        Ok(PreviewSummary {
            package_name: Some(dnp_name.to_string()),
            version: Some(
                version
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "1.0.0-fake-baseline".to_owned()),
            ),
            resolved_ref: version.map(ToString::to_string),
            image_count: Some(1),
            requires_user_input: false,
            summary: "fake install preview".to_owned(),
        })
    }

    async fn install_package(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        if version.is_some_and(|value| value.as_str().contains("required-setup")) {
            return Err(PackageManagerError::RequiredSetup);
        }
        let version = version
            .map(ToString::to_string)
            .unwrap_or_else(|| "1.0.0-fake-baseline".to_owned());
        self.lock()?.installed = Some((dnp_name.clone(), version, true));
        Ok(())
    }

    async fn update_package(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        if version.as_str().contains("install-error") {
            return Err(PackageManagerError::Tool {
                tool: "dappnode_update_package".to_owned(),
                message: "simulated candidate update failure".to_owned(),
            });
        }
        let running = !version.as_str().contains("unstable");
        self.lock()?.installed = Some((dnp_name.clone(), version.to_string(), running));
        Ok(())
    }

    async fn remove_package(
        &self,
        dnp_name: &DnpName,
        _delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        let mut state = self.lock()?;
        if state
            .installed
            .as_ref()
            .is_some_and(|(installed_name, _, _)| installed_name == dnp_name)
        {
            state.installed = None;
        }
        Ok(())
    }
}
