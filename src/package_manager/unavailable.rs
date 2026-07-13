use async_trait::async_trait;

use crate::model::{
    DnpName, PackageDetails, PackageLogs, PackageRef, PackageSummary, PreviewSummary,
};

use super::{PackageManager, PackageManagerError, ToolAvailability};

#[derive(Debug, Clone)]
pub struct UnavailablePackageManager {
    message: String,
}

impl UnavailablePackageManager {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn error(&self) -> PackageManagerError {
        PackageManagerError::Transport(self.message.clone())
    }
}

#[async_trait]
impl PackageManager for UnavailablePackageManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        Err(self.error())
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        Err(self.error())
    }

    async fn get_package_details(
        &self,
        _dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        Err(self.error())
    }

    async fn get_package_logs(
        &self,
        _dnp_name: &DnpName,
        _tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        Err(self.error())
    }

    async fn preview_install(
        &self,
        _dnp_name: &DnpName,
        _version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        Err(self.error())
    }

    async fn install_package(
        &self,
        _dnp_name: &DnpName,
        _version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        Err(self.error())
    }

    async fn update_package(
        &self,
        _dnp_name: &DnpName,
        _version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        Err(self.error())
    }

    async fn remove_package(
        &self,
        _dnp_name: &DnpName,
        _delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        Err(self.error())
    }
}
