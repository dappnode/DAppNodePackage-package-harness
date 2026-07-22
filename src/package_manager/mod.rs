//! Package operations used by the runner.
//!
//! Implementations translate this small capability surface to either the real
//! Dappmanager MCP tools or a deterministic local fake.

use async_trait::async_trait;
use thiserror::Error;

use crate::model::{
    DnpName, PackageDetails, PackageLogs, PackageRef, PackageSummary, PreviewSummary,
};

pub mod dappmanager;
pub mod fake;
pub mod unavailable;

pub use dappmanager::DappmanagerPackageManager;
pub use fake::FakePackageManager;
pub use unavailable::UnavailablePackageManager;

/// MCP tools the real Dappmanager implementation needs before accepting runs.
pub const REQUIRED_MCP_TOOLS: [&str; 7] = [
    "dappnode_list_packages",
    "dappnode_get_package_details",
    "dappnode_get_package_logs",
    "dappnode_fetch_install_preview",
    "dappnode_install_package",
    "dappnode_update_package",
    "dappnode_remove_package",
];

/// Required tools that mutate packages or Docker state.
pub const MUTATING_MCP_TOOLS: [&str; 3] = [
    "dappnode_install_package",
    "dappnode_update_package",
    "dappnode_remove_package",
];

/// Result of checking the Dappmanager MCP tool inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAvailability {
    pub available: Vec<String>,
    pub missing: Vec<String>,
}

impl ToolAvailability {
    /// True when every required tool is available.
    pub fn ready(&self) -> bool {
        self.missing.is_empty()
    }

    /// Human-readable readiness message suitable for `/readyz`.
    pub fn message(&self) -> String {
        if self.ready() {
            return "all required Dappmanager MCP tools are available".to_owned();
        }
        let mutating_missing = self
            .missing
            .iter()
            .any(|tool| MUTATING_MCP_TOOLS.contains(&tool.as_str()));
        if mutating_missing {
            format!(
                "required MCP tools are missing: {}; external MCP mutating tools are probably disabled",
                self.missing.join(", ")
            )
        } else {
            format!(
                "required MCP tools are missing: {}",
                self.missing.join(", ")
            )
        }
    }
}

/// Error raised while talking to or interpreting the package manager.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PackageManagerError {
    #[error("MCP transport failure: {0}")]
    Transport(String),
    #[error("MCP tool '{tool}' timed out")]
    Timeout { tool: String },
    #[error("MCP tool '{tool}' failed: {message}")]
    Tool { tool: String, message: String },
    #[error("MCP tool '{tool}' returned invalid data: {message}")]
    InvalidResponse { tool: String, message: String },
    #[error("package requires setup values that the proof of concept cannot supply")]
    RequiredSetup,
    #[error("package was not found")]
    NotFound,
}

impl PackageManagerError {
    /// Whether repeating a package mutation may recover from this failure.
    pub fn is_transient_mutation_failure(&self) -> bool {
        match self {
            Self::Timeout { .. } => true,
            Self::Transport(message) => retryable_transport_message(message),
            Self::Tool { message, .. } => retryable_tool_message(message),
            Self::InvalidResponse { .. } | Self::RequiredSetup | Self::NotFound => false,
        }
    }
}

pub(crate) fn retryable_transport_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    !lower.contains("401")
        && !lower.contains("403")
        && !lower.contains("unauthorized")
        && !lower.contains("forbidden")
        && !lower.contains("not_logged_in")
}

pub(crate) fn retryable_tool_message(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    [
        "can't download",
        "cannot download",
        "could not get block",
        "failed to fetch",
        "connection reset",
        "econnreset",
        "socket hang up",
        "temporarily unavailable",
        "timed out",
        "timeout",
        "terminated",
    ]
    .iter()
    .any(|signature| lower.contains(signature))
}

/// Capability surface required to install, observe, and clean up a package.
#[async_trait]
pub trait PackageManager: Send + Sync {
    /// Checks whether the implementation has the required mutating and read-only tools.
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError>;

    /// Lists currently installed packages.
    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError>;

    /// Returns package metadata and container state.
    async fn get_package_details(
        &self,
        dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError>;

    /// Returns recent package logs, usually bounded by `tail` lines per container.
    async fn get_package_logs(
        &self,
        dnp_name: &DnpName,
        tail: usize,
    ) -> Result<PackageLogs, PackageManagerError>;

    /// Returns Dappmanager's preview for installing a package version.
    async fn preview_install(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError>;

    /// Installs the baseline version, or the default registry version when `version` is absent.
    async fn install_package(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError>;

    /// Updates an installed package to the candidate reference.
    async fn update_package(
        &self,
        dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError>;

    /// Removes the package after a run.
    async fn remove_package(
        &self,
        dnp_name: &DnpName,
        delete_volumes: bool,
    ) -> Result<(), PackageManagerError>;
}
