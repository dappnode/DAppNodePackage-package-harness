use serde::{Deserialize, Serialize};

use super::DnpName;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageSummary {
    pub dnp_name: DnpName,
    pub version: Option<String>,
    pub is_core: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSnapshot {
    pub name: String,
    pub service_name: Option<String>,
    pub state: Option<String>,
    pub running: bool,
    pub image: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageDetails {
    pub dnp_name: DnpName,
    pub version: Option<String>,
    pub containers: Vec<ContainerSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerLog {
    pub container: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageLogs {
    pub entries: Vec<ContainerLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewSummary {
    pub package_name: Option<String>,
    pub version: Option<String>,
    /// Exact immutable reference resolved by DAppManager. Used only while
    /// building the local rollback plan, not as persisted test evidence.
    #[serde(skip)]
    pub resolved_ref: Option<String>,
    pub image_count: Option<usize>,
    pub requires_user_input: bool,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StabilizationSample {
    pub observed_at: String,
    pub container_names: Vec<String>,
    pub all_running: bool,
    pub non_running_states: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StabilizationResult {
    pub passed: bool,
    pub stable_samples: usize,
    pub duration_ms: u64,
    pub samples: Vec<StabilizationSample>,
    pub last_non_running_states: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEvidence {
    pub install_status: StepStatus,
    pub install_duration_ms: u64,
    pub preview: Option<PreviewSummary>,
    pub details: Option<PackageDetails>,
    pub stabilization: StabilizationResult,
    pub logs: Option<PackageLogs>,
    pub log_error: Option<String>,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonEvidence {
    pub baseline_hard_check: bool,
    pub candidate_hard_check: bool,
    pub baseline_containers: Vec<String>,
    pub candidate_containers: Vec<String>,
    pub containers_added: Vec<String>,
    pub containers_removed: Vec<String>,
    pub baseline_version: Option<String>,
    pub candidate_version: Option<String>,
    pub baseline_stabilization_ms: u64,
    pub candidate_stabilization_ms: u64,
    pub baseline_last_non_running_states: Vec<String>,
    pub candidate_last_non_running_states: Vec<String>,
    pub baseline_logs_collected: bool,
    pub candidate_logs_collected: bool,
    pub deterministic_regressions: Vec<String>,
}
