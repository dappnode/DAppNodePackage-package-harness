use serde::{Deserialize, Serialize};

use super::{ComparisonEvidence, ContainerSnapshot, ReasonCode, RunRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Passed,
    Failed,
    Warning,
    Inconclusive,
    InfrastructureError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerStatus {
    Clean,
    Suspicious,
    Critical,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerKind {
    Heuristic,
    Nexus,
    Composite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalysisSide {
    pub status: AnalyzerStatus,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogFinding {
    pub severity: FindingSeverity,
    pub container: Option<String>,
    pub evidence: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogAnalysisResult {
    pub analyzer: AnalyzerKind,
    pub status: AnalyzerStatus,
    pub summary: String,
    pub baseline: AnalysisSide,
    pub candidate: AnalysisSide,
    pub new_findings: Vec<LogFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub analyzer_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<AnalyzerComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzerComponent {
    pub analyzer: AnalyzerKind,
    pub status: AnalyzerStatus,
    pub summary: String,
    pub new_findings: Vec<LogFinding>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LogAnalysisInput {
    pub baseline: Vec<(Option<String>, String)>,
    pub candidate: Vec<(Option<String>, String)>,
    pub context: Option<LogCollectionContext>,
}

/// Deterministic collection facts supplied alongside bounded log windows.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogCollectionContext {
    pub baseline_stable: bool,
    pub candidate_stable: bool,
    pub baseline_expected_containers: usize,
    pub candidate_expected_containers: usize,
    pub baseline_log_error: Option<String>,
    pub candidate_log_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessResult {
    pub schema_version: u8,
    pub run_id: String,
    pub source: ResultSource,
    pub package: ResultPackage,
    pub execution: ResultExecution,
    pub verdict: Verdict,
    pub reason_code: ReasonCode,
    pub summary: String,
    pub baseline: ResultSide,
    pub candidate: ResultSide,
    pub comparison: ComparisonEvidence,
    pub log_analysis: LogAnalysisResult,
    pub cleanup: CleanupResult,
    pub errors: Vec<RunError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSource {
    pub repository: String,
    pub pull_request: u64,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultPackage {
    pub dnp_name: String,
    pub baseline_requested_ref: Option<String>,
    pub baseline_resolved_version: Option<String>,
    pub candidate_ref: String,
    pub candidate_reported_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultExecution {
    pub status: super::ExecutionStatus,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSide {
    pub install: InstallResult,
    pub hard_check: HardCheckResult,
    pub containers: Vec<ReportedContainer>,
    pub log_collection: LogCollectionResult,
}

/// Preserve the v1 coordinator container shape; richer readiness metadata stays
/// in local capture diagnostics until the coordinator protocol supports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportedContainer {
    pub name: String,
    pub service_name: Option<String>,
    pub state: Option<String>,
    pub running: bool,
    pub image: Option<String>,
    pub created: Option<String>,
}

impl From<&ContainerSnapshot> for ReportedContainer {
    fn from(container: &ContainerSnapshot) -> Self {
        Self {
            name: container.name.clone(),
            service_name: container.service_name.clone(),
            state: container.state.clone(),
            running: container.running,
            image: container.image.clone(),
            created: container.created.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallResult {
    pub status: super::StepStatus,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardCheckResult {
    pub passed: bool,
    pub reason_codes: Vec<ReasonCode>,
    pub container_count: usize,
    pub stable_samples: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogCollectionResult {
    pub status: super::StepStatus,
    pub container_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    #[default]
    Pending,
    Passed,
    Failed,
    TimedOut,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CleanupResult {
    pub status: CleanupStatus,
    pub leftover_packages: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunError {
    pub code: ReasonCode,
    pub message: String,
    pub phase: super::ExecutionPhase,
}

impl ResultSource {
    pub fn from_request(request: &RunRequest) -> Self {
        Self {
            repository: request.source.repository.to_string(),
            pull_request: request.source.pull_request,
            head_sha: request.source.head_sha.to_string(),
        }
    }
}
