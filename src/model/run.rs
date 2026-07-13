use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    CaptureEvidence, CleanupResult, ComparisonEvidence, HarnessResult, LogAnalysisResult,
    ReasonCode, RunError, RunRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    Running,
    Completed,
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Queued,
    Preflight,
    InitialCleanup,
    BaselinePreview,
    BaselineInstall,
    BaselineStabilization,
    BaselineCapture,
    CandidatePreview,
    CandidateInstall,
    CandidateStabilization,
    CandidateCapture,
    Analysis,
    Cleanup,
    Reporting,
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseTransition {
    pub phase: ExecutionPhase,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    #[default]
    Pending,
    Delivered,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReportState {
    pub status: ReportStatus,
    pub attempts: u8,
    pub last_error: Option<String>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RunEvidence {
    pub initial_packages: Vec<super::PackageSummary>,
    pub final_packages: Vec<super::PackageSummary>,
    pub baseline: Option<CaptureEvidence>,
    pub candidate: Option<CaptureEvidence>,
    pub comparison: Option<ComparisonEvidence>,
    pub log_analysis: Option<LogAnalysisResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRecord {
    pub request: RunRequest,
    pub status: ExecutionStatus,
    pub phase: ExecutionPhase,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub phase_history: Vec<PhaseTransition>,
    pub evidence: RunEvidence,
    pub errors: Vec<RunError>,
    pub cleanup: CleanupResult,
    pub report: ReportState,
    pub result: Option<HarnessResult>,
}

impl RunRecord {
    pub fn new(request: RunRequest) -> Self {
        let now = Utc::now();
        Self {
            request,
            status: ExecutionStatus::Queued,
            phase: ExecutionPhase::Queued,
            created_at: now,
            started_at: None,
            finished_at: None,
            phase_history: vec![PhaseTransition {
                phase: ExecutionPhase::Queued,
                at: now,
            }],
            evidence: RunEvidence::default(),
            errors: Vec::new(),
            cleanup: CleanupResult::default(),
            report: ReportState::default(),
            result: None,
        }
    }

    pub fn transition(&mut self, phase: ExecutionPhase) {
        self.phase = phase;
        self.phase_history.push(PhaseTransition {
            phase,
            at: Utc::now(),
        });
    }

    pub fn start(&mut self) {
        self.status = ExecutionStatus::Running;
        self.started_at = Some(Utc::now());
    }

    pub fn interrupt(&mut self) {
        self.status = ExecutionStatus::Interrupted;
        self.finished_at = Some(Utc::now());
        self.errors.push(RunError {
            code: ReasonCode::InterruptedOnRestart,
            message: "run was active when the harness restarted; it was not repeated".to_owned(),
            phase: self.phase,
        });
    }
}
