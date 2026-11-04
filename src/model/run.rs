use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    CaptureEvidence, CleanupResult, CleanupStatus, ComparisonEvidence, HarnessResult,
    LogAnalysisResult, ReasonCode, RunError, RunRequest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Queued,
    Running,
    Completed,
    Interrupted,
}

/// Why a worker could not produce a normal harness result.
///
/// These values mirror the small v1 coordinator protocol and are persisted so
/// a restart can deliver the same completion body without rerunning a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    Interrupted,
    UnsupportedJob,
    CleanupFailed,
    LocalPersistenceFailed,
    UnexpectedError,
}

/// A bounded explanation sent to Tropibot when no normal result is available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerError {
    pub code: WorkerErrorCode,
    pub summary: String,
    pub cleanup_status: CleanupStatus,
}

/// Operator action required before the worker may accept another claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualRecoveryKind {
    Cleanup,
    CompletionConflict,
}

/// A hold that keeps the worker paused until an operator resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualRecovery {
    pub kind: ManualRecoveryKind,
    pub reason: String,
}

/// Destructive target state that restart recovery must reconcile.
///
/// It is persisted before the first mutation; until then nothing needs
/// cleanup, so the default only matters for records that never mutated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetRecoveryPlan {
    /// The target did not exist before the run and must be removed.
    #[default]
    Remove,
    /// The target existed before the run and must be freshly installed from
    /// the latest published registry release while preserving its volumes.
    RestoreLatest,
}

/// Delivery state owned by the polling worker.
///
/// `pending_completion_body` contains the exact serialized JSON body that
/// must be retried. It deliberately lives beside the run evidence so one
/// atomic file write captures both the result and the delivery obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkerState {
    /// Opaque coordinator claim token. It is required after a restart to
    /// heartbeat or complete the same claim, so it must be persisted locally.
    pub claim_token: Option<String>,
    /// Becomes true immediately before the worker can mutate the target.
    pub cleanup_required: bool,
    /// Recovery action persisted before target mutation.
    pub target_recovery: TargetRecoveryPlan,
    /// A normal result is mutually exclusive with a worker error.
    pub worker_error: Option<WorkerError>,
    /// Exact UTF-8 completion JSON persisted before its first HTTP attempt.
    pub pending_completion_body: Option<String>,
    pub completion_acknowledged: bool,
    /// `recorded` or `duplicate` once Tropibot has acknowledged delivery.
    pub completion_disposition: Option<String>,
    /// An unresolved cleanup or completion conflict that requires an operator
    /// and keeps the worker out of ready state.
    pub manual_recovery: Option<ManualRecovery>,
}

impl WorkerState {
    pub fn manual_recovery_kind(&self) -> Option<ManualRecoveryKind> {
        self.manual_recovery.as_ref().map(|hold| hold.kind)
    }

    pub fn manual_recovery_reason(&self) -> Option<&str> {
        self.manual_recovery
            .as_ref()
            .map(|hold| hold.reason.as_str())
    }

    pub fn set_manual_recovery(&mut self, kind: ManualRecoveryKind, reason: String) {
        self.manual_recovery = Some(ManualRecovery { kind, reason });
    }

    pub fn clear_manual_recovery(&mut self) {
        self.manual_recovery = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Queued,
    Preflight,
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

impl ExecutionPhase {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Preflight => "Preflight safety checks",
            Self::BaselinePreview => "Baseline preview",
            Self::BaselineInstall => "Baseline installation",
            Self::BaselineStabilization => "Baseline stabilization",
            Self::BaselineCapture => "Baseline evidence capture",
            Self::CandidatePreview => "Candidate preview",
            Self::CandidateInstall => "Candidate upgrade",
            Self::CandidateStabilization => "Candidate stabilization",
            Self::CandidateCapture => "Candidate evidence capture",
            Self::Analysis => "Evidence comparison and analysis",
            Self::Cleanup => "Target cleanup and restoration",
            Self::Reporting => "Result delivery",
            Self::Finished => "Run finished",
        }
    }

    pub fn protocol_name(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Preflight => "preflight",
            Self::BaselinePreview => "baseline_preview",
            Self::BaselineInstall => "baseline_install",
            Self::BaselineStabilization => "baseline_stabilization",
            Self::BaselineCapture => "baseline_capture",
            Self::CandidatePreview => "candidate_preview",
            Self::CandidateInstall => "candidate_install",
            Self::CandidateStabilization => "candidate_stabilization",
            Self::CandidateCapture => "candidate_capture",
            Self::Analysis => "analysis",
            Self::Cleanup => "cleanup",
            Self::Reporting => "completion",
            Self::Finished => "finished",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseTransition {
    pub phase: ExecutionPhase,
    pub at: DateTime<Utc>,
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
    pub result: Option<HarnessResult>,
    #[serde(default)]
    pub worker: WorkerState,
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
            result: None,
            worker: WorkerState::default(),
        }
    }

    /// Creates a record for a job atomically claimed from Tropibot.
    pub fn claimed(request: RunRequest, claim_token: String) -> Self {
        let mut record = Self::new(request);
        record.worker.claim_token = Some(claim_token);
        record
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

    /// Whether this record prevents the process from claiming another job.
    pub fn requires_worker_attention(&self) -> bool {
        self.worker.manual_recovery.is_some()
            || self.worker.pending_completion_body.is_some()
            || self.worker.claim_token.is_some() && !self.worker.completion_acknowledged
    }
}

#[cfg(test)]
mod tests {
    use super::{ManualRecoveryKind, TargetRecoveryPlan, WorkerState};

    #[test]
    fn manual_recovery_keeps_its_kind_with_its_reason() {
        let mut state = WorkerState::default();
        state.set_manual_recovery(
            ManualRecoveryKind::Cleanup,
            "operator verification is required".to_owned(),
        );

        assert_eq!(
            state.manual_recovery_kind(),
            Some(ManualRecoveryKind::Cleanup)
        );
        assert_eq!(
            state.manual_recovery_reason(),
            Some("operator verification is required")
        );
        state.clear_manual_recovery();
        assert_eq!(state.manual_recovery_kind(), None);
        assert!(state.manual_recovery_reason().is_none());
    }

    #[test]
    fn worker_state_serializes_recovery_plan_and_hold() -> Result<(), serde_json::Error> {
        let mut state = WorkerState {
            target_recovery: TargetRecoveryPlan::RestoreLatest,
            ..WorkerState::default()
        };
        state.set_manual_recovery(
            ManualRecoveryKind::CompletionConflict,
            "conflict".to_owned(),
        );

        let json = serde_json::to_value(&state)?;
        assert_eq!(json["targetRecovery"], "restore_latest");
        assert_eq!(json["manualRecovery"]["kind"], "completion_conflict");
        assert_eq!(serde_json::from_value::<WorkerState>(json)?, state);
        Ok(())
    }
}
