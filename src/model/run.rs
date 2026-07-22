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

/// Destructive target state that restart recovery must reconcile.
///
/// This is persisted before each mutation. It replaces the ambiguous
/// `cleanup_required + optional baseline` convention with an explicit action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TargetRecoveryPlan {
    /// The target did not exist before the run and must be removed.
    Remove,
    /// Return the target to an exact baseline. `retained` records that the
    /// harness intentionally keeps a newly installed baseline as a local cache.
    Restore {
        baseline_ref: String,
        #[serde(default)]
        retained: bool,
    },
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
    /// Explicit recovery action persisted before target mutation.
    #[serde(default)]
    pub target_recovery: Option<TargetRecoveryPlan>,
    /// Exact package reference that was installed before this run. When set,
    /// cleanup restores this package instead of removing it. Kept only for
    /// backward-compatible recovery of records written by harness 0.1.1.
    #[serde(default)]
    pub baseline_restore_ref: Option<String>,
    /// A normal result is mutually exclusive with a worker error.
    pub worker_error: Option<WorkerError>,
    /// Exact UTF-8 completion JSON persisted before its first HTTP attempt.
    pub pending_completion_body: Option<String>,
    pub completion_acknowledged: bool,
    /// `recorded` or `duplicate` once Tropibot has acknowledged delivery.
    pub completion_disposition: Option<String>,
    /// An unresolved cleanup or claim-reconciliation issue that requires an
    /// operator and keeps the worker out of ready state.
    pub manual_recovery_reason: Option<String>,
}

impl WorkerState {
    /// Returns the explicit plan, falling back to the legacy restore field for
    /// records persisted by older harness versions.
    pub fn recovery_plan(&self) -> TargetRecoveryPlan {
        self.target_recovery.clone().unwrap_or_else(|| {
            self.baseline_restore_ref
                .as_ref()
                .map_or(TargetRecoveryPlan::Remove, |baseline_ref| {
                    TargetRecoveryPlan::Restore {
                        baseline_ref: baseline_ref.clone(),
                        retained: false,
                    }
                })
        })
    }

    pub fn set_recovery_plan(&mut self, plan: TargetRecoveryPlan) {
        self.baseline_restore_ref = match &plan {
            TargetRecoveryPlan::Restore { baseline_ref, .. } => Some(baseline_ref.clone()),
            TargetRecoveryPlan::Remove => None,
        };
        self.target_recovery = Some(plan);
    }
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
        self.worker.manual_recovery_reason.is_some()
            || self.worker.pending_completion_body.is_some()
            || self.worker.claim_token.is_some() && !self.worker.completion_acknowledged
    }
}
