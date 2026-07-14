use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tracing::{debug, warn};

use crate::coordinator::{CoordinatorClient, CoordinatorError, HeartbeatOutcome};

use super::progress::WorkerProgress;

/// Independent heartbeat loop. It only updates in-memory controls; the runner
/// continues its mandatory cleanup even if a heartbeat is slow or unavailable.
pub struct HeartbeatTask {
    stop: Arc<AtomicBool>,
    join: tokio::task::JoinHandle<()>,
}

impl HeartbeatTask {
    pub fn start(
        coordinator: CoordinatorClient,
        job_id: String,
        claim_token: String,
        progress: Arc<WorkerProgress>,
        interval: Duration,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let join = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                if task_stop.load(Ordering::SeqCst) {
                    return;
                }
                let snapshot = progress.snapshot();
                match coordinator
                    .heartbeat(
                        &job_id,
                        &claim_token,
                        heartbeat_phase(snapshot.phase),
                        snapshot.cleanup_required,
                    )
                    .await
                {
                    Ok(HeartbeatOutcome::Continue) => {}
                    Ok(HeartbeatOutcome::CancelRequested) => progress.request_cancellation(),
                    Ok(HeartbeatOutcome::ClaimLost) => progress.mark_claim_lost(),
                    Err(error @ CoordinatorError::Authentication { .. }) => {
                        warn!(run_id = %job_id, event = "heartbeat_authentication_failed", error = %error);
                    }
                    Err(error) => {
                        debug!(run_id = %job_id, event = "heartbeat_failed", error = %error);
                    }
                }
            }
        });
        Self { stop, join }
    }

    pub async fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        self.join.abort();
        let _ = self.join.await;
    }
}

fn heartbeat_phase(phase: crate::model::ExecutionPhase) -> &'static str {
    match phase {
        crate::model::ExecutionPhase::Queued => "queued",
        crate::model::ExecutionPhase::Preflight => "preflight",
        crate::model::ExecutionPhase::InitialCleanup => "initial_cleanup",
        crate::model::ExecutionPhase::BaselinePreview => "baseline_preview",
        crate::model::ExecutionPhase::BaselineInstall => "baseline_install",
        crate::model::ExecutionPhase::BaselineStabilization => "baseline_stabilization",
        crate::model::ExecutionPhase::BaselineCapture => "baseline_capture",
        crate::model::ExecutionPhase::CandidatePreview => "candidate_preview",
        crate::model::ExecutionPhase::CandidateInstall => "candidate_install",
        crate::model::ExecutionPhase::CandidateStabilization => "candidate_stabilization",
        crate::model::ExecutionPhase::CandidateCapture => "candidate_capture",
        crate::model::ExecutionPhase::Analysis => "analysis",
        crate::model::ExecutionPhase::Cleanup => "cleanup",
        crate::model::ExecutionPhase::Reporting => "completion",
        crate::model::ExecutionPhase::Finished => "finished",
    }
}
