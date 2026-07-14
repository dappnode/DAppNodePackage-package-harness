use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    model::ExecutionPhase,
    runner::{RunControl, RunProgress},
};

/// Latest locally persisted execution state observed by the heartbeat task.
#[derive(Debug, Clone, Copy)]
pub struct ProgressSnapshot {
    pub phase: ExecutionPhase,
    pub cleanup_required: bool,
}

/// In-memory bridge between the runner and the independent heartbeat task.
#[derive(Debug)]
pub struct WorkerProgress {
    snapshot: Mutex<ProgressSnapshot>,
    cancel_requested: AtomicBool,
    claim_lost: AtomicBool,
}

impl WorkerProgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            snapshot: Mutex::new(ProgressSnapshot {
                phase: ExecutionPhase::Queued,
                cleanup_required: false,
            }),
            cancel_requested: AtomicBool::new(false),
            claim_lost: AtomicBool::new(false),
        })
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        self.snapshot
            .lock()
            .map(|snapshot| *snapshot)
            .unwrap_or(ProgressSnapshot {
                phase: ExecutionPhase::Queued,
                cleanup_required: true,
            })
    }

    pub fn request_cancellation(&self) {
        self.cancel_requested.store(true, Ordering::SeqCst);
    }

    pub fn mark_claim_lost(&self) {
        self.claim_lost.store(true, Ordering::SeqCst);
    }

    pub fn claim_lost(&self) -> bool {
        self.claim_lost.load(Ordering::SeqCst)
    }
}

impl RunProgress for WorkerProgress {
    fn publish(&self, phase: ExecutionPhase, cleanup_required: bool) {
        if let Ok(mut snapshot) = self.snapshot.lock() {
            *snapshot = ProgressSnapshot {
                phase,
                cleanup_required,
            };
        }
    }

    fn control(&self) -> RunControl {
        if self.claim_lost.load(Ordering::SeqCst) {
            RunControl::ClaimLost
        } else if self.cancel_requested.load(Ordering::SeqCst) {
            RunControl::CancelRequested
        } else {
            RunControl::Continue
        }
    }
}
