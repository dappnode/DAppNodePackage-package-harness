use crate::model::ExecutionPhase;

/// A safe boundary observed by the execution controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunControl {
    Continue,
    CancelRequested,
    ClaimLost,
}

/// Narrow worker-facing port for progress and cancellation.
///
/// The controller only publishes local state and checks an in-memory control
/// signal. The Tropibot HTTP client runs independently in the worker, so a
/// slow heartbeat can never delay package cleanup.
pub trait RunProgress: Send + Sync {
    fn publish(&self, phase: ExecutionPhase, cleanup_required: bool);
    fn control(&self) -> RunControl;
}

/// Useful for direct controller tests and embedding the runner without a
/// coordinator worker.
#[derive(Debug, Default)]
pub struct NoopRunProgress;

impl RunProgress for NoopRunProgress {
    fn publish(&self, _phase: ExecutionPhase, _cleanup_required: bool) {}

    fn control(&self) -> RunControl {
        RunControl::Continue
    }
}
