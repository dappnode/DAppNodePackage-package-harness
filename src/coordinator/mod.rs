//! Typed boundary for the Tropibot worker protocol.
//!
//! The worker talks to exactly three coordinator endpoints. Keeping their DTOs
//! and HTTP behavior here prevents protocol details from leaking into the
//! package execution controller.

pub mod client;
pub mod protocol;

pub use client::{
    ClaimOutcome, CompletionDisposition, CoordinatorClient, CoordinatorError, HeartbeatOutcome,
};
pub use protocol::{ClaimedJob, CompletionOutcome, WorkerErrorCompletion};
