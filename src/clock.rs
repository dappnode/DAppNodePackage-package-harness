use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Time source used by runner code.
///
/// Keeping time behind a trait lets tests advance stabilization and cleanup
/// loops without sleeping in real time.
#[async_trait]
pub trait Clock: Send + Sync {
    /// Returns the current UTC timestamp.
    fn now(&self) -> DateTime<Utc>;

    /// Suspends execution for the requested duration.
    async fn sleep(&self, duration: Duration);
}

/// Production clock backed by Tokio timers.
#[derive(Debug, Default)]
pub struct TokioClock;

#[async_trait]
impl Clock for TokioClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}
