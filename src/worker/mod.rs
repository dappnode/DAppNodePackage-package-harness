//! One-at-a-time Tropibot polling worker and local restart recovery.

pub mod heartbeat;
pub mod progress;

use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tracing::{debug, error, info, warn};

use crate::{
    analysis::redaction::redact_and_bound,
    clock::Clock,
    coordinator::{
        ClaimOutcome, ClaimedJob, CompletionDisposition, CompletionOutcome, CoordinatorClient,
        CoordinatorError, WorkerErrorCompletion,
    },
    model::{
        CleanupResult, CleanupStatus, ExecutionStatus, PackageRef, RunRecord, TargetRecoveryPlan,
        WorkerError, WorkerErrorCode,
    },
    package_manager::PackageManager,
    runner::{
        RunController,
        cleanup::{cleanup_target, leftover_packages, restore_target},
    },
    storage::RunStore,
};

use self::{heartbeat::HeartbeatTask, progress::WorkerProgress};

/// Configuration that belongs to the polling worker rather than the package
/// execution algorithm.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub worker_id: String,
    pub harness_dnp_name: String,
    pub poll_interval: Duration,
    pub heartbeat_interval: Duration,
    pub cleanup_timeout: Duration,
}

/// Runtime capabilities required by the polling worker.
///
/// Grouping these stable ports keeps construction explicit without turning the
/// worker constructor into a long positional list as storage evolves.
pub struct WorkerDependencies {
    pub controller: Arc<RunController>,
    pub package_manager: Arc<dyn PackageManager>,
    pub store: Arc<dyn RunStore>,
    pub clock: Arc<dyn Clock>,
}

/// Readiness signal exposed through the local supervision endpoint.
#[derive(Clone, Debug, Default)]
pub struct WorkerReadiness {
    reason: Arc<RwLock<Option<String>>>,
}

impl WorkerReadiness {
    pub fn ready(&self) -> bool {
        self.reason
            .read()
            .map(|reason| reason.is_none())
            .unwrap_or(false)
    }

    pub fn reason(&self) -> Option<String> {
        self.reason.read().ok().and_then(|reason| reason.clone())
    }

    pub fn set_not_ready(&self, reason: impl Into<String>) {
        if let Ok(mut current) = self.reason.write() {
            *current = Some(redact_and_bound(&reason.into(), 500));
        }
    }

    pub fn clear(&self) {
        if let Ok(mut current) = self.reason.write() {
            *current = None;
        }
    }
}

/// Polls Tropibot, drives exactly one local run at a time, and only claims
/// again after the previous completion has been acknowledged.
pub struct PackageHarnessWorker {
    coordinator: CoordinatorClient,
    controller: Arc<RunController>,
    package_manager: Arc<dyn PackageManager>,
    store: Arc<dyn RunStore>,
    clock: Arc<dyn Clock>,
    config: WorkerConfig,
    readiness: WorkerReadiness,
    accepting: Arc<AtomicBool>,
}

impl PackageHarnessWorker {
    pub fn new(
        coordinator: CoordinatorClient,
        dependencies: WorkerDependencies,
        config: WorkerConfig,
        readiness: WorkerReadiness,
        accepting: Arc<AtomicBool>,
    ) -> Self {
        Self {
            coordinator,
            controller: dependencies.controller,
            package_manager: dependencies.package_manager,
            store: dependencies.store,
            clock: dependencies.clock,
            config,
            readiness,
            accepting,
        }
    }

    /// Runs restart reconciliation, then polls until shutdown or an operator
    /// action is needed. Errors that make another claim unsafe become a local
    /// not-ready reason instead of being silently skipped.
    pub async fn run(self) {
        if let Err(error) = self.recover().await {
            self.readiness.set_not_ready(error);
            return;
        }
        self.readiness.clear();
        let mut transient_attempt = 0_u32;
        while self.accepting.load(Ordering::SeqCst) {
            match self.coordinator.claim().await {
                Ok(ClaimOutcome::NoWork) => {
                    transient_attempt = 0;
                    debug!(
                        event = "claim_no_work",
                        poll_interval_seconds = self.config.poll_interval.as_secs(),
                    );
                    tokio::time::sleep(self.config.poll_interval).await;
                }
                Ok(ClaimOutcome::Claimed(job)) => {
                    transient_attempt = 0;
                    info!(
                        event = "claim_succeeded",
                        run_id = %job.request.run_id,
                        dnp_name = %job.request.package.dnp_name,
                    );
                    if let Err(error) = self.process_claim(job).await {
                        error!(
                            event = "claim_processing_failed",
                            error = %error,
                        );
                        self.readiness.set_not_ready(error);
                        return;
                    }
                }
                Err(CoordinatorError::Authentication { status }) => {
                    error!(
                        event = "claim_authentication_failed",
                        status = status.as_u16(),
                    );
                    self.readiness
                        .set_not_ready("Tropibot rejected worker authentication; polling stopped");
                    return;
                }
                Err(CoordinatorError::UnresolvedJob) => {
                    error!(event = "claim_unresolved_job");
                    self.readiness.set_not_ready(
                        "Tropibot reports an unresolved job but no recoverable local record exists",
                    );
                    return;
                }
                Err(error) if error.is_transient() => {
                    transient_attempt = transient_attempt.saturating_add(1);
                    warn!(
                        event = "claim_transient_failure",
                        attempt = transient_attempt,
                        error = %error,
                    );
                    tokio::time::sleep(retry_delay(
                        self.config.poll_interval,
                        transient_attempt,
                        &self.config.worker_id,
                    ))
                    .await;
                }
                Err(error) => {
                    error!(
                        event = "claim_failed",
                        error = %error,
                    );
                    self.readiness
                        .set_not_ready(format!("Tropibot claim failed: {error}"));
                    return;
                }
            }
        }
    }

    async fn process_claim(&self, job: ClaimedJob) -> Result<(), String> {
        let mut record = RunRecord::claimed(job.request, job.claim_token);
        self.store
            .create(&record)
            .await
            .map_err(|error| format!("cannot persist claimed job before execution: {error}"))?;

        let unsupported_job = match self.unsupported_job_reason(&record).await {
            Ok(reason) => reason,
            Err(error) => {
                self.set_worker_error(&mut record, WorkerErrorCode::UnexpectedError, error)
                    .await?;
                return self.deliver_or_require_manual_recovery(&mut record).await;
            }
        };
        if let Some(summary) = unsupported_job {
            self.set_worker_error(&mut record, WorkerErrorCode::UnsupportedJob, summary)
                .await?;
            return self.deliver_or_require_manual_recovery(&mut record).await;
        }

        let progress = WorkerProgress::new();
        let heartbeat = HeartbeatTask::start(
            self.coordinator.clone(),
            record.request.run_id.to_string(),
            record
                .worker
                .claim_token
                .clone()
                .ok_or("claimed record unexpectedly lacks claim token")?,
            Arc::clone(&progress),
            self.config.heartbeat_interval,
        );
        let execution = self
            .controller
            .execute(&record.request.run_id, progress.as_ref())
            .await;
        heartbeat.stop().await;

        record = self
            .store
            .get(&record.request.run_id)
            .await
            .map_err(|error| format!("cannot reload executed job: {error}"))?
            .ok_or("executed job disappeared from local storage")?;

        if let Err(error) = execution {
            error!(run_id = %record.request.run_id, event = "run_worker_error", error = %error);
            if let Err(recovery_error) = self.recover_target_if_required(&mut record).await {
                let reason = self
                    .mark_manual_recovery(
                        &mut record,
                        format!("execution and cleanup recovery failed: {recovery_error}"),
                    )
                    .await?;
                return Err(reason);
            }
            self.set_worker_error(
                &mut record,
                WorkerErrorCode::LocalPersistenceFailed,
                format!("execution stopped before a persisted result: {error}"),
            )
            .await?;
        }

        if progress.claim_lost() {
            if let Err(recovery_error) = self.recover_target_if_required(&mut record).await {
                let reason = self
                    .mark_manual_recovery(
                        &mut record,
                        format!("claim was lost and cleanup recovery failed: {recovery_error}"),
                    )
                    .await?;
                return Err(reason);
            }
            return Err(self
                .mark_manual_recovery(
                    &mut record,
                    "Tropibot no longer recognizes this claim; cleanup was reconciled locally and operator review is required",
                )
                .await?);
        }

        if cleanup_failed(&record) {
            return Err(self
                .mark_manual_recovery(
                    &mut record,
                    "target cleanup failed; operator action is required before another job can be claimed",
                )
                .await?);
        }

        self.deliver_or_require_manual_recovery(&mut record).await
    }

    async fn recover(&self) -> Result<(), String> {
        let records = self
            .store
            .load_all()
            .await
            .map_err(|error| format!("cannot load local worker records: {error}"))?;
        let unresolved = records
            .into_iter()
            .filter(RunRecord::requires_worker_attention)
            .collect::<Vec<_>>();
        if unresolved.len() > 1 {
            return Err(
                "multiple unresolved local jobs exist; operator recovery is required".to_owned(),
            );
        }
        let Some(mut record) = unresolved.into_iter().next() else {
            return Ok(());
        };
        if record.worker.manual_recovery_reason.is_some() {
            return Err(record
                .worker
                .manual_recovery_reason
                .clone()
                .unwrap_or_else(|| "manual recovery is required".to_owned()));
        }
        if record.worker.pending_completion_body.is_some() {
            return self.deliver_or_require_manual_recovery(&mut record).await;
        }
        if record.status == ExecutionStatus::Completed && record.result.is_some() {
            return self.deliver_or_require_manual_recovery(&mut record).await;
        }

        record.interrupt();
        if let Err(recovery_error) = self.recover_target_if_required(&mut record).await {
            let reason = self
                .mark_manual_recovery(
                    &mut record,
                    format!("interrupted job cleanup recovery failed: {recovery_error}"),
                )
                .await?;
            return Err(reason);
        }
        if cleanup_failed(&record) {
            return Err(self
                .mark_manual_recovery(
                    &mut record,
                    "interrupted job cleanup failed; operator action is required",
                )
                .await?);
        }
        self.set_worker_error(
            &mut record,
            WorkerErrorCode::Interrupted,
            "worker restarted before this job completed; the job was not rerun".to_owned(),
        )
        .await?;
        self.deliver_or_require_manual_recovery(&mut record).await
    }

    async fn unsupported_job_reason(&self, record: &RunRecord) -> Result<Option<String>, String> {
        if record.request.package.dnp_name.as_str() == self.config.harness_dnp_name {
            return Ok(Some(
                "refused to test the harness package itself".to_owned(),
            ));
        }
        let packages = self
            .package_manager
            .list_packages()
            .await
            .map_err(|error| format!("cannot validate claimed package safety: {error}"))?;
        if packages
            .iter()
            .any(|package| package.dnp_name == record.request.package.dnp_name && package.is_core)
        {
            return Ok(Some("refused to test a core Dappnode package".to_owned()));
        }
        Ok(None)
    }

    async fn recover_target_if_required(&self, record: &mut RunRecord) -> Result<(), String> {
        if !record.worker.cleanup_required {
            self.store
                .save(record)
                .await
                .map_err(|error| format!("cannot persist recovery state: {error}"))?;
            return Ok(());
        }
        let target = &record.request.package.dnp_name;
        if target.as_str() == self.config.harness_dnp_name {
            return Err("refusing restart cleanup of the harness package".to_owned());
        }
        let packages = self
            .package_manager
            .list_packages()
            .await
            .map_err(|error| format!("cannot inspect target during restart recovery: {error}"))?;
        if packages
            .iter()
            .any(|package| package.dnp_name == *target && package.is_core)
        {
            return Err("refusing restart cleanup of a core package".to_owned());
        }
        let recovery_plan = record.worker.recovery_plan();
        let retained_target = matches!(
            recovery_plan,
            TargetRecoveryPlan::Restore { retained: true, .. }
        )
        .then_some(target);
        record.cleanup = match recovery_plan {
            TargetRecoveryPlan::Restore { baseline_ref, .. } => {
                let baseline_ref = PackageRef::parse(&baseline_ref)
                    .map_err(|error| format!("saved baseline reference is invalid: {error}"))?;
                restore_target(
                    self.package_manager.as_ref(),
                    Arc::clone(&self.clock),
                    target,
                    &baseline_ref,
                    self.config.cleanup_timeout,
                )
                .await
            }
            TargetRecoveryPlan::Remove => {
                if packages.iter().any(|package| package.dnp_name == *target) {
                    cleanup_target(
                        self.package_manager.as_ref(),
                        Arc::clone(&self.clock),
                        target,
                        self.config.cleanup_timeout,
                    )
                    .await
                } else {
                    CleanupResult {
                        status: CleanupStatus::Passed,
                        leftover_packages: Vec::new(),
                        error: None,
                    }
                }
            }
        };
        match self.package_manager.list_packages().await {
            Ok(final_packages) => {
                record.cleanup.leftover_packages = leftover_packages(
                    &record.evidence.initial_packages,
                    &final_packages,
                    retained_target,
                );
                if record.cleanup.status == CleanupStatus::Passed
                    && !record.cleanup.leftover_packages.is_empty()
                {
                    record.cleanup.status = CleanupStatus::Failed;
                    record.cleanup.error = Some(redact_and_bound(
                        &format!(
                            "restart cleanup left packages that were not present before the run: {}",
                            record.cleanup.leftover_packages.join(", ")
                        ),
                        300,
                    ));
                }
                record.evidence.final_packages = final_packages;
            }
            Err(error) => {
                if record.cleanup.status == CleanupStatus::Passed {
                    record.cleanup.status = CleanupStatus::Failed;
                }
                if record.cleanup.error.is_none() {
                    record.cleanup.error = Some(redact_and_bound(&error.to_string(), 300));
                }
            }
        }
        self.store
            .save(record)
            .await
            .map_err(|error| format!("cannot persist restart cleanup result: {error}"))?;
        Ok(())
    }

    async fn set_worker_error(
        &self,
        record: &mut RunRecord,
        code: WorkerErrorCode,
        summary: String,
    ) -> Result<(), String> {
        record.worker.worker_error = Some(WorkerError {
            code,
            summary: redact_and_bound(&summary, 500),
            cleanup_status: worker_error_cleanup_status(record),
        });
        self.store
            .save(record)
            .await
            .map_err(|error| format!("cannot persist worker error: {error}"))
    }

    async fn deliver_until_terminal(&self, record: &mut RunRecord) -> Result<(), String> {
        if record.worker.completion_acknowledged {
            return Ok(());
        }
        self.prepare_completion(record).await?;
        let mut transient_attempt = 0_u32;
        loop {
            let body = record
                .worker
                .pending_completion_body
                .as_ref()
                .ok_or("pending completion unexpectedly missing")?
                .as_bytes()
                .to_vec();
            match self
                .coordinator
                .complete_raw(&record.request.run_id.to_string(), body)
                .await
            {
                Ok(disposition) => {
                    record.worker.completion_acknowledged = true;
                    record.worker.completion_disposition = Some(match disposition {
                        CompletionDisposition::Recorded => "recorded".to_owned(),
                        CompletionDisposition::Duplicate => "duplicate".to_owned(),
                    });
                    record.worker.pending_completion_body = None;
                    self.store.save(record).await.map_err(|error| {
                        format!("cannot persist completion acknowledgement: {error}")
                    })?;
                    info!(
                        run_id = %record.request.run_id,
                        event = "completion_acknowledged",
                        disposition = ?record.worker.completion_disposition
                    );
                    return Ok(());
                }
                Err(error) if error.is_transient() => {
                    transient_attempt = transient_attempt.saturating_add(1);
                    warn!(
                        run_id = %record.request.run_id,
                        event = "completion_transient_failure",
                        attempt = transient_attempt,
                        error = %error,
                    );
                    tokio::time::sleep(retry_delay(
                        self.config.poll_interval,
                        transient_attempt,
                        &self.config.worker_id,
                    ))
                    .await;
                }
                Err(CoordinatorError::Authentication { status }) => {
                    error!(
                        run_id = %record.request.run_id,
                        event = "completion_authentication_failed",
                        status = status.as_u16(),
                    );
                    return Err(
                        "Tropibot rejected worker authentication while completing a job".to_owned(),
                    );
                }
                Err(CoordinatorError::CompletionConflict { status, .. }) => {
                    error!(
                        run_id = %record.request.run_id,
                        event = "completion_conflict",
                        status = status.as_u16(),
                    );
                    return Err("Tropibot rejected the persisted completion as conflicting; operator recovery is required".to_owned());
                }
                Err(error) => {
                    error!(
                        run_id = %record.request.run_id,
                        event = "completion_failed",
                        error = %error,
                    );
                    return Err(format!("Tropibot completion failed: {error}"));
                }
            }
        }
    }

    async fn deliver_or_require_manual_recovery(
        &self,
        record: &mut RunRecord,
    ) -> Result<(), String> {
        match self.deliver_until_terminal(record).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.mark_manual_recovery(record, error).await?),
        }
    }

    async fn mark_manual_recovery(
        &self,
        record: &mut RunRecord,
        reason: impl AsRef<str>,
    ) -> Result<String, String> {
        let reason = redact_and_bound(reason.as_ref(), 500);
        record.worker.manual_recovery_reason = Some(reason.clone());
        self.store.save(record).await.map_err(|store_error| {
            format!("cannot persist manual recovery requirement: {store_error}")
        })?;
        Ok(reason)
    }

    async fn prepare_completion(&self, record: &mut RunRecord) -> Result<(), String> {
        if record.worker.pending_completion_body.is_some() {
            return Ok(());
        }
        let claim_token = record
            .worker
            .claim_token
            .clone()
            .ok_or("local record lacks a claim token required for completion")?;
        let outcome = match (&record.result, &record.worker.worker_error) {
            (Some(result), None) if result.run_id == record.request.run_id.to_string() => {
                CompletionOutcome::Result {
                    result: Box::new(result.clone()),
                }
            }
            (None, Some(error)) => {
                CompletionOutcome::WorkerError(WorkerErrorCompletion::from(error))
            }
            (Some(_), None) => {
                return Err("persisted result runId does not match the claimed job".to_owned());
            }
            (None, None) => {
                return Err(
                    "no normal result or worker error is available for completion".to_owned(),
                );
            }
            (Some(_), Some(_)) => {
                return Err("record contains both a normal result and worker error".to_owned());
            }
        };
        let body = serde_json::to_string(&crate::coordinator::protocol::CompleteRequest {
            schema_version: 1,
            worker_id: self.config.worker_id.clone(),
            claim_token,
            outcome,
        })
        .map_err(|error| format!("cannot serialize completion body: {error}"))?;
        record.worker.pending_completion_body = Some(body);
        self.store
            .save(record)
            .await
            .map_err(|error| format!("cannot persist completion body: {error}"))
    }
}

fn cleanup_failed(record: &RunRecord) -> bool {
    matches!(
        record.cleanup.status,
        CleanupStatus::Failed | CleanupStatus::TimedOut
    )
}

fn worker_error_cleanup_status(record: &RunRecord) -> CleanupStatus {
    if record.cleanup.status == CleanupStatus::Pending && !record.worker.cleanup_required {
        CleanupStatus::Skipped
    } else {
        record.cleanup.status
    }
}

fn retry_delay(base: Duration, attempt: u32, worker_id: &str) -> Duration {
    let exponent = attempt.saturating_sub(1).min(5);
    let cap = Duration::from_secs(30);
    let scaled = base.saturating_mul(1_u32 << exponent).min(cap);
    let seed = worker_id.bytes().fold(attempt, |value, byte| {
        value.wrapping_mul(31).wrapping_add(byte as u32)
    });
    scaled.saturating_add(Duration::from_millis((seed % 251) as u64))
}
