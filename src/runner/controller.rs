use std::{sync::Arc, time::Duration};

use chrono::Utc;
use thiserror::Error;
use tracing::{error, info};

use crate::{
    analysis::{
        LogAnalyzer,
        redaction::{redact_and_bound, truncate_utf8},
    },
    clock::Clock,
    model::{
        AnalysisSide, AnalyzerKind, AnalyzerStatus, CaptureEvidence, CleanupStatus,
        ComparisonEvidence, ExecutionPhase, ExecutionStatus, HardCheckResult, HarnessResult,
        InstallResult, LogAnalysisInput, LogAnalysisResult, LogCollectionResult, PackageResolver,
        ReasonCode, ResultExecution, ResultPackage, ResultSide, ResultSource, RunError, RunId,
        RunRecord, StabilizationResult, StepStatus, Verdict,
    },
    package_manager::{PackageManager, PackageManagerError},
    runner::{
        cleanup::{cleanup_target, leftover_packages, restore_target},
        comparison::{compare, deterministic_verdict},
        progress::{RunControl, RunProgress},
        stabilization::{StabilizationConfig, stabilize},
    },
    storage::{RunStore, StoreError},
};

/// Runtime policy for one package test execution.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Harness package name, refused as a target to avoid self-removal.
    pub harness_dnp_name: String,
    /// Container stabilization hard-check policy.
    pub stabilization: StabilizationConfig,
    /// Number of log lines requested from the package manager.
    pub log_tail: usize,
    /// Whether cleanup removes the target package after a run.
    pub cleanup_enabled: bool,
    /// Maximum time spent trying to remove the target package.
    pub cleanup_timeout: Duration,
}

/// Error returned to API code when a run cannot be driven.
#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("run does not exist")]
    NotFound,
    #[error("persistence failed: {0}")]
    Persistence(String),
}

#[derive(Debug)]
struct Failure {
    verdict: Verdict,
    reason: ReasonCode,
    summary: String,
}

/// Coordinates one run from queued record to persisted final result.
pub struct RunController {
    package_manager: Arc<dyn PackageManager>,
    analyzer: Arc<dyn LogAnalyzer>,
    store: Arc<dyn RunStore>,
    resolver: Arc<dyn PackageResolver>,
    clock: Arc<dyn Clock>,
    config: RunnerConfig,
}

impl RunController {
    /// Creates a controller from its runtime capabilities.
    pub fn new(
        package_manager: Arc<dyn PackageManager>,
        analyzer: Arc<dyn LogAnalyzer>,
        store: Arc<dyn RunStore>,
        resolver: Arc<dyn PackageResolver>,
        clock: Arc<dyn Clock>,
        config: RunnerConfig,
    ) -> Self {
        Self {
            package_manager,
            analyzer,
            store,
            resolver,
            clock,
            config,
        }
    }

    /// Executes a queued run exactly once.
    ///
    /// The runner persists after phase transitions and evidence capture so an
    /// interrupted process can explain what happened on the next startup.
    pub async fn execute(
        &self,
        run_id: &RunId,
        progress: &dyn RunProgress,
    ) -> Result<(), ControllerError> {
        let mut record = self
            .store
            .get(run_id)
            .await
            .map_err(store_error)?
            .ok_or(ControllerError::NotFound)?;
        if record.status != ExecutionStatus::Queued {
            return Ok(());
        }
        record.start();
        self.save(&record).await?;
        progress.publish(record.phase, record.worker.cleanup_required);
        let package = self.resolver.resolve(&record.request);
        let mut cleanup_authorized = false;

        let algorithm_result = self
            .run_algorithm(&mut record, &mut cleanup_authorized, progress)
            .await;
        let failure = match algorithm_result {
            Ok(()) => None,
            Err(failure) => {
                record.errors.push(RunError {
                    code: failure.reason.clone(),
                    message: truncate_utf8(&failure.summary, 500),
                    phase: record.phase,
                });
                Some(failure)
            }
        };

        if cleanup_authorized {
            self.phase(&mut record, ExecutionPhase::Cleanup, progress)
                .await?;
            record.cleanup = if let Some(baseline_ref) = record.worker.baseline_restore_ref.as_ref()
            {
                match crate::model::PackageRef::parse(baseline_ref) {
                    Ok(baseline_ref) => {
                        restore_target(
                            self.package_manager.as_ref(),
                            Arc::clone(&self.clock),
                            &package.dnp_name,
                            &baseline_ref,
                            self.config.cleanup_timeout,
                        )
                        .await
                    }
                    Err(error) => crate::model::CleanupResult {
                        status: CleanupStatus::Failed,
                        leftover_packages: Vec::new(),
                        error: Some(truncate_utf8(
                            &format!("saved baseline reference is invalid: {error}"),
                            300,
                        )),
                    },
                }
            } else if self.config.cleanup_enabled {
                cleanup_target(
                    self.package_manager.as_ref(),
                    Arc::clone(&self.clock),
                    &package.dnp_name,
                    self.config.cleanup_timeout,
                )
                .await
            } else {
                crate::model::CleanupResult {
                    status: CleanupStatus::Skipped,
                    leftover_packages: Vec::new(),
                    error: None,
                }
            };
            match self.package_manager.list_packages().await {
                Ok(final_packages) => {
                    record.cleanup.leftover_packages =
                        leftover_packages(&record.evidence.initial_packages, &final_packages);
                    record.evidence.final_packages = final_packages;
                }
                Err(error) => {
                    if record.cleanup.error.is_none() {
                        record.cleanup.error = Some(truncate_utf8(&error.to_string(), 300));
                    }
                }
            }
            self.save(&record).await?;
        }

        let comparison = record
            .evidence
            .comparison
            .clone()
            .unwrap_or_else(|| comparison_from_partial(&record));
        let analysis = record
            .evidence
            .log_analysis
            .clone()
            .unwrap_or_else(inconclusive_analysis);
        let (mut verdict, mut reason, mut summary) = failure
            .map(|failure| (failure.verdict, failure.reason, failure.summary))
            .unwrap_or_else(|| deterministic_verdict(&comparison, &analysis));
        if matches!(
            record.cleanup.status,
            CleanupStatus::Failed | CleanupStatus::TimedOut
        ) && verdict == Verdict::Passed
        {
            verdict = Verdict::Warning;
            reason = ReasonCode::CleanupFailed;
            summary = format!("{summary}; target cleanup failed");
        }
        if matches!(
            record.cleanup.status,
            CleanupStatus::Failed | CleanupStatus::TimedOut
        ) {
            record.errors.push(RunError {
                code: ReasonCode::CleanupFailed,
                message: record
                    .cleanup
                    .error
                    .clone()
                    .unwrap_or_else(|| "target cleanup failed".to_owned()),
                phase: ExecutionPhase::Cleanup,
            });
        }

        let finished = Utc::now();
        record.status = ExecutionStatus::Completed;
        record.finished_at = Some(finished);
        let result = build_result(
            &record,
            comparison,
            analysis,
            verdict,
            reason,
            truncate_utf8(&summary, 500),
        );
        record.result = Some(result.clone());
        self.phase(&mut record, ExecutionPhase::Finished, progress)
            .await?;
        info!(
            run_id = %record.request.run_id,
            phase = ?record.phase,
            dnp_name = %record.request.package.dnp_name,
            event = "run_finished",
            verdict = ?verdict
        );
        Ok(())
    }

    async fn run_algorithm(
        &self,
        record: &mut RunRecord,
        cleanup_authorized: &mut bool,
        progress: &dyn RunProgress,
    ) -> Result<(), Failure> {
        let package = self.resolver.resolve(&record.request);
        self.phase_failure(record, ExecutionPhase::Preflight, progress)
            .await?;
        let tools = self
            .package_manager
            .verify_tools()
            .await
            .map_err(infrastructure)?;
        if !tools.ready() {
            return Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::RequiredMcpToolsMissing,
                summary: tools.message(),
            });
        }
        if package.dnp_name.as_str() == self.config.harness_dnp_name {
            return Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::HarnessPackageRefused,
                summary: "refused to test the harness package itself".to_owned(),
            });
        }
        let packages = self
            .package_manager
            .list_packages()
            .await
            .map_err(infrastructure)?;
        if packages
            .iter()
            .any(|installed| installed.dnp_name == package.dnp_name && installed.is_core)
        {
            return Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::CorePackageRefused,
                summary: "refused to test a core Dappnode package".to_owned(),
            });
        }
        record.evidence.initial_packages = packages.clone();
        self.save_failure(record).await?;

        let installed_baseline = packages
            .iter()
            .find(|installed| installed.dnp_name == package.dnp_name);
        if let Some(installed_baseline) = installed_baseline {
            let version = installed_baseline
                .version
                .as_deref()
                .ok_or_else(|| Failure {
                    verdict: Verdict::InfrastructureError,
                    reason: ReasonCode::BaselineUnavailable,
                    summary: "installed target has no version to restore after testing".to_owned(),
                })?;
            let baseline_ref =
                crate::model::PackageRef::parse(version).map_err(|error| Failure {
                    verdict: Verdict::InfrastructureError,
                    reason: ReasonCode::BaselineUnavailable,
                    summary: truncate_utf8(
                        &format!("installed target version cannot be restored: {error}"),
                        500,
                    ),
                })?;
            // Save this before candidate mutation so restart recovery restores
            // the package that was already running, rather than deleting it.
            record.worker.baseline_restore_ref = Some(baseline_ref.to_string());
            self.save_failure(record).await?;
        }

        self.phase_failure(record, ExecutionPhase::BaselinePreview, progress)
            .await?;
        let baseline_preview = if installed_baseline.is_some() {
            crate::model::PreviewSummary {
                package_name: Some(package.dnp_name.to_string()),
                version: record.worker.baseline_restore_ref.clone(),
                image_count: None,
                requires_user_input: false,
                summary: "using the target package already installed before this run".to_owned(),
            }
        } else {
            self.package_manager
                .preview_install(&package.dnp_name, package.baseline_ref.as_ref())
                .await
                .map_err(infrastructure)?
        };
        self.phase_failure(record, ExecutionPhase::BaselineInstall, progress)
            .await?;
        let baseline_started = self.clock.now();
        if installed_baseline.is_none() {
            self.authorize_cleanup(record, cleanup_authorized, progress)
                .await?;
            match self
                .package_manager
                .install_package(&package.dnp_name, package.baseline_ref.as_ref())
                .await
            {
                Ok(()) => {}
                Err(PackageManagerError::RequiredSetup) => {
                    return Err(Failure {
                        verdict: Verdict::Inconclusive,
                        reason: ReasonCode::UnsupportedRequiredSetup,
                        summary:
                            "baseline requires setup values; only default/empty settings are supported"
                                .to_owned(),
                    });
                }
                Err(error) => {
                    return Err(Failure {
                        verdict: Verdict::InfrastructureError,
                        reason: ReasonCode::BaselineInstallFailed,
                        summary: truncate_utf8(&error.to_string(), 500),
                    });
                }
            }
        }
        let baseline_install_ms = elapsed_ms(baseline_started, self.clock.now());
        self.phase_failure(record, ExecutionPhase::BaselineStabilization, progress)
            .await?;
        let baseline_stabilization = stabilize(
            self.package_manager.as_ref(),
            Arc::clone(&self.clock),
            &package.dnp_name,
            self.config.stabilization,
            progress,
        )
        .await;
        self.control_failure(progress)?;
        self.phase_failure(record, ExecutionPhase::BaselineCapture, progress)
            .await?;
        let baseline = self
            .capture(
                &package.dnp_name,
                baseline_preview,
                baseline_install_ms,
                baseline_stabilization,
                baseline_started,
            )
            .await
            .map_err(|error| Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::BaselineUnavailable,
                summary: error,
            })?;
        record.evidence.baseline = Some(baseline);
        self.save_failure(record).await?;

        self.phase_failure(record, ExecutionPhase::CandidatePreview, progress)
            .await?;
        let candidate_preview = self
            .package_manager
            .preview_install(&package.dnp_name, Some(&package.candidate_ref))
            .await
            .map_err(infrastructure)?;
        self.phase_failure(record, ExecutionPhase::CandidateInstall, progress)
            .await?;
        self.authorize_cleanup(record, cleanup_authorized, progress)
            .await?;
        let candidate_started = self.clock.now();
        // The candidate is always applied as an update from the installed
        // baseline to exercise the upgrade path, not a fresh install path.
        if let Err(error) = self
            .package_manager
            .update_package(&package.dnp_name, &package.candidate_ref)
            .await
        {
            return Err(Failure {
                verdict: Verdict::Failed,
                reason: ReasonCode::CandidateInstallFailed,
                summary: truncate_utf8(&error.to_string(), 500),
            });
        }
        let candidate_install_ms = elapsed_ms(candidate_started, self.clock.now());
        self.phase_failure(record, ExecutionPhase::CandidateStabilization, progress)
            .await?;
        let candidate_stabilization = stabilize(
            self.package_manager.as_ref(),
            Arc::clone(&self.clock),
            &package.dnp_name,
            self.config.stabilization,
            progress,
        )
        .await;
        self.control_failure(progress)?;
        self.phase_failure(record, ExecutionPhase::CandidateCapture, progress)
            .await?;
        let candidate = self
            .capture(
                &package.dnp_name,
                candidate_preview,
                candidate_install_ms,
                candidate_stabilization,
                candidate_started,
            )
            .await
            .map_err(|error| Failure {
                verdict: Verdict::Failed,
                reason: ReasonCode::CandidateContainersUnstable,
                summary: error,
            })?;
        record.evidence.candidate = Some(candidate);

        self.phase_failure(record, ExecutionPhase::Analysis, progress)
            .await?;
        let baseline = record.evidence.baseline.as_ref().ok_or_else(|| Failure {
            verdict: Verdict::InfrastructureError,
            reason: ReasonCode::UnexpectedError,
            summary: "baseline evidence was unexpectedly absent".to_owned(),
        })?;
        let candidate = record.evidence.candidate.as_ref().ok_or_else(|| Failure {
            verdict: Verdict::InfrastructureError,
            reason: ReasonCode::UnexpectedError,
            summary: "candidate evidence was unexpectedly absent".to_owned(),
        })?;
        record.evidence.comparison = Some(compare(baseline, candidate));
        let input = analysis_input(baseline, candidate);
        record.evidence.log_analysis = Some(
            self.analyzer
                .analyze(&input)
                .await
                .unwrap_or_else(|error| analysis_failure(&error.to_string())),
        );
        self.save_failure(record).await?;
        Ok(())
    }

    async fn capture(
        &self,
        dnp_name: &crate::model::DnpName,
        preview: crate::model::PreviewSummary,
        install_duration_ms: u64,
        stabilization: StabilizationResult,
        started_at: chrono::DateTime<Utc>,
    ) -> Result<CaptureEvidence, String> {
        let details = self
            .package_manager
            .get_package_details(dnp_name)
            .await
            .map_err(|error| truncate_utf8(&error.to_string(), 500))?;
        let (logs, log_error) = match self
            .package_manager
            .get_package_logs(dnp_name, self.config.log_tail)
            .await
        {
            Ok(mut logs) => {
                for entry in &mut logs.entries {
                    // Persisted logs are evidence, but still need strict size
                    // and secret bounds before storage or coordinator delivery.
                    entry.text = redact_and_bound(&entry.text, 64 * 1024);
                }
                (Some(logs), None)
            }
            Err(error) => (None, Some(truncate_utf8(&error.to_string(), 300))),
        };
        Ok(CaptureEvidence {
            install_status: StepStatus::Passed,
            install_duration_ms,
            preview: Some(preview),
            details: Some(details),
            stabilization,
            logs,
            log_error,
            started_at: started_at.to_rfc3339(),
            finished_at: self.clock.now().to_rfc3339(),
        })
    }

    async fn phase(
        &self,
        record: &mut RunRecord,
        phase: ExecutionPhase,
        progress: &dyn RunProgress,
    ) -> Result<(), ControllerError> {
        record.transition(phase);
        self.save(record).await?;
        progress.publish(phase, record.worker.cleanup_required);
        info!(
            run_id = %record.request.run_id,
            phase = ?phase,
            dnp_name = %record.request.package.dnp_name,
            event = "phase_transition"
        );
        Ok(())
    }

    async fn phase_failure(
        &self,
        record: &mut RunRecord,
        phase: ExecutionPhase,
        progress: &dyn RunProgress,
    ) -> Result<(), Failure> {
        self.phase(record, phase, progress)
            .await
            .map_err(persistence_failure)?;
        self.control_failure(progress)
    }

    async fn save(&self, record: &RunRecord) -> Result<(), ControllerError> {
        self.store.save(record).await.map_err(store_error)
    }

    async fn save_failure(&self, record: &RunRecord) -> Result<(), Failure> {
        self.save(record).await.map_err(persistence_failure)
    }

    async fn authorize_cleanup(
        &self,
        record: &mut RunRecord,
        cleanup_authorized: &mut bool,
        progress: &dyn RunProgress,
    ) -> Result<(), Failure> {
        if *cleanup_authorized {
            return Ok(());
        }
        // Persist this before the first destructive call so restart recovery
        // never guesses whether it must inspect and clean the target.
        record.worker.cleanup_required = true;
        *cleanup_authorized = true;
        self.save_failure(record).await?;
        progress.publish(record.phase, record.worker.cleanup_required);
        Ok(())
    }

    fn control_failure(&self, progress: &dyn RunProgress) -> Result<(), Failure> {
        match progress.control() {
            RunControl::Continue => Ok(()),
            RunControl::CancelRequested => Err(Failure {
                verdict: Verdict::Inconclusive,
                reason: ReasonCode::CancellationRequested,
                summary: "Tropibot requested cancellation at a safe phase boundary".to_owned(),
            }),
            RunControl::ClaimLost => Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::ClaimLost,
                summary: "Tropibot no longer recognizes this worker claim".to_owned(),
            }),
        }
    }
}

fn analysis_input(baseline: &CaptureEvidence, candidate: &CaptureEvidence) -> LogAnalysisInput {
    LogAnalysisInput {
        baseline: logs_for_analysis(baseline),
        candidate: logs_for_analysis(candidate),
    }
}

fn logs_for_analysis(capture: &CaptureEvidence) -> Vec<(Option<String>, String)> {
    capture
        .logs
        .as_ref()
        .map(|logs| {
            logs.entries
                .iter()
                .take(20)
                .map(|entry| {
                    (
                        entry.container.clone(),
                        redact_and_bound(&entry.text, 16 * 1024),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn infrastructure(error: PackageManagerError) -> Failure {
    Failure {
        verdict: Verdict::InfrastructureError,
        reason: ReasonCode::McpUnavailable,
        summary: truncate_utf8(&error.to_string(), 500),
    }
}

fn persistence_failure(error: ControllerError) -> Failure {
    error!(event = "persistence_failure", error = %error);
    Failure {
        verdict: Verdict::InfrastructureError,
        reason: ReasonCode::PersistenceFailed,
        summary: truncate_utf8(&error.to_string(), 500),
    }
}

fn store_error(error: StoreError) -> ControllerError {
    ControllerError::Persistence(error.to_string())
}

fn elapsed_ms(start: chrono::DateTime<Utc>, end: chrono::DateTime<Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}

fn analysis_failure(message: &str) -> LogAnalysisResult {
    LogAnalysisResult {
        analyzer: AnalyzerKind::Heuristic,
        status: AnalyzerStatus::Inconclusive,
        summary: "Log analysis was unavailable".to_owned(),
        baseline: AnalysisSide {
            status: AnalyzerStatus::Inconclusive,
            summary: "Analysis unavailable".to_owned(),
        },
        candidate: AnalysisSide {
            status: AnalyzerStatus::Inconclusive,
            summary: "Analysis unavailable".to_owned(),
        },
        new_findings: Vec::new(),
        analyzer_errors: vec![truncate_utf8(message, 300)],
        components: Vec::new(),
    }
}

fn inconclusive_analysis() -> LogAnalysisResult {
    analysis_failure("run ended before comparative log analysis")
}

fn comparison_from_partial(record: &RunRecord) -> ComparisonEvidence {
    match (&record.evidence.baseline, &record.evidence.candidate) {
        (Some(baseline), Some(candidate)) => compare(baseline, candidate),
        _ => ComparisonEvidence {
            baseline_hard_check: record
                .evidence
                .baseline
                .as_ref()
                .is_some_and(|capture| capture.stabilization.passed),
            candidate_hard_check: false,
            baseline_containers: Vec::new(),
            candidate_containers: Vec::new(),
            containers_added: Vec::new(),
            containers_removed: Vec::new(),
            baseline_version: record
                .evidence
                .baseline
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
            candidate_version: None,
            baseline_stabilization_ms: record
                .evidence
                .baseline
                .as_ref()
                .map_or(0, |capture| capture.stabilization.duration_ms),
            candidate_stabilization_ms: 0,
            baseline_last_non_running_states: Vec::new(),
            candidate_last_non_running_states: Vec::new(),
            baseline_logs_collected: record
                .evidence
                .baseline
                .as_ref()
                .is_some_and(|capture| capture.logs.is_some()),
            candidate_logs_collected: false,
            deterministic_regressions: Vec::new(),
        },
    }
}

fn build_result(
    record: &RunRecord,
    comparison: ComparisonEvidence,
    analysis: LogAnalysisResult,
    verdict: Verdict,
    reason_code: ReasonCode,
    summary: String,
) -> HarnessResult {
    let baseline = result_side(record.evidence.baseline.as_ref());
    let candidate = result_side(record.evidence.candidate.as_ref());
    let started = record.started_at.unwrap_or(record.created_at);
    let finished = record.finished_at.unwrap_or_else(Utc::now);
    HarnessResult {
        schema_version: 1,
        run_id: record.request.run_id.to_string(),
        source: ResultSource::from_request(&record.request),
        package: ResultPackage {
            dnp_name: record.request.package.dnp_name.to_string(),
            baseline_requested_ref: record
                .request
                .package
                .baseline_ref
                .as_ref()
                .map(ToString::to_string),
            baseline_resolved_version: record
                .evidence
                .baseline
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
            candidate_ref: record.request.package.candidate_ref.to_string(),
            candidate_reported_version: record
                .evidence
                .candidate
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
        },
        execution: ResultExecution {
            status: ExecutionStatus::Completed,
            started_at: started.to_rfc3339(),
            finished_at: finished.to_rfc3339(),
            duration_ms: elapsed_ms(started, finished),
        },
        verdict,
        reason_code,
        summary,
        baseline,
        candidate,
        comparison,
        log_analysis: analysis,
        cleanup: record.cleanup.clone(),
        errors: record.errors.clone(),
    }
}

fn result_side(capture: Option<&CaptureEvidence>) -> ResultSide {
    let containers = capture
        .and_then(|capture| capture.details.as_ref())
        .map(|details| details.containers.clone())
        .unwrap_or_default();
    ResultSide {
        install: InstallResult {
            status: capture.map_or(StepStatus::Failed, |capture| capture.install_status),
            duration_ms: capture.map_or(0, |capture| capture.install_duration_ms),
        },
        hard_check: HardCheckResult {
            passed: capture.is_some_and(|capture| capture.stabilization.passed),
            reason_codes: if capture.is_some_and(|capture| capture.stabilization.passed) {
                Vec::new()
            } else {
                vec![ReasonCode::CandidateContainersUnstable]
            },
            container_count: containers.len(),
            stable_samples: capture.map_or(0, |capture| capture.stabilization.stable_samples),
        },
        containers,
        log_collection: LogCollectionResult {
            status: if capture.is_some_and(|capture| capture.logs.is_some()) {
                StepStatus::Passed
            } else {
                StepStatus::Failed
            },
            container_count: capture
                .and_then(|capture| capture.logs.as_ref())
                .map_or(0, |logs| logs.entries.len()),
        },
    }
}
