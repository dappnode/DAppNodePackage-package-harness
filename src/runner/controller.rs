use std::{sync::Arc, time::Duration};

use chrono::Utc;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::{
    analysis::{
        LogAnalyzer,
        redaction::{redact_and_bound, redact_and_bound_tail, truncate_utf8},
    },
    clock::Clock,
    model::{
        CaptureEvidence, CleanupStatus, DnpName, ExecutionPhase, ExecutionStatus, LogAnalysisInput,
        LogCollectionContext, PackageResolver, ReasonCode, RunError, RunId, RunRecord,
        StabilizationResult, StepStatus, TargetRecoveryPlan, Verdict, same_install_origin,
    },
    package_manager::{PackageManager, PackageManagerError},
    runner::{
        cleanup::reconcile_target,
        comparison::{compare, deterministic_verdict},
        progress::{RunControl, RunProgress},
        result::{analysis_failure, build_result, comparison_from_partial, inconclusive_analysis},
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

struct CaptureContext<'a> {
    run_id: &'a RunId,
    side: &'static str,
    dnp_name: &'a crate::model::DnpName,
    started_at: chrono::DateTime<Utc>,
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
        info!(
            event = "run_started",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            "Starting package validation run"
        );

        let algorithm_result = self
            .run_algorithm(&mut record, &mut cleanup_authorized, progress)
            .await;
        let failure = match algorithm_result {
            Ok(()) => None,
            Err(failure) => {
                warn!(
                    event = "run_algorithm_failed",
                    run_id = %record.request.run_id,
                    dnp_name = %package.dnp_name,
                    phase = ?record.phase,
                    verdict = ?failure.verdict,
                    reason = ?failure.reason,
                    summary = ?redact_and_bound(&failure.summary, 500),
                    "Package workflow stopped; cleanup will still run when required"
                );
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
            let recovery_plan = record.worker.target_recovery;
            info!(
                event = "cleanup_plan_started",
                run_id = %record.request.run_id,
                dnp_name = %package.dnp_name,
                recovery_plan = ?recovery_plan,
                cleanup_timeout_ms = self.config.cleanup_timeout.as_millis() as u64,
                "Applying the persisted cleanup plan"
            );
            let (cleanup, final_packages) = reconcile_target(
                self.package_manager.as_ref(),
                Arc::clone(&self.clock),
                &package.dnp_name,
                recovery_plan,
                record.request.package.baseline_ref.as_ref(),
                &record.evidence.initial_packages,
                self.config.cleanup_timeout,
            )
            .await;
            record.cleanup = cleanup;
            record.evidence.final_packages = final_packages;
            if matches!(
                record.cleanup.status,
                CleanupStatus::Passed | CleanupStatus::Skipped
            ) {
                info!(
                    event = "cleanup_verified",
                    run_id = %record.request.run_id,
                    dnp_name = %package.dnp_name,
                    status = ?record.cleanup.status,
                    final_package_count = record.evidence.final_packages.len(),
                    leftover_packages = ?record.cleanup.leftover_packages,
                    "Cleanup and final inventory verification completed"
                );
            } else {
                warn!(
                    event = "cleanup_failed",
                    run_id = %record.request.run_id,
                    dnp_name = %package.dnp_name,
                    status = ?record.cleanup.status,
                    leftover_packages = ?record.cleanup.leftover_packages,
                    error = record.cleanup.error.as_deref().unwrap_or("unknown cleanup error"),
                    "Cleanup could not restore the expected node state"
                );
            }
            self.save(&record).await?;
        } else {
            record.cleanup = crate::model::CleanupResult {
                status: CleanupStatus::Skipped,
                leftover_packages: Vec::new(),
                error: None,
            };
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
        if record
            .errors
            .iter()
            .any(|error| error.code == ReasonCode::BaselineSignatureInvalid)
        {
            match verdict {
                Verdict::Passed => {
                    verdict = Verdict::Warning;
                    reason = ReasonCode::BaselineSignatureInvalid;
                    summary = format!("{summary}; baseline signature validation was bypassed");
                }
                Verdict::Warning => {
                    summary = format!("{summary}; baseline signature validation was bypassed");
                }
                Verdict::Failed | Verdict::Inconclusive | Verdict::InfrastructureError => {}
            }
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
            event = "run_finished",
            run_id = %record.request.run_id,
            dnp_name = %record.request.package.dnp_name,
            verdict = ?result.verdict,
            reason = ?result.reason_code,
            cleanup = ?result.cleanup.status,
            duration_ms = result.execution.duration_ms,
            baseline_version = result.package.baseline_resolved_version.as_deref().unwrap_or("unknown"),
            candidate_version = result.package.candidate_reported_version.as_deref().unwrap_or("unknown"),
            analyzer = ?result.log_analysis.analyzer,
            analysis_status = ?result.log_analysis.status,
            findings = result.log_analysis.new_findings.len(),
            analyzer_errors = ?result.log_analysis.analyzer_errors,
            summary = ?redact_and_bound(&result.summary, 500),
            "Package validation run finished"
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
            .map_err(|error| package_failure(error, ReasonCode::McpUnavailable))?;
        if !tools.ready() {
            return Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason: ReasonCode::RequiredMcpToolsMissing,
                summary: tools.message(),
            });
        }
        info!(
            event = "preflight_tools_verified",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            available_tools = tools.available.len(),
            "Required Dappmanager tools are available"
        );
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
            .map_err(|error| package_failure(error, ReasonCode::McpUnavailable))?;
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
        info!(
            event = "baseline_inventory_inspected",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            installed_package_count = packages.len(),
            target_already_installed = installed_baseline.is_some(),
            installed_version = installed_baseline.and_then(|package| package.version.as_deref()).unwrap_or("none"),
            "Inventory inspected"
        );
        record.worker.target_recovery = if installed_baseline.is_some() {
            if package
                .baseline_ref
                .as_ref()
                .is_some_and(|reference| reference.is_ipfs())
            {
                TargetRecoveryPlan::RestoreBaseline
            } else {
                TargetRecoveryPlan::RestoreLatest
            }
        } else {
            TargetRecoveryPlan::Remove
        };
        self.save_failure(record).await?;

        self.phase_failure(record, ExecutionPhase::BaselinePreview, progress)
            .await?;
        // An omitted baselineRef always means the latest published release.
        // Installed node state must not silently replace that request.
        let baseline_preview = self
            .package_manager
            .preview_install(&package.dnp_name, package.baseline_ref.as_ref())
            .await
            .map_err(|error| {
                if !package.baseline_ref.as_ref().is_some_and(|reference| reference.is_ipfs())
                    && error.is_unresolvable_registry_name()
                {
                    Failure {
                        verdict: Verdict::Inconclusive,
                        reason: ReasonCode::BaselineUnresolvable,
                        summary: format!(
                            "No resolvable published baseline for {}; upgrade comparison skipped without changing packages. Publish or repair the registry entry, or supply an explicit known-good IPFS baselineRef",
                            package.dnp_name
                        ),
                    }
                } else {
                    package_failure(error, ReasonCode::BaselineUnavailable)
                }
            })?;
        let baseline_resolved_ref = baseline_preview.resolved_ref.clone();
        let baseline_expected_version = baseline_preview.version.clone();
        let installed_version_matches = installed_baseline.is_some_and(|installed| {
            let Some(installed_version) = installed.version.as_deref() else {
                return false;
            };
            baseline_expected_version.as_deref().map_or_else(
                || {
                    package
                        .baseline_ref
                        .as_ref()
                        .is_some_and(|requested| requested.as_str() == installed_version)
                },
                |resolved_version| resolved_version == installed_version,
            )
        });
        // An earlier IPFS build can share its version with the requested
        // release, so the install origin has to match as well.
        let reuse_installed_baseline = installed_version_matches
            && self
                .installed_origin_matches(&package.dnp_name, baseline_resolved_ref.as_deref())
                .await;
        if installed_version_matches && !reuse_installed_baseline {
            info!(
                event = "installed_baseline_origin_mismatch",
                run_id = %record.request.run_id,
                dnp_name = %package.dnp_name,
                "Installed target has the baseline version but another install origin; reinstalling the baseline"
            );
        }
        info!(
            event = "baseline_preview_ready",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            requested_ref = package.baseline_ref.as_ref().map_or("latest", crate::model::PackageRef::as_str),
            resolved_version = baseline_preview.version.as_deref().unwrap_or("unknown"),
            resolved_ref = baseline_resolved_ref.as_deref().unwrap_or("unavailable"),
            reused_existing = reuse_installed_baseline,
            requires_user_input = baseline_preview.requires_user_input,
            "Baseline preview ready"
        );
        self.phase_failure(record, ExecutionPhase::BaselineInstall, progress)
            .await?;
        let baseline_started = self.clock.now();
        if !reuse_installed_baseline {
            self.authorize_cleanup(record, cleanup_authorized, progress)
                .await?;
            if installed_baseline.is_some()
                && let Err(error) = self
                    .package_manager
                    .remove_package(&package.dnp_name, false)
                    .await
                && !matches!(error, PackageManagerError::NotFound)
            {
                return Err(Failure {
                    verdict: Verdict::InfrastructureError,
                    reason: ReasonCode::BaselineInstallFailed,
                    summary: truncate_utf8(&error.to_string(), 500),
                });
            }
            let install_result = self
                .package_manager
                .install_package(&package.dnp_name, package.baseline_ref.as_ref())
                .await;
            let install_result = match install_result {
                Err(error) if error.is_signature_rejection() => {
                    let warning = truncate_utf8(
                        &format!("baseline signature validation failed and was bypassed: {error}"),
                        500,
                    );
                    warn!(
                        event = "baseline_signature_bypassed",
                        run_id = %record.request.run_id,
                        dnp_name = %package.dnp_name,
                        error = %warning,
                        "Baseline signature was rejected; retrying with the signed-package restriction bypass"
                    );
                    let retry = self
                        .package_manager
                        .install_package_bypassing_signature(
                            &package.dnp_name,
                            package.baseline_ref.as_ref(),
                        )
                        .await;
                    if retry.is_ok() {
                        record.errors.push(RunError {
                            code: ReasonCode::BaselineSignatureInvalid,
                            message: warning,
                            phase: ExecutionPhase::BaselineInstall,
                        });
                        self.save_failure(record).await?;
                    }
                    retry
                }
                result => result,
            };
            match install_result {
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
        info!(
            event = "baseline_install_completed",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            reused_existing = reuse_installed_baseline,
            duration_ms = baseline_install_ms,
            "Baseline installation step completed"
        );
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
                CaptureContext {
                    run_id: &record.request.run_id,
                    side: "baseline",
                    dnp_name: &package.dnp_name,
                    started_at: baseline_started,
                },
                baseline_preview,
                baseline_install_ms,
                baseline_stabilization,
            )
            .await
            .map_err(|error| package_failure(error, ReasonCode::BaselineUnavailable))?;
        let applied = applied_version(&baseline, "baseline", ReasonCode::BaselineInstallFailed);
        record.evidence.baseline = Some(baseline);
        self.save_failure(record).await?;
        applied?;

        self.phase_failure(record, ExecutionPhase::CandidatePreview, progress)
            .await?;
        let candidate_preview = self
            .package_manager
            .preview_install(&package.dnp_name, Some(&package.candidate_ref))
            .await
            .map_err(|error| package_failure(error, ReasonCode::CandidateInstallFailed))?;
        info!(
            event = "candidate_preview_ready",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            candidate_ref = %package.candidate_ref,
            resolved_version = candidate_preview.version.as_deref().unwrap_or("unknown"),
            requires_user_input = candidate_preview.requires_user_input,
            "Candidate install preview ready"
        );
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
            let verdict = if error.is_transient_mutation_failure() {
                Verdict::InfrastructureError
            } else {
                Verdict::Failed
            };
            return Err(Failure {
                verdict,
                reason: ReasonCode::CandidateInstallFailed,
                summary: truncate_utf8(&error.to_string(), 500),
            });
        }
        let candidate_install_ms = elapsed_ms(candidate_started, self.clock.now());
        info!(
            event = "candidate_install_completed",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            candidate_ref = %package.candidate_ref,
            duration_ms = candidate_install_ms,
            "Candidate update completed"
        );
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
                CaptureContext {
                    run_id: &record.request.run_id,
                    side: "candidate",
                    dnp_name: &package.dnp_name,
                    started_at: candidate_started,
                },
                candidate_preview,
                candidate_install_ms,
                candidate_stabilization,
            )
            .await
            .map_err(|error| package_failure(error, ReasonCode::CandidateInstallFailed))?;
        let applied = applied_version(&candidate, "candidate", ReasonCode::CandidateInstallFailed);
        record.evidence.candidate = Some(candidate);
        self.save_failure(record).await?;
        applied?;

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
        let comparison = compare(baseline, candidate);
        info!(
            event = "comparison_completed",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            baseline_version = comparison.baseline_version.as_deref().unwrap_or("unknown"),
            candidate_version = comparison.candidate_version.as_deref().unwrap_or("unknown"),
            containers_added = ?comparison.containers_added,
            containers_removed = ?comparison.containers_removed,
            deterministic_regressions = comparison.deterministic_regressions.len(),
            "Baseline and candidate evidence compared"
        );
        record.evidence.comparison = Some(comparison);
        let input = analysis_input(baseline, candidate);
        let analysis_input_bytes = input
            .baseline
            .iter()
            .chain(&input.candidate)
            .map(|(_, text)| text.len())
            .sum::<usize>();
        info!(
            event = "log_analysis_started",
            run_id = %record.request.run_id,
            dnp_name = %package.dnp_name,
            baseline_log_blocks = input.baseline.len(),
            candidate_log_blocks = input.candidate.len(),
            input_bytes = analysis_input_bytes,
            "Comparative log analysis started"
        );
        let analysis_started = self.clock.now();
        let analysis = self
            .analyzer
            .analyze(&input)
            .await
            .unwrap_or_else(|error| analysis_failure(&error.to_string()));
        let analysis_duration_ms = elapsed_ms(analysis_started, self.clock.now());
        if analysis.analyzer_errors.is_empty() {
            info!(
                event = "log_analysis_completed",
                run_id = %record.request.run_id,
                dnp_name = %package.dnp_name,
                analyzer = ?analysis.analyzer,
                status = ?analysis.status,
                findings = analysis.new_findings.len(),
                duration_ms = analysis_duration_ms,
                "Comparative log analysis completed"
            );
        } else {
            warn!(
                event = "log_analysis_completed_with_fallback",
                run_id = %record.request.run_id,
                dnp_name = %package.dnp_name,
                analyzer = ?analysis.analyzer,
                status = ?analysis.status,
                findings = analysis.new_findings.len(),
                duration_ms = analysis_duration_ms,
                analyzer_errors = ?analysis.analyzer_errors,
                "Log analysis completed with an advisory analyzer fallback"
            );
        }
        record.evidence.log_analysis = Some(analysis);
        self.save_failure(record).await?;
        Ok(())
    }

    async fn capture(
        &self,
        context: CaptureContext<'_>,
        preview: crate::model::PreviewSummary,
        install_duration_ms: u64,
        stabilization: StabilizationResult,
    ) -> Result<CaptureEvidence, PackageManagerError> {
        let details = self
            .package_manager
            .get_package_details(context.dnp_name)
            .await?;
        let (mut logs, mut log_error) = match self
            .package_manager
            .get_package_logs(context.dnp_name, self.config.log_tail)
            .await
        {
            Ok(mut logs) => {
                for entry in &mut logs.entries {
                    // Persisted logs are evidence, but still need strict size
                    // and secret bounds before storage or coordinator delivery.
                    entry.text = redact_and_bound_tail(&entry.text, 64 * 1024);
                }
                (Some(logs), None)
            }
            Err(error) => {
                let error = truncate_utf8(&error.to_string(), 300);
                warn!(
                    event = "capture_logs_failed",
                    run_id = %context.run_id,
                    dnp_name = %context.dnp_name,
                    side = context.side,
                    error = %error,
                    "Package details were captured, but container logs were unavailable"
                );
                (None, Some(error))
            }
        };
        // Classifier advice may only request bounded extra observations. It
        // never suppresses logs, decides success, or bypasses mandatory cleanup.
        if let Some(current) = &mut logs {
            for attempt in 0..2 {
                let blocks = current
                    .entries
                    .iter()
                    .map(|entry| (entry.container.clone(), entry.text.clone()))
                    .collect();
                let mut input = LogAnalysisInput::default();
                let mut collection = LogCollectionContext::default();
                if context.side == "baseline" {
                    input.baseline = blocks;
                    collection.baseline_stable = stabilization.passed;
                    collection.baseline_expected_containers = details.containers.len();
                } else {
                    input.candidate = blocks;
                    collection.candidate_stable = stabilization.passed;
                    collection.candidate_expected_containers = details.containers.len();
                }
                input.context = Some(collection);
                let empty = current
                    .entries
                    .iter()
                    .all(|entry| entry.text.trim().is_empty());
                let advice = if empty {
                    Ok(true)
                } else {
                    self.analyzer.needs_more_logs(&input).await
                };
                match advice {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        warn!(event = "collection_classifier_unavailable", run_id = %context.run_id,
                            side = context.side, error = %error, "Proceeding with captured logs after advisory classifier failure");
                        break;
                    }
                }
                info!(event = "collecting_additional_startup_logs", run_id = %context.run_id,
                    side = context.side, attempt = attempt + 1, "Startup is progressing; collecting another bounded log sample");
                self.clock.sleep(Duration::from_secs(5)).await;
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    self.package_manager
                        .get_package_logs(context.dnp_name, self.config.log_tail),
                )
                .await
                {
                    Ok(Ok(mut next)) => {
                        for entry in &mut next.entries {
                            entry.text = redact_and_bound_tail(&entry.text, 64 * 1024);
                        }
                        *current = next;
                    }
                    result => {
                        log_error = Some(match result {
                            Ok(Err(error)) => truncate_utf8(&error.to_string(), 300),
                            _ => "additional log collection timed out; retained the earlier sample"
                                .to_owned(),
                        });
                        break;
                    }
                }
            }
        }
        let log_blocks = logs.as_ref().map_or(0, |logs| logs.entries.len());
        let log_bytes = logs.as_ref().map_or(0, |logs| {
            logs.entries.iter().map(|entry| entry.text.len()).sum()
        });
        let running_containers = details
            .containers
            .iter()
            .filter(|container| container.running)
            .count();
        info!(
            event = "evidence_capture_completed",
            run_id = %context.run_id,
            dnp_name = %context.dnp_name,
            side = context.side,
            reported_version = details.version.as_deref().unwrap_or("unknown"),
            container_count = details.containers.len(),
            running_containers,
            stabilization_passed = stabilization.passed,
            stabilization_duration_ms = stabilization.duration_ms,
            install_duration_ms,
            log_blocks,
            log_bytes,
            "Package evidence captured"
        );
        Ok(CaptureEvidence {
            install_status: StepStatus::Passed,
            install_duration_ms,
            preview: Some(preview),
            details: Some(details),
            stabilization,
            logs,
            log_error,
            started_at: context.started_at.to_rfc3339(),
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
        if phase == ExecutionPhase::Finished {
            return Ok(());
        }
        let label = phase.display_name();
        info!(
            event = "phase_started",
            run_id = %record.request.run_id,
            phase = ?phase,
            "{label}"
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

    /// Whether the installed target came from `expected` (an IPFS origin, or
    /// `None` for a registry release). Unreadable details count as no match,
    /// which reinstalls the baseline instead of reusing an unknown build.
    async fn installed_origin_matches(&self, dnp_name: &DnpName, expected: Option<&str>) -> bool {
        self.package_manager
            .get_package_details(dnp_name)
            .await
            .is_ok_and(|details| same_install_origin(expected, details.origin.as_deref()))
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
        context: Some(LogCollectionContext {
            baseline_stable: baseline.stabilization.passed,
            candidate_stable: candidate.stabilization.passed,
            baseline_expected_containers: baseline
                .details
                .as_ref()
                .map_or(0, |details| details.containers.len()),
            candidate_expected_containers: candidate
                .details
                .as_ref()
                .map_or(0, |details| details.containers.len()),
            baseline_log_error: baseline.log_error.clone(),
            candidate_log_error: candidate.log_error.clone(),
        }),
    }
}

fn logs_for_analysis(capture: &CaptureEvidence) -> Vec<(Option<String>, String)> {
    capture
        .logs
        .as_ref()
        .map(|logs| {
            logs.entries
                .iter()
                .map(|entry| (entry.container.clone(), entry.text.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Fails when Dappmanager reported a mutation as applied but the package
/// still reports another version or install origin than the preview
/// resolved. Without this, a no-op update would compare the baseline with
/// itself and pass. The origin check matters when a candidate build keeps
/// the baseline's version.
fn applied_version(
    capture: &CaptureEvidence,
    side: &str,
    reason: ReasonCode,
) -> Result<(), Failure> {
    let expected = capture
        .preview
        .as_ref()
        .and_then(crate::model::PreviewSummary::semantic_version);
    let reported = capture
        .details
        .as_ref()
        .and_then(|details| details.version.as_deref());
    if let (Some(expected), Some(reported)) = (expected, reported)
        && expected != reported
    {
        return Err(Failure {
            verdict: Verdict::InfrastructureError,
            reason,
            summary: format!(
                "Dappmanager reported the {side} as installed, but the package reports version {reported} instead of {expected}"
            ),
        });
    }
    if let Some(details) = capture.details.as_ref() {
        let expected_origin = capture
            .preview
            .as_ref()
            .and_then(|preview| preview.resolved_ref.as_deref());
        let reported_origin = details.origin.as_deref();
        if !same_install_origin(expected_origin, reported_origin) {
            return Err(Failure {
                verdict: Verdict::InfrastructureError,
                reason,
                summary: format!(
                    "Dappmanager reported the {side} as installed, but the package was installed from {} instead of {}",
                    reported_origin.unwrap_or("the registry"),
                    expected_origin.unwrap_or("the registry")
                ),
            });
        }
    }
    Ok(())
}

fn package_failure(error: PackageManagerError, operation_reason: ReasonCode) -> Failure {
    let reason = match error {
        PackageManagerError::Transport(_) | PackageManagerError::Timeout { .. } => {
            ReasonCode::McpUnavailable
        }
        PackageManagerError::Configuration(_) | PackageManagerError::InvalidResponse { .. } => {
            ReasonCode::UnexpectedError
        }
        PackageManagerError::Tool { .. }
        | PackageManagerError::RequiredSetup
        | PackageManagerError::NotFound => operation_reason,
    };
    Failure {
        verdict: Verdict::InfrastructureError,
        reason,
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
