use std::{
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dappnode_package_harness::{
    analysis::{CompositeLogAnalyzer, HeuristicLogAnalyzer, LogAnalyzer, NexusLogAnalyzer},
    clock::Clock,
    coordinator::protocol::{ClaimResponse, CompleteRequest, HeartbeatRequest},
    coordinator::{ClaimOutcome, CompletionDisposition, CoordinatorClient, HeartbeatOutcome},
    model::{
        CleanupStatus, ContainerLog, ContainerSnapshot, DnpName, ExecutionStatus,
        ExplicitPackageResolver, LogAnalysisInput, PackageDetails, PackageLogs, PackageRef,
        PackageSummary, PreviewSummary, ReasonCode, RunRecord, RunRequest, RunRequestDto,
        TargetRecoveryPlan, Verdict, WorkerErrorCode, WorkerState,
    },
    package_manager::{PackageManager, PackageManagerError, REQUIRED_MCP_TOOLS, ToolAvailability},
    runner::{
        NoopRunProgress, RunControl, RunController, RunProgress, RunnerConfig,
        cleanup::restore_target,
        stabilization::{StabilizationConfig, stabilize},
    },
    storage::{FileRunStore, RunStore},
    worker::{
        PackageHarnessWorker, WorkerConfig, WorkerDependencies, WorkerReadiness,
        progress::WorkerProgress,
    },
};
use serde_json::json;
use tempfile::TempDir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

#[derive(Debug, Default)]
struct ImmediateClock;

#[async_trait]
impl Clock for ImmediateClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn sleep(&self, _duration: Duration) {}
}

#[derive(Debug, Clone)]
struct ScriptedPackageManager {
    target: DnpName,
    state: Arc<Mutex<ScriptedState>>,
    baseline_running: bool,
    candidate_running: bool,
    cleanup_failure: bool,
    candidate_removes_target: bool,
    candidate_error: Option<PackageManagerError>,
    leave_extra_package: bool,
    core: bool,
}

#[derive(Debug, Clone, Default)]
struct ScriptedState {
    installed: bool,
    candidate: bool,
    version: String,
    install_calls: usize,
    update_versions: Vec<String>,
    cleanup_calls: usize,
}

impl ScriptedPackageManager {
    fn new(target: DnpName) -> Self {
        Self {
            target,
            state: Arc::new(Mutex::new(ScriptedState::default())),
            baseline_running: true,
            candidate_running: true,
            cleanup_failure: false,
            candidate_removes_target: false,
            candidate_error: None,
            leave_extra_package: false,
            core: false,
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, ScriptedState>, PackageManagerError> {
        self.state
            .lock()
            .map_err(|_| PackageManagerError::Transport("test state lock poisoned".to_owned()))
    }

    fn cleanup_calls(&self) -> Result<usize, PackageManagerError> {
        Ok(self.state()?.cleanup_calls)
    }

    fn with_installed_baseline(self, version: &str) -> Result<Self, PackageManagerError> {
        let mut state = self.state()?;
        state.installed = true;
        state.version = version.to_owned();
        drop(state);
        Ok(self)
    }

    fn installed_version(&self) -> Result<Option<String>, PackageManagerError> {
        let state = self.state()?;
        Ok(state.installed.then(|| state.version.clone()))
    }

    fn install_calls(&self) -> Result<usize, PackageManagerError> {
        Ok(self.state()?.install_calls)
    }

    fn update_versions(&self) -> Result<Vec<String>, PackageManagerError> {
        Ok(self.state()?.update_versions.clone())
    }
}

#[async_trait]
impl PackageManager for ScriptedPackageManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        Ok(ToolAvailability {
            available: REQUIRED_MCP_TOOLS.iter().map(ToString::to_string).collect(),
            missing: Vec::new(),
        })
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        let state = self.state()?.clone();
        let mut packages = if state.installed || self.core {
            vec![PackageSummary {
                dnp_name: self.target.clone(),
                version: Some(state.version.clone()),
                is_core: self.core,
            }]
        } else {
            Vec::new()
        };
        if self.leave_extra_package && state.cleanup_calls > 0 {
            packages.push(PackageSummary {
                dnp_name: DnpName::parse("dependency.dnp.dappnode.eth").map_err(|error| {
                    PackageManagerError::InvalidResponse {
                        tool: "scripted package manager".to_owned(),
                        message: error.to_string(),
                    }
                })?,
                version: Some("1.0.0".to_owned()),
                is_core: false,
            });
        }
        Ok(packages)
    }

    async fn get_package_details(
        &self,
        dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        let state = self.state()?.clone();
        if !state.installed || dnp_name != &self.target {
            return Err(PackageManagerError::NotFound);
        }
        let running = if state.candidate {
            self.candidate_running
        } else {
            self.baseline_running
        };
        Ok(details(dnp_name, &state.version, running, "service"))
    }

    async fn get_package_logs(
        &self,
        _dnp_name: &DnpName,
        _tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        Ok(PackageLogs {
            entries: vec![ContainerLog {
                container: Some("service".to_owned()),
                text: "service log".to_owned(),
            }],
        })
    }

    async fn preview_install(
        &self,
        dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        Ok(PreviewSummary {
            package_name: Some(dnp_name.to_string()),
            version: version.map(ToString::to_string),
            image_count: Some(1),
            requires_user_input: false,
            summary: "preview".to_owned(),
        })
    }

    async fn install_package(
        &self,
        _dnp_name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        let mut state = self.state()?;
        state.install_calls = state.install_calls.saturating_add(1);
        state.installed = true;
        state.candidate = false;
        state.version = version.map_or_else(|| "baseline".to_owned(), ToString::to_string);
        Ok(())
    }

    async fn update_package(
        &self,
        _dnp_name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        if version.as_str() == "/ipfs/QmCandidate"
            && let Some(error) = &self.candidate_error
        {
            return Err(error.clone());
        }
        let mut state = self.state()?;
        state.update_versions.push(version.to_string());
        state.installed =
            !(self.candidate_removes_target && version.as_str() == "/ipfs/QmCandidate");
        state.candidate = version.as_str() == "/ipfs/QmCandidate";
        state.version = version.to_string();
        Ok(())
    }

    async fn remove_package(
        &self,
        _dnp_name: &DnpName,
        _delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        let mut state = self.state()?;
        state.cleanup_calls = state.cleanup_calls.saturating_add(1);
        if self.cleanup_failure {
            return Err(PackageManagerError::Tool {
                tool: "dappnode_remove_package".to_owned(),
                message: "simulated cleanup failure".to_owned(),
            });
        }
        state.installed = false;
        Ok(())
    }
}

fn details(dnp_name: &DnpName, version: &str, running: bool, name: &str) -> PackageDetails {
    PackageDetails {
        dnp_name: dnp_name.clone(),
        version: Some(version.to_owned()),
        containers: vec![ContainerSnapshot {
            name: name.to_owned(),
            service_name: Some(name.to_owned()),
            state: Some(if running { "running" } else { "exited" }.to_owned()),
            running,
            image: Some("example:latest".to_owned()),
            created: None,
        }],
    }
}

fn request(run_id: &str) -> Result<RunRequest, Box<dyn Error>> {
    Ok(RunRequest::try_from(RunRequestDto {
        schema_version: 1,
        run_id: run_id.to_owned(),
        source: dappnode_package_harness::model::SourceDto {
            repository: "dappnode/example-package".to_owned(),
            pull_request: 123,
            head_sha: "abcdef0123456789".to_owned(),
        },
        package: dappnode_package_harness::model::PackageRequestDto {
            dnp_name: "example.dnp.dappnode.eth".to_owned(),
            candidate_ref: "/ipfs/QmCandidate".to_owned(),
            baseline_ref: None,
        },
    })?)
}

fn runner_config() -> RunnerConfig {
    RunnerConfig {
        harness_dnp_name: "package-harness.dnp.dappnode.eth".to_owned(),
        stabilization: StabilizationConfig {
            timeout: Duration::from_millis(10),
            poll_interval: Duration::from_millis(1),
            required_samples: 2,
        },
        log_tail: 30,
        cleanup_enabled: true,
        cleanup_timeout: Duration::from_millis(10),
        retain_baseline_packages: Default::default(),
    }
}

async fn execute_with(
    request: RunRequest,
    manager: Arc<dyn PackageManager>,
    progress: &dyn RunProgress,
) -> Result<(TempDir, Arc<FileRunStore>, RunRecord), Box<dyn Error>> {
    execute_with_config(request, manager, progress, runner_config()).await
}

async fn execute_with_config(
    request: RunRequest,
    manager: Arc<dyn PackageManager>,
    progress: &dyn RunProgress,
    config: RunnerConfig,
) -> Result<(TempDir, Arc<FileRunStore>, RunRecord), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
    store.create(&RunRecord::new(request.clone())).await?;
    let controller = RunController::new(
        manager,
        Arc::new(HeuristicLogAnalyzer),
        store.clone(),
        Arc::new(ExplicitPackageResolver),
        Arc::new(ImmediateClock),
        config,
    );
    controller.execute(&request.run_id, progress).await?;
    let record = store
        .get(&request.run_id)
        .await?
        .ok_or("record disappeared")?;
    Ok((directory, store, record))
}

fn worker_for(
    server: &MockServer,
    store: Arc<FileRunStore>,
    manager: Arc<dyn PackageManager>,
    accepting: Arc<AtomicBool>,
) -> Result<PackageHarnessWorker, Box<dyn Error>> {
    let clock: Arc<dyn Clock> = Arc::new(ImmediateClock);
    let store_port: Arc<dyn RunStore> = store;
    let controller = Arc::new(RunController::new(
        Arc::clone(&manager),
        Arc::new(HeuristicLogAnalyzer),
        Arc::clone(&store_port),
        Arc::new(ExplicitPackageResolver),
        Arc::clone(&clock),
        runner_config(),
    ));
    let coordinator = CoordinatorClient::new(
        &server.uri(),
        "worker-01".to_owned(),
        "worker-secret".to_owned(),
        Duration::from_secs(1),
    )?;
    Ok(PackageHarnessWorker::new(
        coordinator,
        WorkerDependencies {
            controller,
            package_manager: manager,
            store: store_port,
            clock,
        },
        WorkerConfig {
            worker_id: "worker-01".to_owned(),
            harness_dnp_name: "package-harness.dnp.dappnode.eth".to_owned(),
            poll_interval: Duration::from_millis(1),
            heartbeat_interval: Duration::from_millis(1),
            cleanup_timeout: Duration::from_millis(10),
        },
        WorkerReadiness::default(),
        accepting,
    ))
}

#[tokio::test]
async fn normal_run_persists_result_and_cleans_up() -> Result<(), Box<dyn Error>> {
    let request = request("normal-run")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        request.package.dnp_name.clone(),
    ));
    let observation = manager.clone();
    let (_directory, _store, record) = execute_with(request, manager, &NoopRunProgress).await?;
    assert_eq!(record.status, ExecutionStatus::Completed);
    assert_eq!(
        record.result.ok_or("missing result")?.verdict,
        Verdict::Passed
    );
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    assert_eq!(observation.cleanup_calls()?, 1);
    Ok(())
}

#[tokio::test]
async fn unstable_candidate_is_failed_but_still_cleaned() -> Result<(), Box<dyn Error>> {
    let request = request("unstable-candidate")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.candidate_running = false;
    let observation = manager.clone();
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    assert_eq!(
        record.result.ok_or("missing result")?.verdict,
        Verdict::Failed
    );
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    assert_eq!(observation.cleanup_calls()?, 1);
    Ok(())
}

#[tokio::test]
async fn transient_candidate_install_failure_is_infrastructure_error() -> Result<(), Box<dyn Error>>
{
    let request = request("candidate-infrastructure-failure")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.candidate_error = Some(PackageManagerError::Tool {
        tool: "dappnode_update_package".to_owned(),
        message: "Can't download image: Could not get block QmExample".to_owned(),
    });
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::InfrastructureError);
    assert_eq!(result.reason_code, ReasonCode::CandidateInstallFailed);
    assert_eq!(result.cleanup.status, CleanupStatus::Passed);
    Ok(())
}

#[tokio::test]
async fn deterministic_candidate_install_failure_is_failed() -> Result<(), Box<dyn Error>> {
    let request = request("candidate-deterministic-failure")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.candidate_error = Some(PackageManagerError::Tool {
        tool: "dappnode_update_package".to_owned(),
        message: "package manifest is invalid".to_owned(),
    });
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::Failed);
    assert_eq!(result.reason_code, ReasonCode::CandidateInstallFailed);
    Ok(())
}

#[tokio::test]
async fn installed_target_is_used_as_baseline_and_restored() -> Result<(), Box<dyn Error>> {
    let request = request("installed-baseline")?;
    let manager = Arc::new(
        ScriptedPackageManager::new(request.package.dnp_name.clone())
            .with_installed_baseline("/ipfs/QmOriginal")?,
    );
    let observation = manager.clone();
    let (_directory, _store, record) = execute_with(request, manager, &NoopRunProgress).await?;
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    assert_eq!(
        record.worker.baseline_restore_ref.as_deref(),
        Some("/ipfs/QmOriginal")
    );
    assert_eq!(observation.cleanup_calls()?, 0);
    assert_eq!(
        observation.installed_version()?.as_deref(),
        Some("/ipfs/QmOriginal")
    );
    Ok(())
}

#[tokio::test]
async fn expensive_baseline_is_retained_then_reused() -> Result<(), Box<dyn Error>> {
    let mut first_request = request("retained-baseline-first")?;
    first_request.package.baseline_ref = Some(PackageRef::parse("1.0.0")?);
    let manager = Arc::new(ScriptedPackageManager::new(
        first_request.package.dnp_name.clone(),
    ));
    let mut config = runner_config();
    config
        .retain_baseline_packages
        .insert(first_request.package.dnp_name.to_string());

    let (_directory, _store, first) = execute_with_config(
        first_request.clone(),
        manager.clone(),
        &NoopRunProgress,
        config.clone(),
    )
    .await?;
    assert_eq!(first.cleanup.status, CleanupStatus::Passed);
    assert_eq!(manager.cleanup_calls()?, 0);
    assert_eq!(manager.install_calls()?, 1);
    assert_eq!(manager.installed_version()?.as_deref(), Some("1.0.0"));
    assert!(matches!(
        first.worker.target_recovery,
        Some(TargetRecoveryPlan::Restore {
            baseline_ref,
            retained: true,
        }) if baseline_ref == "1.0.0"
    ));

    let mut second_request = first_request;
    second_request.run_id =
        dappnode_package_harness::model::RunId::parse("retained-baseline-second")?;
    let (_directory, _store, second) =
        execute_with_config(second_request, manager.clone(), &NoopRunProgress, config).await?;
    assert_eq!(second.cleanup.status, CleanupStatus::Passed);
    assert_eq!(
        manager.install_calls()?,
        1,
        "second run must reuse baseline"
    );
    assert_eq!(manager.installed_version()?.as_deref(), Some("1.0.0"));
    Ok(())
}

#[test]
fn legacy_worker_state_recovers_its_saved_baseline() -> Result<(), Box<dyn Error>> {
    let mut legacy = WorkerState {
        baseline_restore_ref: Some("1.2.3".to_owned()),
        ..WorkerState::default()
    };
    legacy.target_recovery = None;
    let mut value = serde_json::to_value(legacy)?;
    value
        .as_object_mut()
        .ok_or("worker state did not serialize as an object")?
        .remove("targetRecovery");
    let restored: WorkerState = serde_json::from_value(value)?;
    assert_eq!(
        restored.recovery_plan(),
        TargetRecoveryPlan::Restore {
            baseline_ref: "1.2.3".to_owned(),
            retained: false,
        }
    );
    Ok(())
}

#[tokio::test]
async fn explicit_baseline_is_honored_then_original_installation_is_restored()
-> Result<(), Box<dyn Error>> {
    let mut request = request("explicit-installed-baseline")?;
    request.package.baseline_ref = Some(PackageRef::parse("/ipfs/QmRequestedBaseline")?);
    let manager = Arc::new(
        ScriptedPackageManager::new(request.package.dnp_name.clone())
            .with_installed_baseline("/ipfs/QmOriginal")?,
    );
    let observation = manager.clone();
    let (_directory, _store, record) = execute_with(request, manager, &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(
        result.package.baseline_resolved_version.as_deref(),
        Some("/ipfs/QmRequestedBaseline")
    );
    assert_eq!(
        observation.update_versions()?,
        vec![
            "/ipfs/QmRequestedBaseline",
            "/ipfs/QmCandidate",
            "/ipfs/QmOriginal"
        ]
    );
    assert_eq!(
        observation.installed_version()?.as_deref(),
        Some("/ipfs/QmOriginal")
    );
    Ok(())
}

#[tokio::test]
async fn restoration_reinstalls_a_missing_preexisting_target() -> Result<(), Box<dyn Error>> {
    let request = request("restore-missing-target")?;
    let manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    let baseline_ref = PackageRef::parse("/ipfs/QmOriginal")?;
    let cleanup = restore_target(
        &manager,
        Arc::new(ImmediateClock),
        &request.package.dnp_name,
        &baseline_ref,
        Duration::from_millis(10),
    )
    .await;
    assert_eq!(cleanup.status, CleanupStatus::Passed);
    assert_eq!(manager.install_calls()?, 1);
    assert_eq!(
        manager.installed_version()?.as_deref(),
        Some("/ipfs/QmOriginal")
    );
    Ok(())
}

#[tokio::test]
async fn candidate_removing_target_still_restores_preexisting_baseline()
-> Result<(), Box<dyn Error>> {
    let request = request("candidate-removes-target")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone())
        .with_installed_baseline("/ipfs/QmOriginal")?;
    manager.candidate_removes_target = true;
    let observation = Arc::new(manager);
    let (_directory, _store, record) =
        execute_with(request, observation.clone(), &NoopRunProgress).await?;
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    assert_eq!(
        observation.installed_version()?.as_deref(),
        Some("/ipfs/QmOriginal")
    );
    Ok(())
}

#[tokio::test]
async fn unexpected_packages_left_by_cleanup_make_cleanup_fail() -> Result<(), Box<dyn Error>> {
    let request = request("cleanup-leftover")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.leave_extra_package = true;
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    assert_eq!(record.cleanup.status, CleanupStatus::Failed);
    assert_eq!(
        record.cleanup.leftover_packages,
        vec!["dependency.dnp.dappnode.eth"]
    );
    Ok(())
}

#[tokio::test]
async fn baseline_hard_check_uses_baseline_reason_code() -> Result<(), Box<dyn Error>> {
    let request = request("baseline-reason")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.baseline_running = false;
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(
        result.baseline.hard_check.reason_codes,
        vec![ReasonCode::BaselineContainersUnstable]
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_failure_promotes_a_pass_to_warning() -> Result<(), Box<dyn Error>> {
    let request = request("cleanup-failure")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.cleanup_failure = true;
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::Warning);
    assert_eq!(result.reason_code, ReasonCode::CleanupFailed);
    assert_eq!(result.cleanup.status, CleanupStatus::Failed);
    Ok(())
}

#[tokio::test]
async fn core_package_is_refused_before_any_mutation() -> Result<(), Box<dyn Error>> {
    let request = request("core-refused")?;
    let mut manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    manager.core = true;
    let observation = manager.clone();
    let (_directory, _store, record) =
        execute_with(request, Arc::new(manager), &NoopRunProgress).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.reason_code, ReasonCode::CorePackageRefused);
    assert_eq!(result.cleanup.status, CleanupStatus::Skipped);
    assert_eq!(observation.cleanup_calls()?, 0);
    Ok(())
}

#[tokio::test]
async fn cancellation_before_mutation_skips_install_and_cleanup() -> Result<(), Box<dyn Error>> {
    let request = request("cancelled")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        request.package.dnp_name.clone(),
    ));
    let observation = manager.clone();
    let progress = WorkerProgress::new();
    progress.request_cancellation();
    let (_directory, _store, record) = execute_with(request, manager, progress.as_ref()).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::Inconclusive);
    assert_eq!(result.reason_code, ReasonCode::CancellationRequested);
    assert_eq!(result.cleanup.status, CleanupStatus::Skipped);
    assert_eq!(observation.cleanup_calls()?, 0);
    Ok(())
}

#[tokio::test]
async fn stabilization_stops_when_progress_requests_cancellation() -> Result<(), Box<dyn Error>> {
    let request = request("cancel-stabilization")?;
    let manager = ScriptedPackageManager::new(request.package.dnp_name.clone());
    let progress = WorkerProgress::new();
    progress.request_cancellation();
    let result = stabilize(
        &manager,
        Arc::new(ImmediateClock),
        &request.package.dnp_name,
        StabilizationConfig {
            timeout: Duration::from_secs(1),
            poll_interval: Duration::from_millis(1),
            required_samples: 3,
        },
        progress.as_ref(),
    )
    .await;
    assert!(!result.passed);
    assert!(result.samples.is_empty());
    Ok(())
}

#[tokio::test]
async fn malformed_nexus_response_falls_back_to_heuristic() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"message": {"content": "not valid analyzer JSON"}}]
        })))
        .mount(&server)
        .await;
    let nexus = NexusLogAnalyzer::new(
        "test-key".to_owned(),
        server.uri(),
        "test-model".to_owned(),
        Duration::from_secs(1),
        4096,
    )?;
    let composite = CompositeLogAnalyzer::new(nexus);
    let result = composite
        .analyze(&LogAnalysisInput {
            baseline: Vec::new(),
            candidate: vec![(Some("service".to_owned()), "normal startup".to_owned())],
        })
        .await?;
    assert!(!result.analyzer_errors.is_empty());
    assert_eq!(
        result.status,
        dappnode_package_harness::model::AnalyzerStatus::Clean
    );
    Ok(())
}

#[test]
fn claim_fixture_is_strictly_validated() -> Result<(), Box<dyn Error>> {
    let response: ClaimResponse =
        serde_json::from_str(include_str!("fixtures/claim-response.json"))?;
    let claimed = dappnode_package_harness::coordinator::ClaimedJob::try_from(response)?;
    assert_eq!(
        claimed.request.run_id.to_string(),
        "gh-pr-42-0123456789ab-abcdef1234567890"
    );
    assert_eq!(
        claimed.claim_token,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    Ok(())
}

#[test]
fn complete_fixture_matches_the_protocol_shape() -> Result<(), Box<dyn Error>> {
    let completion = CompleteRequest {
        schema_version: 1,
        worker_id: "worker-01".to_owned(),
        claim_token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned(),
        outcome: dappnode_package_harness::coordinator::CompletionOutcome::WorkerError(
            dappnode_package_harness::coordinator::WorkerErrorCompletion {
                code: WorkerErrorCode::Interrupted,
                summary: "worker restarted before this job completed".to_owned(),
                cleanup_status: CleanupStatus::Passed,
            },
        ),
    };
    let actual: serde_json::Value = serde_json::to_value(completion)?;
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/complete-worker-error.json"))?;
    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn heartbeat_fixture_matches_the_protocol_shape() -> Result<(), Box<dyn Error>> {
    let heartbeat = HeartbeatRequest {
        schema_version: 1,
        worker_id: "worker-01",
        claim_token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        phase: "candidate_stabilization",
        cleanup_required: true,
    };
    let actual: serde_json::Value = serde_json::to_value(heartbeat)?;
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/heartbeat-request.json"))?;
    assert_eq!(actual, expected);
    Ok(())
}

#[tokio::test]
async fn coordinator_claims_with_required_headers_and_parses_response() -> Result<(), Box<dyn Error>>
{
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/claim"))
        .and(header("authorization", "Bearer worker-secret"))
        .and(header("content-type", "application/json"))
        .and(header("user-agent", "dappnode-package-harness/0.1.1"))
        .and(body_json(
            json!({ "schemaVersion": 1, "workerId": "worker-01" }),
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(include_str!("fixtures/claim-response.json")),
        )
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(
        &server.uri(),
        "worker-01".to_owned(),
        "worker-secret".to_owned(),
        Duration::from_secs(1),
    )?;
    let outcome = client.claim().await?;
    assert!(matches!(outcome, ClaimOutcome::Claimed(_)));
    Ok(())
}

#[tokio::test]
async fn coordinator_maps_no_work_and_heartbeat_cancellation() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/claim"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/job-1/heartbeat"))
        .and(body_json(json!({
            "schemaVersion": 1,
            "workerId": "worker-01",
            "claimToken": "claim",
            "phase": "candidate_stabilization",
            "cleanupRequired": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemaVersion": 1,
            "cancelRequested": true
        })))
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(
        &server.uri(),
        "worker-01".to_owned(),
        "worker-secret".to_owned(),
        Duration::from_secs(1),
    )?;
    assert_eq!(client.claim().await?, ClaimOutcome::NoWork);
    assert_eq!(
        client
            .heartbeat("job-1", "claim", "candidate_stabilization", true)
            .await?,
        HeartbeatOutcome::CancelRequested
    );
    Ok(())
}

#[tokio::test]
async fn coordinator_resends_exact_completion_bytes_and_accepts_duplicate()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    let body = include_str!("fixtures/complete-worker-error.json")
        .as_bytes()
        .to_vec();
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/job-1/complete"))
        .and(body_json(serde_json::from_slice::<serde_json::Value>(
            &body,
        )?))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemaVersion": 1,
            "disposition": "duplicate"
        })))
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(
        &server.uri(),
        "worker-01".to_owned(),
        "worker-secret".to_owned(),
        Duration::from_secs(1),
    )?;
    assert_eq!(
        client.complete_raw("job-1", body).await?,
        CompletionDisposition::Duplicate
    );
    Ok(())
}

#[tokio::test]
async fn coordinator_recognizes_lost_claim() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/job-1/heartbeat"))
        .respond_with(ResponseTemplate::new(409))
        .mount(&server)
        .await;
    let client = CoordinatorClient::new(
        &server.uri(),
        "worker-01".to_owned(),
        "worker-secret".to_owned(),
        Duration::from_secs(1),
    )?;
    assert_eq!(
        client.heartbeat("job-1", "claim", "analysis", true).await?,
        HeartbeatOutcome::ClaimLost
    );
    Ok(())
}

#[tokio::test]
async fn polling_worker_claims_executes_and_acknowledges_before_next_claim()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    let accepting = Arc::new(AtomicBool::new(true));
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/claim"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(include_str!("fixtures/claim-response.json")),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/package-harness/jobs/gh-pr-42-0123456789ab-abcdef1234567890/heartbeat",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "schemaVersion": 1,
            "cancelRequested": false
        })))
        .mount(&server)
        .await;
    let stop_after_completion = Arc::clone(&accepting);
    Mock::given(method("POST"))
        .and(path(
            "/v1/package-harness/jobs/gh-pr-42-0123456789ab-abcdef1234567890/complete",
        ))
        .respond_with(move |_: &wiremock::Request| {
            stop_after_completion.store(false, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_json(json!({
                "schemaVersion": 1,
                "disposition": "recorded"
            }))
        })
        .expect(1)
        .mount(&server)
        .await;

    let directory = tempfile::tempdir()?;
    let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
    let request = request("worker-observation")?;
    let manager: Arc<dyn PackageManager> = Arc::new(ScriptedPackageManager::new(
        request.package.dnp_name.clone(),
    ));
    let worker = worker_for(&server, Arc::clone(&store), manager, accepting)?;
    tokio::time::timeout(Duration::from_secs(2), worker.run()).await?;

    let job_id =
        dappnode_package_harness::model::RunId::parse("gh-pr-42-0123456789ab-abcdef1234567890")?;
    let record = store.get(&job_id).await?.ok_or("missing worker record")?;
    assert!(record.result.is_some());
    assert!(record.worker.completion_acknowledged);
    assert_eq!(
        record.worker.completion_disposition.as_deref(),
        Some("recorded")
    );
    assert!(record.worker.pending_completion_body.is_none());
    Ok(())
}

#[tokio::test]
async fn claimed_record_persists_claim_and_pending_completion_exactly() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let store = FileRunStore::new(directory.path().to_path_buf()).await?;
    let request = request("claim-persistence")?;
    let mut record = RunRecord::claimed(request.clone(), "opaque-claim-token".to_owned());
    record.worker.pending_completion_body =
        Some(include_str!("fixtures/complete-worker-error.json").to_owned());
    store.create(&record).await?;
    let loaded = store.get(&request.run_id).await?.ok_or("missing record")?;
    assert_eq!(
        loaded.worker.claim_token.as_deref(),
        Some("opaque-claim-token")
    );
    assert_eq!(
        loaded.worker.pending_completion_body.as_deref(),
        Some(include_str!("fixtures/complete-worker-error.json"))
    );
    Ok(())
}

#[test]
fn worker_progress_prioritizes_lost_claim_over_cancellation() {
    let progress = WorkerProgress::new();
    progress.request_cancellation();
    assert_eq!(progress.control(), RunControl::CancelRequested);
    progress.mark_claim_lost();
    assert_eq!(progress.control(), RunControl::ClaimLost);
}
