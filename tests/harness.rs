use std::{
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::{DateTime, Utc};
use dappnode_package_harness::{
    analysis::{CompositeLogAnalyzer, HeuristicLogAnalyzer, LogAnalyzer, NexusLogAnalyzer},
    api::{ApiState, router},
    clock::Clock,
    config::{Config, PackageManagerMode, ResultReporterMode},
    model::{
        CleanupStatus, ContainerLog, ContainerSnapshot, DnpName, ExecutionStatus,
        ExplicitPackageResolver, LogAnalysisInput, PackageDetails, PackageLogs, PackageRef,
        PackageSummary, PreviewSummary, ReasonCode, RunId, RunRecord, RunRequest, RunRequestDto,
        Verdict,
    },
    package_manager::{PackageManager, PackageManagerError, REQUIRED_MCP_TOOLS, ToolAvailability},
    reporting::{GithubPrCommentReporter, ResultReporter, WebhookResultReporter, signature},
    runner::{
        RunController, RunnerConfig,
        stabilization::{StabilizationConfig, stabilize},
    },
    storage::{FileRunStore, RunStore},
};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tower::ServiceExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[derive(Debug, Default)]
struct ImmediateClock;

#[async_trait]
impl Clock for ImmediateClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }

    async fn sleep(&self, _duration: Duration) {}
}

#[derive(Debug, Clone, Copy)]
enum BaselineFailure {
    RequiredSetup,
    Infrastructure,
}

#[derive(Debug, Clone)]
struct ScriptedPackageManager {
    target: DnpName,
    state: Arc<Mutex<ScriptedState>>,
    baseline_running: bool,
    candidate_running: bool,
    baseline_failure: Option<BaselineFailure>,
    candidate_install_failure: bool,
    cleanup_failure: bool,
    core: bool,
    missing_mutating_tools: bool,
}

#[derive(Debug, Clone, Default)]
struct ScriptedState {
    installed: bool,
    candidate: bool,
    cleanup_calls: usize,
}

impl ScriptedPackageManager {
    fn new(target: DnpName) -> Self {
        Self {
            target,
            state: Arc::new(Mutex::new(ScriptedState::default())),
            baseline_running: true,
            candidate_running: true,
            baseline_failure: None,
            candidate_install_failure: false,
            cleanup_failure: false,
            core: false,
            missing_mutating_tools: false,
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
}

#[async_trait]
impl PackageManager for ScriptedPackageManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        let available = if self.missing_mutating_tools {
            REQUIRED_MCP_TOOLS[..3]
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        } else {
            REQUIRED_MCP_TOOLS
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        };
        let missing = REQUIRED_MCP_TOOLS
            .iter()
            .filter(|tool| !available.iter().any(|available| available == **tool))
            .map(ToString::to_string)
            .collect();
        Ok(ToolAvailability { available, missing })
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        let state = self.state()?.clone();
        if state.installed || self.core {
            Ok(vec![PackageSummary {
                dnp_name: self.target.clone(),
                version: Some(
                    if state.candidate {
                        "candidate"
                    } else {
                        "baseline"
                    }
                    .to_owned(),
                ),
                is_core: self.core,
            }])
        } else {
            Ok(Vec::new())
        }
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
        Ok(details(
            dnp_name,
            if state.candidate {
                "candidate"
            } else {
                "baseline"
            },
            running,
            "service",
        ))
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
        _version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        match self.baseline_failure {
            Some(BaselineFailure::RequiredSetup) => return Err(PackageManagerError::RequiredSetup),
            Some(BaselineFailure::Infrastructure) => {
                return Err(PackageManagerError::Transport(
                    "simulated baseline transport failure".to_owned(),
                ));
            }
            None => {}
        }
        let mut state = self.state()?;
        state.installed = true;
        state.candidate = false;
        Ok(())
    }

    async fn update_package(
        &self,
        _dnp_name: &DnpName,
        _version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        if self.candidate_install_failure {
            return Err(PackageManagerError::Tool {
                tool: "dappnode_update_package".to_owned(),
                message: "simulated update failure".to_owned(),
            });
        }
        let mut state = self.state()?;
        state.installed = true;
        state.candidate = true;
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

fn request(run_id: &str) -> Result<RunRequest, Box<dyn Error>> {
    request_with(run_id, "/ipfs/candidate", None)
}

fn request_with(
    run_id: &str,
    candidate: &str,
    baseline: Option<&str>,
) -> Result<RunRequest, Box<dyn Error>> {
    let value = json!({
        "schemaVersion": 1,
        "runId": run_id,
        "source": {
            "repository": "dappnode/example-package",
            "pullRequest": 123,
            "headSha": "abcdef0123456789"
        },
        "package": {
            "dnpName": "example.dnp.dappnode.eth",
            "candidateRef": candidate,
            "baselineRef": baseline
        }
    });
    let dto: RunRequestDto = serde_json::from_value(value)?;
    Ok(RunRequest::try_from(dto)?)
}

fn request_for_name(run_id: &str, dnp_name: &str) -> Result<RunRequest, Box<dyn Error>> {
    let dto: RunRequestDto = serde_json::from_value(json!({
        "schemaVersion": 1,
        "runId": run_id,
        "source": {
            "repository": "dappnode/example-package",
            "pullRequest": 123,
            "headSha": "abcdef0123456789"
        },
        "package": {
            "dnpName": dnp_name,
            "candidateRef": "/ipfs/candidate"
        }
    }))?;
    Ok(RunRequest::try_from(dto)?)
}

fn details(dnp_name: &DnpName, version: &str, running: bool, name: &str) -> PackageDetails {
    PackageDetails {
        dnp_name: dnp_name.clone(),
        version: Some(version.to_owned()),
        containers: vec![ContainerSnapshot {
            name: name.to_owned(),
            service_name: Some("service".to_owned()),
            state: Some(if running { "running" } else { "exited" }.to_owned()),
            running,
            image: Some(format!("test:{version}")),
            created: None,
        }],
    }
}

async fn execute_with(
    run_request: RunRequest,
    manager: Arc<dyn PackageManager>,
) -> Result<(TempDir, Arc<FileRunStore>, RunRecord), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
    store.create(&RunRecord::new(run_request.clone())).await?;
    let store_port: Arc<dyn RunStore> = store.clone();
    let clock: Arc<dyn Clock> = Arc::new(ImmediateClock);
    let controller = RunController::new(
        manager,
        Arc::new(HeuristicLogAnalyzer),
        None,
        store_port,
        Arc::new(ExplicitPackageResolver),
        clock,
        runner_config(),
    );
    controller.execute(&run_request.run_id).await?;
    let record = store
        .get(&run_request.run_id)
        .await?
        .ok_or("run disappeared")?;
    Ok((directory, store, record))
}

fn runner_config() -> RunnerConfig {
    RunnerConfig {
        harness_dnp_name: "package-harness.dnp.dappnode.eth".to_owned(),
        stabilization: StabilizationConfig {
            timeout: Duration::from_millis(3),
            poll_interval: Duration::from_millis(1),
            required_samples: 3,
        },
        log_tail: 300,
        cleanup_enabled: true,
        cleanup_timeout: Duration::from_millis(2),
    }
}

fn test_config(data_dir: &std::path::Path) -> Config {
    Config {
        listen_addr: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        data_dir: data_dir.to_path_buf(),
        harness_api_token: Some("test-api-token".to_owned()),
        harness_dnp_name: "package-harness.dnp.dappnode.eth".to_owned(),
        allow_destructive_tests: true,
        package_manager_mode: PackageManagerMode::Fake,
        dappmanager_mcp_url: None,
        dappmanager_mcp_token: None,
        mcp_timeout: Duration::from_secs(1),
        stabilization_timeout: Duration::from_millis(3),
        stabilization_poll: Duration::from_millis(1),
        stabilization_required_samples: 3,
        log_tail: 300,
        cleanup_enabled: true,
        cleanup_timeout: Duration::from_millis(2),
        recover_cleanup_on_start: false,
        nexus_api_key: None,
        nexus_base_url: "http://unused".to_owned(),
        nexus_model: "test".to_owned(),
        nexus_timeout: Duration::from_secs(1),
        nexus_max_input_bytes: 4096,
        result_reporter_mode: ResultReporterMode::None,
        result_callback_url: None,
        result_callback_hmac_secret: None,
        result_callback_timeout: Duration::from_secs(1),
        github_app_id: None,
        github_app_private_key: None,
        github_api_base_url: "https://api.github.com".to_owned(),
    }
}

#[tokio::test]
async fn stable_baseline_and_candidate_pass() -> Result<(), Box<dyn Error>> {
    let run_request = request("stable-pass")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, record) = execute_with(run_request, manager).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::Passed);
    assert!(result.baseline.hard_check.passed);
    assert!(result.candidate.hard_check.passed);
    Ok(())
}

#[tokio::test]
async fn stable_baseline_and_unstable_candidate_fail() -> Result<(), Box<dyn Error>> {
    let run_request = request("candidate-unstable")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.candidate_running = false;
    let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
    assert_eq!(
        record.result.ok_or("missing result")?.verdict,
        Verdict::Failed
    );
    Ok(())
}

#[tokio::test]
async fn unstable_baseline_and_stable_candidate_warn() -> Result<(), Box<dyn Error>> {
    let run_request = request("baseline-unstable")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.baseline_running = false;
    let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
    assert_eq!(
        record.result.ok_or("missing result")?.verdict,
        Verdict::Warning
    );
    Ok(())
}

#[tokio::test]
async fn baseline_install_errors_are_classified() -> Result<(), Box<dyn Error>> {
    for (suffix, failure, expected) in [
        (
            "setup",
            BaselineFailure::RequiredSetup,
            Verdict::Inconclusive,
        ),
        (
            "transport",
            BaselineFailure::Infrastructure,
            Verdict::InfrastructureError,
        ),
    ] {
        let run_request = request(&format!("baseline-{suffix}"))?;
        let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
        scripted.baseline_failure = Some(failure);
        let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
        assert_eq!(record.result.ok_or("missing result")?.verdict, expected);
    }
    Ok(())
}

#[tokio::test]
async fn candidate_install_error_still_cleans_up() -> Result<(), Box<dyn Error>> {
    let run_request = request("candidate-install-error")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.candidate_install_failure = true;
    let observation = scripted.clone();
    let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    assert_eq!(observation.cleanup_calls()?, 1);
    assert_eq!(
        record.result.ok_or("missing result")?.verdict,
        Verdict::Failed
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_failure_promotes_pass_to_warning() -> Result<(), Box<dyn Error>> {
    let run_request = request("cleanup-failure")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.cleanup_failure = true;
    let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::Warning);
    assert_eq!(result.reason_code, ReasonCode::CleanupFailed);
    assert_eq!(result.cleanup.status, CleanupStatus::Failed);
    Ok(())
}

fn post_request(run_request: &RunRequest, token: &str) -> Result<Request<Body>, Box<dyn Error>> {
    Ok(Request::builder()
        .method("POST")
        .uri("/v1/runs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(run_request)?))?)
}

async fn api_fixture(
    manager: Arc<dyn PackageManager>,
) -> Result<
    (
        TempDir,
        Arc<FileRunStore>,
        axum::Router,
        mpsc::Receiver<RunId>,
    ),
    Box<dyn Error>,
> {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
    let (sender, receiver) = mpsc::channel(8);
    let state = ApiState {
        config: Arc::new(test_config(directory.path())),
        store: store.clone(),
        package_manager: manager,
        queue: sender,
        accepting: Arc::new(AtomicBool::new(true)),
    };
    Ok((directory, store, router(state), receiver))
}

#[tokio::test]
async fn identical_duplicate_run_is_idempotent() -> Result<(), Box<dyn Error>> {
    let run_request = request("duplicate-identical")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, app, _receiver) = api_fixture(manager).await?;
    let first = app
        .clone()
        .oneshot(post_request(&run_request, "test-api-token")?)
        .await?;
    let second = app
        .oneshot(post_request(&run_request, "test-api-token")?)
        .await?;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn conflicting_duplicate_run_returns_conflict() -> Result<(), Box<dyn Error>> {
    let first_request = request("duplicate-conflict")?;
    let second_request = request_with("duplicate-conflict", "/ipfs/different", None)?;
    let manager = Arc::new(ScriptedPackageManager::new(
        first_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, app, _receiver) = api_fixture(manager).await?;
    let first = app
        .clone()
        .oneshot(post_request(&first_request, "test-api-token")?)
        .await?;
    let second = app
        .oneshot(post_request(&second_request, "test-api-token")?)
        .await?;
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(second.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
async fn invalid_api_bearer_is_rejected() -> Result<(), Box<dyn Error>> {
    let run_request = request("invalid-auth")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, app, _receiver) = api_fixture(manager).await?;
    let response = app
        .oneshot(post_request(
            &run_request,
            "wrong-token-with-different-length",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn missing_mutating_tools_fail_readiness() -> Result<(), Box<dyn Error>> {
    let run_request = request("readiness-tools")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.missing_mutating_tools = true;
    let (_directory, _store, app, _receiver) = api_fixture(Arc::new(scripted)).await?;
    let response = app
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 16 * 1024).await?;
    assert!(String::from_utf8(body.to_vec())?.contains("mutating tools are probably disabled"));
    Ok(())
}

#[derive(Debug)]
struct ChangingSetManager {
    target: DnpName,
    call: AtomicUsize,
}

#[async_trait]
impl PackageManager for ChangingSetManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        Ok(ToolAvailability {
            available: Vec::new(),
            missing: Vec::new(),
        })
    }

    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        Ok(Vec::new())
    }

    async fn get_package_details(
        &self,
        dnp_name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        let call = self.call.fetch_add(1, Ordering::SeqCst);
        let name = if call == 1 { "changed" } else { "service" };
        Ok(details(dnp_name, "test", true, name))
    }

    async fn get_package_logs(
        &self,
        _dnp_name: &DnpName,
        _tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        Ok(PackageLogs {
            entries: Vec::new(),
        })
    }

    async fn preview_install(
        &self,
        _dnp_name: &DnpName,
        _version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        Err(PackageManagerError::NotFound)
    }

    async fn install_package(
        &self,
        _dnp_name: &DnpName,
        _version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        Err(PackageManagerError::NotFound)
    }

    async fn update_package(
        &self,
        _dnp_name: &DnpName,
        _version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        Err(PackageManagerError::NotFound)
    }

    async fn remove_package(
        &self,
        _dnp_name: &DnpName,
        _delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        Ok(())
    }
}

#[tokio::test]
async fn stabilization_requires_same_consecutive_container_set() -> Result<(), Box<dyn Error>> {
    let run_request = request("stable-set")?;
    let manager = ChangingSetManager {
        target: run_request.package.dnp_name.clone(),
        call: AtomicUsize::new(0),
    };
    let result = stabilize(
        &manager,
        Arc::new(ImmediateClock),
        &manager.target,
        StabilizationConfig {
            timeout: Duration::from_millis(6),
            poll_interval: Duration::from_millis(1),
            required_samples: 3,
        },
    )
    .await;
    assert!(result.passed);
    assert_eq!(result.samples.len(), 5);
    Ok(())
}

#[tokio::test]
async fn invalid_nexus_json_falls_back_to_heuristic() -> Result<(), Box<dyn Error>> {
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

#[tokio::test]
async fn no_nexus_key_still_completes_run() -> Result<(), Box<dyn Error>> {
    let run_request = request("no-nexus")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, record) = execute_with(run_request, manager).await?;
    assert_eq!(record.status, ExecutionStatus::Completed);
    assert!(record.evidence.log_analysis.is_some());
    Ok(())
}

#[tokio::test]
async fn callback_hmac_covers_exact_request_body() -> Result<(), Box<dyn Error>> {
    let run_request = request("callback-signature")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, record) = execute_with(run_request, manager).await?;
    let result = record.result.ok_or("missing result")?;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let reporter = WebhookResultReporter::new(
        server.uri(),
        "callback-secret".to_owned(),
        Duration::from_secs(1),
        Arc::new(ImmediateClock),
    )?;
    reporter.report(&result).await?;
    let requests = server
        .received_requests()
        .await
        .ok_or("request recording disabled")?;
    let callback = requests.first().ok_or("callback not received")?;
    let header = callback
        .headers
        .get("x-dappnode-harness-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or("signature header missing")?;
    let expected = signature(b"callback-secret", &callback.body)?;
    assert_eq!(header, format!("sha256={expected}"));
    let raw = serde_json::to_vec(&result)?;
    assert_eq!(callback.body, raw);

    let mut independent = Hmac::<Sha256>::new_from_slice(b"callback-secret")?;
    independent.update(&raw);
    assert_eq!(expected, hex::encode(independent.finalize().into_bytes()));
    Ok(())
}

#[tokio::test]
async fn callback_retries_transient_but_not_regular_client_errors() -> Result<(), Box<dyn Error>> {
    let run_request = request("callback-retry")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, record) = execute_with(run_request, manager).await?;
    let result = record.result.ok_or("missing result")?;

    let transient_server = MockServer::start().await;
    let transient_calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = Arc::clone(&transient_calls);
    Mock::given(method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            if responder_calls.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200)
            }
        })
        .mount(&transient_server)
        .await;
    let transient_reporter = WebhookResultReporter::new(
        transient_server.uri(),
        "secret".to_owned(),
        Duration::from_secs(1),
        Arc::new(ImmediateClock),
    )?;
    let outcome = transient_reporter.report(&result).await?;
    assert_eq!(outcome.attempts, 3);
    assert_eq!(transient_calls.load(Ordering::SeqCst), 3);

    let client_error_server = MockServer::start().await;
    let client_error_calls = Arc::new(AtomicUsize::new(0));
    let responder_calls = Arc::clone(&client_error_calls);
    Mock::given(method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            responder_calls.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
        })
        .mount(&client_error_server)
        .await;
    let client_error_reporter = WebhookResultReporter::new(
        client_error_server.uri(),
        "secret".to_owned(),
        Duration::from_secs(1),
        Arc::new(ImmediateClock),
    )?;
    let error = client_error_reporter
        .report(&result)
        .await
        .err()
        .ok_or("400 callback unexpectedly succeeded")?;
    assert_eq!(error.attempts, 1);
    assert_eq!(client_error_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn github_reporter_posts_markdown_pr_comment() -> Result<(), Box<dyn Error>> {
    let run_request = request("github-comment")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, record) = execute_with(run_request, manager).await?;
    let result = record.result.ok_or("missing result")?;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
        .mount(&server)
        .await;

    let reporter = GithubPrCommentReporter::new_with_token(
        server.uri(),
        "github-token".to_owned(),
        Duration::from_secs(1),
        Arc::new(ImmediateClock),
    )?;
    let outcome = reporter.report(&result).await?;
    assert_eq!(outcome.http_status, Some(201));

    let requests = server
        .received_requests()
        .await
        .ok_or("request recording disabled")?;
    let request = requests.first().ok_or("GitHub comment not received")?;
    assert_eq!(
        request.url.path(),
        "/repos/dappnode/example-package/issues/123/comments"
    );
    assert_eq!(
        request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer github-token")
    );
    assert_eq!(
        request
            .headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok()),
        Some("dappnode-package-harness")
    );
    let body: serde_json::Value = serde_json::from_slice(&request.body)?;
    let comment = body
        .get("body")
        .and_then(serde_json::Value::as_str)
        .ok_or("GitHub comment body missing")?;
    assert!(comment.contains("Dappnode package harness"));
    assert!(comment.contains("<!-- dappnode-package-harness:github-comment -->"));
    assert!(comment.contains("`example.dnp.dappnode.eth`"));
    Ok(())
}

#[tokio::test]
async fn harness_identity_is_rejected_at_api_boundary() -> Result<(), Box<dyn Error>> {
    let run_request = request_for_name("harness-self-test", "package-harness.dnp.dappnode.eth")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let (_directory, _store, app, _receiver) = api_fixture(manager).await?;
    let response = app
        .oneshot(post_request(&run_request, "test-api-token")?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[tokio::test]
async fn core_package_is_refused_before_mutation() -> Result<(), Box<dyn Error>> {
    let run_request = request("core-package")?;
    let mut scripted = ScriptedPackageManager::new(run_request.package.dnp_name.clone());
    scripted.core = true;
    let observation = scripted.clone();
    let (_directory, _store, record) = execute_with(run_request, Arc::new(scripted)).await?;
    let result = record.result.ok_or("missing result")?;
    assert_eq!(result.verdict, Verdict::InfrastructureError);
    assert_eq!(result.reason_code, ReasonCode::CorePackageRefused);
    assert_eq!(observation.cleanup_calls()?, 0);
    Ok(())
}

#[tokio::test]
async fn persisted_run_does_not_contain_configured_secrets() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = FileRunStore::new(directory.path().to_path_buf()).await?;
    let run_request = request("secret-persistence")?;
    store.create(&RunRecord::new(run_request.clone())).await?;
    let bytes = tokio::fs::read(
        directory
            .path()
            .join(format!("{}.json", run_request.run_id.as_str())),
    )
    .await?;
    let persisted = String::from_utf8(bytes)?;
    for secret in [
        "test-api-token",
        "dappmanager-mcp-secret",
        "nexus-api-secret",
        "callback-hmac-secret",
    ] {
        assert!(!persisted.contains(secret));
    }
    Ok(())
}

#[tokio::test]
async fn api_submission_executes_and_returns_versioned_result() -> Result<(), Box<dyn Error>> {
    let run_request = request("api-integration")?;
    let manager = Arc::new(ScriptedPackageManager::new(
        run_request.package.dnp_name.clone(),
    ));
    let manager_port: Arc<dyn PackageManager> = manager;
    let (_directory, store, app, mut receiver) = api_fixture(Arc::clone(&manager_port)).await?;
    let accepted = app
        .clone()
        .oneshot(post_request(&run_request, "test-api-token")?)
        .await?;
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let queued_run = receiver.recv().await.ok_or("queue closed")?;
    let store_port: Arc<dyn RunStore> = store.clone();
    let controller = RunController::new(
        manager_port,
        Arc::new(HeuristicLogAnalyzer),
        None,
        store_port,
        Arc::new(ExplicitPackageResolver),
        Arc::new(ImmediateClock),
        runner_config(),
    );
    controller.execute(&queued_run).await?;

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/runs/{}", run_request.run_id))
                .header("authorization", "Bearer test-api-token")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    let record: RunRecord = serde_json::from_slice(&body)?;
    let result = record.result.ok_or("result missing from API response")?;
    assert_eq!(result.schema_version, 1);
    assert_eq!(result.verdict, Verdict::Passed);
    assert_eq!(result.cleanup.status, CleanupStatus::Passed);
    Ok(())
}
