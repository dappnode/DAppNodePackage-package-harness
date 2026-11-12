use async_trait::async_trait;
use dappnode_package_harness::{
    clock::TokioClock,
    model::{
        CleanupStatus, DnpName, PackageDetails, PackageLogs, PackageRef, PackageSummary,
        PreviewSummary, TargetRecoveryPlan,
    },
    package_manager::{FakePackageManager, PackageManager, PackageManagerError, ToolAvailability},
    runner::{
        NoopRunProgress,
        cleanup::{RecoverySpec, reconcile_target},
        readiness::{PackageReadiness, ReadinessProfiles},
        stabilization::{StabilizationConfig, stabilize},
    },
};
use serde_json::json;
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};

struct ObservedManager {
    inner: FakePackageManager,
    calls: AtomicUsize,
    health: Vec<Option<String>>,
    restarts: Vec<u64>,
    ids: Vec<String>,
    read_delay: Duration,
    broken_after_restore: bool,
    restores: AtomicUsize,
    candidate: Arc<AtomicBool>,
    wrong_restored_version: bool,
    registry_unavailable: bool,
    removals: AtomicUsize,
    version_drifts_after_readiness: bool,
    remove_core_after_restore: bool,
}

impl ObservedManager {
    async fn new(name: &DnpName) -> Result<Self, PackageManagerError> {
        let inner = FakePackageManager::new();
        inner.install_package(name, None).await?;
        Ok(Self {
            inner,
            calls: AtomicUsize::new(0),
            health: vec![Some("healthy".into())],
            restarts: vec![0],
            ids: vec!["container-1".into()],
            read_delay: Duration::ZERO,
            broken_after_restore: false,
            restores: AtomicUsize::new(0),
            candidate: Arc::new(AtomicBool::new(false)),
            wrong_restored_version: false,
            registry_unavailable: false,
            removals: AtomicUsize::new(0),
            version_drifts_after_readiness: false,
            remove_core_after_restore: false,
        })
    }
}

#[async_trait]
impl PackageManager for ObservedManager {
    async fn verify_tools(&self) -> Result<ToolAvailability, PackageManagerError> {
        self.inner.verify_tools().await
    }
    async fn list_packages(&self) -> Result<Vec<PackageSummary>, PackageManagerError> {
        let mut packages = self.inner.list_packages().await?;
        if self.remove_core_after_restore && self.restores.load(Ordering::SeqCst) > 0 {
            packages.retain(|package| !package.is_core);
        }
        Ok(packages)
    }
    async fn get_package_details(
        &self,
        name: &DnpName,
    ) -> Result<PackageDetails, PackageManagerError> {
        tokio::time::sleep(self.read_delay).await;
        let index = self.calls.fetch_add(1, Ordering::SeqCst);
        let mut details = self.inner.get_package_details(name).await?;
        if self.wrong_restored_version && self.restores.load(Ordering::SeqCst) > 0 {
            details.version = Some("9.9.9".to_owned());
        }
        if self.version_drifts_after_readiness && index >= 4 {
            details.version = Some("9.9.9".to_owned());
        }
        for container in &mut details.containers {
            container.health = self
                .health
                .get(index)
                .or_else(|| self.health.last())
                .cloned()
                .flatten();
            container.restart_count = self
                .restarts
                .get(index)
                .or_else(|| self.restarts.last())
                .copied();
            container.container_id = self.ids.get(index).or_else(|| self.ids.last()).cloned();
            if self.broken_after_restore && self.restores.load(Ordering::SeqCst) > 0 {
                container.health = Some("unhealthy".into());
            }
        }
        Ok(details)
    }
    async fn get_package_logs(
        &self,
        name: &DnpName,
        tail: usize,
    ) -> Result<PackageLogs, PackageManagerError> {
        self.inner.get_package_logs(name, tail).await
    }
    async fn preview_install(
        &self,
        name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<PreviewSummary, PackageManagerError> {
        if self.registry_unavailable && version.is_none() {
            return Err(PackageManagerError::Tool {
                tool: "dappnode_fetch_install_preview".into(),
                message: "registry unavailable".into(),
            });
        }
        self.inner.preview_install(name, version).await
    }
    async fn install_package(
        &self,
        name: &DnpName,
        version: Option<&PackageRef>,
    ) -> Result<(), PackageManagerError> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        self.candidate.store(false, Ordering::SeqCst);
        self.inner.install_package(name, version).await
    }
    async fn update_package(
        &self,
        name: &DnpName,
        version: &PackageRef,
    ) -> Result<(), PackageManagerError> {
        self.inner.update_package(name, version).await?;
        self.candidate.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn remove_package(
        &self,
        name: &DnpName,
        delete_volumes: bool,
    ) -> Result<(), PackageManagerError> {
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.inner.remove_package(name, delete_volumes).await
    }
}

fn name() -> Result<DnpName, Box<dyn Error>> {
    Ok(DnpName::parse("example.dnp.dappnode.eth")?)
}
fn config() -> StabilizationConfig {
    StabilizationConfig {
        timeout: Duration::from_millis(150),
        poll_interval: Duration::from_millis(5),
        required_samples: 3,
    }
}
fn profile(probes: serde_json::Value) -> Result<PackageReadiness, Box<dyn Error>> {
    Ok(ReadinessProfiles::from_json(
        &json!({"example.dnp.dappnode.eth":{"probes":probes}}).to_string(),
    )?
    .for_package("example.dnp.dappnode.eth"))
}

#[tokio::test]
async fn a_running_container_waits_for_its_application_to_be_ready() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    let requests = Arc::new(AtomicUsize::new(0));
    let seen = requests.clone();
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(move |_: &wiremock::Request| {
            if seen.fetch_add(1, Ordering::SeqCst) < 2 {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_string("application ready")
            }
        })
        .mount(&server)
        .await;
    let name = name()?;
    let manager = ObservedManager::new(&name).await?;
    let policy = profile(
        json!([{"type":"http","name":"api","url":format!("{}/health",server.uri()),"bodyContains":"application ready"}]),
    )?;
    let result = stabilize(
        &manager,
        Arc::new(TokioClock),
        &name,
        config(),
        &NoopRunProgress,
        &policy,
    )
    .await;
    assert!(result.passed);
    assert!(requests.load(Ordering::SeqCst) >= 5);
    assert!(result.samples[0].all_running);
    assert!(!result.samples[0].probe_results[0].passed);
    assert!(result.samples.last().ok_or("no samples")?.probe_results[0].passed);
    Ok(())
}

#[tokio::test]
async fn unhealthy_and_required_but_missing_docker_health_cannot_pass() -> Result<(), Box<dyn Error>>
{
    let name = name()?;
    for health in [Some("unhealthy".into()), Some("starting".into()), None] {
        let mut manager = ObservedManager::new(&name).await?;
        manager.health = vec![health];
        let policy = PackageReadiness {
            require_docker_health: true,
            ..Default::default()
        };
        let result = stabilize(
            &manager,
            Arc::new(TokioClock),
            &name,
            config(),
            &NoopRunProgress,
            &policy,
        )
        .await;
        assert!(!result.passed);
        assert!(!result.last_non_running_states.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn restart_counts_and_recreated_containers_reset_the_stability_window()
-> Result<(), Box<dyn Error>> {
    let name = name()?;
    for recreated in [false, true] {
        let mut manager = ObservedManager::new(&name).await?;
        if recreated {
            manager.ids = vec!["old".into(), "new".into()];
        } else {
            manager.restarts = vec![0, 1];
        }
        let result = stabilize(
            &manager,
            Arc::new(TokioClock),
            &name,
            config(),
            &NoopRunProgress,
            &Default::default(),
        )
        .await;
        assert!(result.passed);
        assert!(manager.calls.load(Ordering::SeqCst) >= 4);
    }
    Ok(())
}

#[tokio::test]
async fn slow_metadata_and_application_reads_obey_the_wall_clock_deadline()
-> Result<(), Box<dyn Error>> {
    let name = name()?;
    let mut manager = ObservedManager::new(&name).await?;
    manager.read_delay = Duration::from_secs(2);
    let short = StabilizationConfig {
        timeout: Duration::from_millis(60),
        ..config()
    };
    let started = Instant::now();
    let result = stabilize(
        &manager,
        Arc::new(TokioClock),
        &name,
        short,
        &NoopRunProgress,
        &Default::default(),
    )
    .await;
    assert!(!result.passed);
    assert!(started.elapsed() < Duration::from_millis(500));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;
    manager.read_delay = Duration::ZERO;
    let policy = profile(json!([{"type":"http","name":"api","url":server.uri()}]))?;
    let started = Instant::now();
    let result = stabilize(
        &manager,
        Arc::new(TokioClock),
        &name,
        short,
        &NoopRunProgress,
        &policy,
    )
    .await;
    assert!(!result.passed);
    assert!(started.elapsed() < Duration::from_millis(500));
    Ok(())
}

#[tokio::test]
async fn rpc_errors_are_not_readiness_and_probe_credentials_are_not_reported()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer private-test-value"))
        .and(body_json(
            json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"id":1,"error":{"message":"private-test-value"},"result":null}),
            ),
        )
        .mount(&server)
        .await;
    let policy = profile(
        json!([{"type":"json_rpc","name":"chain","url":server.uri(),"method":"eth_blockNumber","headers":{"Authorization":"Bearer private-test-value"}}]),
    )?;
    let result = policy.probes[0]
        .check(&dappnode_package_harness::runner::readiness::client()?)
        .await;
    assert!(!result.passed);
    assert!(!serde_json::to_string(&result)?.contains("private-test-value"));
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":1,"result":"0x42"})))
        .mount(&server)
        .await;
    assert!(
        policy.probes[0]
            .check(&dappnode_package_harness::runner::readiness::client()?)
            .await
            .passed
    );
    Ok(())
}

#[tokio::test]
async fn redirects_do_not_forward_probe_credentials() -> Result<(), Box<dyn Error>> {
    let first = MockServer::start().await;
    let second = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", second.uri()))
        .mount(&first)
        .await;
    let policy = profile(
        json!([{"type":"http","name":"api","url":first.uri(),"headers":{"Authorization":"Bearer private-test-value"}}]),
    )?;
    assert!(
        !policy.probes[0]
            .check(&dappnode_package_harness::runner::readiness::client()?)
            .await
            .passed
    );
    assert!(
        second
            .received_requests()
            .await
            .ok_or("request recording unavailable")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn restored_but_unhealthy_packages_fail_cleanup_verification() -> Result<(), Box<dyn Error>> {
    let name = name()?;
    let mut manager = ObservedManager::new(&name).await?;
    manager.broken_after_restore = true;
    let initial = manager.list_packages().await?;
    let (cleanup, _) = reconcile_target(
        &manager,
        Arc::new(TokioClock),
        &name,
        RecoverySpec {
            plan: TargetRecoveryPlan::RestoreLatest,
            baseline_ref: None,
            initial_packages: &initial,
            readiness: &Default::default(),
            stabilization: config(),
        },
        config().timeout,
    )
    .await;
    assert_ne!(cleanup.status, CleanupStatus::Passed);
    assert!(
        cleanup
            .error
            .as_deref()
            .is_some_and(|error| error.contains("readiness verification"))
    );
    Ok(())
}

#[test]
fn invalid_profiles_and_mutating_rpc_methods_are_rejected_without_secret_echoes() {
    for value in [
        json!({"example.dnp.dappnode.eth":{"probes":[{"type":"json_rpc","name":"bad","url":"http://node","method":"eth_sendRawTransaction"}]}}),
        json!({"example.dnp.dappnode.eth":{"probes":[{"type":"http","name":"api","url":"http://user:private-test-value@node"}]}}),
        json!({"example.dnp.dappnode.eth":{"probes":[{"type":"http","name":"api","url":"http://node","headers":{"Authorization":"private-test-value\r\ninjected: bad"}}]}}),
    ] {
        let error = ReadinessProfiles::from_json(&value.to_string()).err();
        assert!(error.is_some());
        assert!(!error.unwrap_or_default().contains("private-test-value"));
    }
}

#[tokio::test]
async fn a_wrong_restored_version_is_detected_and_registry_failure_does_not_remove_a_package()
-> Result<(), Box<dyn Error>> {
    let name = name()?;
    for unavailable in [false, true] {
        let mut manager = ObservedManager::new(&name).await?;
        manager.wrong_restored_version = !unavailable;
        manager.registry_unavailable = unavailable;
        let initial = manager.list_packages().await?;
        let (cleanup, _) = reconcile_target(
            &manager,
            Arc::new(TokioClock),
            &name,
            RecoverySpec {
                plan: TargetRecoveryPlan::RestoreLatest,
                baseline_ref: None,
                initial_packages: &initial,
                readiness: &Default::default(),
                stabilization: config(),
            },
            config().timeout,
        )
        .await;
        assert_eq!(cleanup.status, CleanupStatus::Failed);
        if unavailable {
            assert_eq!(manager.removals.load(Ordering::SeqCst), 0);
            assert_eq!(manager.restores.load(Ordering::SeqCst), 0);
        } else {
            assert!(
                cleanup
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("resolved latest release"))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn candidate_application_regressions_fail_the_test_and_healthy_restoration_passes()
-> Result<(), Box<dyn Error>> {
    use dappnode_package_harness::{
        analysis::HeuristicLogAnalyzer,
        model::{
            ExplicitPackageResolver, PackageRequestDto, RunRecord, RunRequest, RunRequestDto,
            SourceDto, Verdict,
        },
        runner::{RunController, RunnerConfig},
        storage::{FileRunStore, RunStore},
    };
    let name = name()?;
    let manager = Arc::new(ObservedManager::new(&name).await?);
    let candidate = manager.candidate.clone();
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(move |_: &wiremock::Request| {
            ResponseTemplate::new(if candidate.load(Ordering::SeqCst) {
                503
            } else {
                200
            })
        })
        .mount(&server)
        .await;
    let profiles = ReadinessProfiles::from_json(
        &json!({name.as_str():{"probes":[{"type":"http","name":"api","url":server.uri()}]}})
            .to_string(),
    )?;
    let directory = tempfile::tempdir()?;
    let store = Arc::new(FileRunStore::new(directory.path().to_path_buf()).await?);
    let request = RunRequest::try_from(RunRequestDto {
        schema_version: 1,
        run_id: "application-readiness-regression".into(),
        source: SourceDto {
            repository: "dappnode/example".into(),
            pull_request: 1,
            head_sha: "abcdef1234567890".into(),
        },
        package: PackageRequestDto {
            dnp_name: name.to_string(),
            baseline_ref: None,
            candidate_ref: "/ipfs/QmCandidate".into(),
        },
    })?;
    store.create(&RunRecord::new(request.clone())).await?;
    let controller = RunController::new(
        manager,
        Arc::new(HeuristicLogAnalyzer),
        store.clone(),
        Arc::new(ExplicitPackageResolver),
        Arc::new(TokioClock),
        RunnerConfig {
            harness_dnp_name: "package-harness.dnp.dappnode.eth".into(),
            stabilization: config(),
            log_tail: 10,
            cleanup_timeout: Duration::from_secs(1),
            readiness_profiles: Arc::new(profiles),
        },
    );
    controller
        .execute(&request.run_id, &NoopRunProgress)
        .await?;
    let record = store.get(&request.run_id).await?.ok_or("missing result")?;
    let result = record.result.as_ref().ok_or("result missing")?;
    assert_eq!(result.verdict, Verdict::Failed);
    assert!(result.baseline.hard_check.passed);
    assert!(!result.candidate.hard_check.passed);
    assert_eq!(record.cleanup.status, CleanupStatus::Passed);
    let observed = &record
        .evidence
        .baseline
        .as_ref()
        .ok_or("baseline missing")?
        .details
        .as_ref()
        .ok_or("details missing")?
        .containers[0];
    assert_eq!(observed.health.as_deref(), Some("healthy"));
    let wire = serde_json::to_value(result)?;
    for key in ["health", "restartCount", "containerId", "startedAt"] {
        assert!(
            wire["baseline"]["containers"][0].get(key).is_none(),
            "v1 coordinator schema changed: {key}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn post_readiness_version_drift_and_missing_preexisting_packages_fail_cleanup()
-> Result<(), Box<dyn Error>> {
    let name = name()?;
    for drift in [true, false] {
        let mut manager = ObservedManager::new(&name).await?;
        manager.version_drifts_after_readiness = drift;
        manager.remove_core_after_restore = !drift;
        let initial = manager.list_packages().await?;
        let (cleanup, _) = reconcile_target(
            &manager,
            Arc::new(TokioClock),
            &name,
            RecoverySpec {
                plan: TargetRecoveryPlan::RestoreLatest,
                baseline_ref: None,
                initial_packages: &initial,
                readiness: &Default::default(),
                stabilization: config(),
            },
            config().timeout,
        )
        .await;
        assert_eq!(cleanup.status, CleanupStatus::Failed);
        let message = cleanup.error.ok_or("cleanup failure reason missing")?;
        assert!(message.contains(if drift {
            "after readiness"
        } else {
            "pre-existing packages"
        }));
    }
    Ok(())
}

#[tokio::test]
async fn tcp_probes_require_a_reachable_listener() -> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let policy = profile(
        json!([{"type":"tcp","name":"database-listener","host":"127.0.0.1","port":address.port()}]),
    )?;
    let client = dappnode_package_harness::runner::readiness::client()?;
    assert!(policy.probes[0].check(&client).await.passed);
    drop(listener);
    assert!(!policy.probes[0].check(&client).await.passed);
    Ok(())
}
