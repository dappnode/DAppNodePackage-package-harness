use std::{
    env,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use dappnode_package_harness::{
    analysis::{CompositeLogAnalyzer, HeuristicLogAnalyzer, LogAnalyzer, NexusLogAnalyzer},
    api::{ApiState, router},
    clock::{Clock, TokioClock},
    config::{Config, PackageManagerMode},
    coordinator::CoordinatorClient,
    model::ExplicitPackageResolver,
    package_manager::{
        DappmanagerPackageManager, FakePackageManager, PackageManager, PackageManagerError,
    },
    runner::{RunController, RunnerConfig, stabilization::StabilizationConfig},
    startup::validate_dependencies,
    storage::{FileRunStore, RunStore},
    worker::{
        PackageHarnessWorker, WorkerConfig, WorkerDependencies, WorkerDrainControl,
        WorkerReadiness, WorkerRecoveryControl,
    },
};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Existing process variables win over a local development .env file.
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                EnvFilter::new("dappnode_package_harness=info,tower_http=info")
            }),
        )
        // Event names and fields preserve machine-searchable structure. Hiding
        // Rust module targets makes the default Docker log view much easier to
        // scan; module-specific RUST_LOG filters continue to work normally.
        .with_target(false)
        .with_ansi(false)
        .compact()
        .init();

    let config = Arc::new(Config::from_env()?);
    if !env::args().any(|argument| argument == "--mcp-smoke")
        && let Some(error) = config.acceptance_error()
    {
        return Err(error.into());
    }
    info!(
        event = "harness_starting",
        version = %env!("CARGO_PKG_VERSION"),
        worker_id = %config.package_harness_worker_id,
        listen_addr = %config.listen_addr,
        data_dir = %config.data_dir.display(),
        "Package Harness starting"
    );
    info!(
        event = "execution_policy_loaded",
        harness_dnp_name = %config.harness_dnp_name,
        package_manager_mode = ?config.package_manager_mode,
        destructive_tests_allowed = config.allow_destructive_tests,
        mcp_read_timeout_ms = config.mcp_timeout.as_millis() as u64,
        mcp_mutation_timeout_ms = config.mcp_mutation_timeout.as_millis() as u64,
        mcp_mutation_attempts = config.mcp_mutation_attempts,
        mcp_mutation_retry_delay_ms = config.mcp_mutation_retry_delay.as_millis() as u64,
        stabilization_timeout_ms = config.stabilization_timeout.as_millis() as u64,
        stabilization_poll_ms = config.stabilization_poll.as_millis() as u64,
        stabilization_required_samples = config.stabilization_required_samples,
        cleanup_timeout_ms = config.cleanup_timeout.as_millis() as u64,
        log_tail_lines = config.log_tail,
        "Execution policy loaded"
    );
    info!(
        event = "integration_policy_loaded",
        poll_seconds = config.package_harness_poll.as_secs(),
        heartbeat_seconds = config.package_harness_heartbeat.as_secs(),
        nexus_enabled = config.nexus_api_key.is_some(),
        nexus_model = %config.nexus_model,
        nexus_timeout_ms = config.nexus_timeout.as_millis() as u64,
        nexus_max_input_bytes = config.nexus_max_input_bytes,
        "Coordinator and analyzer policy loaded"
    );
    let package_manager = package_manager(&config)?;
    debug!(
        event = "package_manager_ready",
        mode = ?config.package_manager_mode,
    );
    if env::args().any(|argument| argument == "--mcp-smoke") {
        return mcp_smoke(package_manager).await;
    }
    let store: Arc<dyn RunStore> = Arc::new(FileRunStore::new(config.data_dir.clone()).await?);
    debug!(
        event = "run_store_ready",
        data_dir = %config.data_dir.display(),
        "Local run store ready"
    );
    let clock: Arc<dyn Clock> = Arc::new(TokioClock);
    let controller = Arc::new(RunController::new(
        Arc::clone(&package_manager),
        analyzer(&config)?,
        Arc::clone(&store),
        Arc::new(ExplicitPackageResolver),
        Arc::clone(&clock),
        RunnerConfig {
            readiness_profiles: Arc::new(config.readiness_profiles.clone()),
            harness_dnp_name: config.harness_dnp_name.clone(),
            stabilization: StabilizationConfig {
                timeout: config.stabilization_timeout,
                poll_interval: config.stabilization_poll,
                required_samples: config.stabilization_required_samples,
            },
            log_tail: config.log_tail,
            cleanup_timeout: config.cleanup_timeout,
        },
    ));
    let coordinator = CoordinatorClient::new(
        &config.tropibot_url,
        config.package_harness_worker_id.clone(),
        config.package_harness_worker_token.clone(),
        config.tropibot_timeout,
    )?;
    debug!(
        event = "coordinator_client_ready",
        tropibot_url = %config.tropibot_url,
        worker_id = %config.package_harness_worker_id,
        tropibot_timeout_ms = config.tropibot_timeout.as_millis() as u64,
        mcp_enabled = config.package_manager_mode == PackageManagerMode::Mcp,
        "Tropibot coordinator client ready"
    );
    info!(
        event = "startup_validation_started",
        "Validating dependencies before accepting jobs"
    );
    validate_dependencies(&config, package_manager.as_ref(), &coordinator).await?;
    // Bind before spawning: a port conflict must never leave a worker claiming jobs.
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(
        event = "startup_validation_passed",
        "Startup checks passed; worker may reconcile local state and accept jobs"
    );
    let accepting = Arc::new(AtomicBool::new(true));
    let worker_readiness = WorkerReadiness::default();
    let worker_recovery_control = WorkerRecoveryControl::default();
    let worker_drain_control = WorkerDrainControl::default();
    worker_readiness.set_not_ready("worker is reconciling local state");
    let worker = PackageHarnessWorker::new(
        coordinator.clone(),
        WorkerDependencies {
            controller,
            package_manager: Arc::clone(&package_manager),
            store: Arc::clone(&store),
            clock,
        },
        WorkerConfig {
            readiness_profiles: Arc::new(config.readiness_profiles.clone()),
            stabilization: StabilizationConfig {
                timeout: config.stabilization_timeout,
                poll_interval: config.stabilization_poll,
                required_samples: config.stabilization_required_samples,
            },
            worker_id: config.package_harness_worker_id.clone(),
            harness_dnp_name: config.harness_dnp_name.clone(),
            poll_interval: config.package_harness_poll,
            heartbeat_interval: config.package_harness_heartbeat,
            cleanup_timeout: config.cleanup_timeout,
        },
        worker_readiness.clone(),
        worker_recovery_control.clone(),
        worker_drain_control.clone(),
        Arc::clone(&accepting),
    );
    let worker = tokio::spawn(worker.run());
    debug!(event = "worker_spawned");
    let state = ApiState {
        config: Arc::clone(&config),
        package_manager,
        store,
        coordinator,
        worker_readiness,
        worker_recovery_control: worker_recovery_control.clone(),
        worker_drain_control: worker_drain_control.clone(),
    };
    info!(
        event = "supervision_server_started",
        address = %config.listen_addr,
        "Supervision server listening"
    );
    debug!(event = "supervision_server_binding_complete");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal(
            Arc::clone(&accepting),
            worker_recovery_control,
            worker_drain_control,
        ))
        .await?;
    info!(
        event = "supervision_server_stopped",
        "Supervision server stopped"
    );
    worker.await?;
    info!(
        event = "worker_shutdown_complete",
        "Worker shutdown complete"
    );
    Ok(())
}

fn package_manager(config: &Config) -> Result<Arc<dyn PackageManager>, PackageManagerError> {
    match config.package_manager_mode {
        PackageManagerMode::Fake => Ok(Arc::new(FakePackageManager::new())),
        PackageManagerMode::Mcp => {
            let url = config.dappmanager_mcp_url.clone().ok_or_else(|| {
                PackageManagerError::Configuration(
                    "DAPPMANAGER_MCP_URL must be configured".to_owned(),
                )
            })?;
            let token = config.dappmanager_mcp_token.clone().ok_or_else(|| {
                PackageManagerError::Configuration(
                    "DAPPMANAGER_MCP_TOKEN must be configured".to_owned(),
                )
            })?;
            Ok(Arc::new(DappmanagerPackageManager::new(
                url,
                token,
                config.mcp_timeout,
                config.mcp_mutation_timeout,
                config.mcp_mutation_attempts,
                config.mcp_mutation_retry_delay,
            )?))
        }
    }
}

fn analyzer(config: &Config) -> Result<Arc<dyn LogAnalyzer>, Box<dyn Error>> {
    match &config.nexus_api_key {
        Some(api_key) => {
            let nexus = NexusLogAnalyzer::new(
                api_key.clone(),
                &config.nexus_base_url,
                config.nexus_model.clone(),
                config.nexus_timeout,
                config.nexus_max_input_bytes,
            )?
            .with_classifier_model(config.nexus_classifier_model.clone());
            Ok(Arc::new(CompositeLogAnalyzer::new(nexus)))
        }
        None => Ok(Arc::new(HeuristicLogAnalyzer)),
    }
}

async fn mcp_smoke(package_manager: Arc<dyn PackageManager>) -> Result<(), Box<dyn Error>> {
    let tools = package_manager.verify_tools().await?;
    if !tools.ready() {
        return Err(tools.message().into());
    }
    let packages = package_manager.list_packages().await?;
    println!("{}", serde_json::to_string_pretty(&packages)?);
    Ok(())
}

async fn shutdown_signal(
    accepting: Arc<AtomicBool>,
    worker_recovery_control: WorkerRecoveryControl,
    worker_drain_control: WorkerDrainControl,
) {
    let ctrl_c = async {
        if let Err(signal_error) = tokio::signal::ctrl_c().await {
            error!(event = "signal_error", error = %signal_error);
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(signal_error) => error!(event = "signal_error", error = %signal_error),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    worker_drain_control.request_drain();
    accepting.store(false, Ordering::SeqCst);
    worker_recovery_control.resume();
    info!(
        event = "shutdown_started",
        "Shutdown requested; finishing safe work"
    );
}
