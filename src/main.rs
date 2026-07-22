use std::{
    env,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use dappnode_package_harness::{
    analysis::{CompositeLogAnalyzer, HeuristicLogAnalyzer, LogAnalyzer, NexusLogAnalyzer},
    api::{ApiState, router},
    clock::{Clock, TokioClock},
    config::{Config, PackageManagerMode},
    coordinator::CoordinatorClient,
    model::ExplicitPackageResolver,
    package_manager::{
        DappmanagerPackageManager, FakePackageManager, PackageManager, UnavailablePackageManager,
    },
    runner::{RunController, RunnerConfig, stabilization::StabilizationConfig},
    storage::{FileRunStore, RunStore},
    worker::{PackageHarnessWorker, WorkerConfig, WorkerDependencies, WorkerReadiness},
};
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Existing process variables win over a local development .env file.
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    info!(
        event = "config_loaded",
        listen_addr = %config.listen_addr,
        data_dir = %config.data_dir.display(),
        harness_dnp_name = %config.harness_dnp_name,
        package_manager_mode = ?config.package_manager_mode,
        destructive_tests_allowed = config.allow_destructive_tests,
        stabilization_timeout_ms = config.stabilization_timeout.as_millis() as u64,
        stabilization_poll_ms = config.stabilization_poll.as_millis() as u64,
        stabilization_required_samples = config.stabilization_required_samples,
        cleanup_enabled = config.cleanup_enabled,
        cleanup_timeout_ms = config.cleanup_timeout.as_millis() as u64,
        retained_baseline_packages = ?config.retain_baseline_packages,
        log_tail_lines = config.log_tail,
        poll_seconds = config.package_harness_poll.as_secs(),
        heartbeat_seconds = config.package_harness_heartbeat.as_secs(),
        nexus_enabled = config.nexus_api_key.is_some(),
    );
    let package_manager = package_manager(&config);
    debug!(
        event = "package_manager_ready",
        mode = ?config.package_manager_mode,
    );
    if env::args().any(|argument| argument == "--mcp-smoke") {
        return mcp_smoke(package_manager).await;
    }
    let store: Arc<dyn RunStore> = Arc::new(FileRunStore::new(config.data_dir.clone()).await?);
    info!(event = "run_store_ready", data_dir = %config.data_dir.display());
    let clock: Arc<dyn Clock> = Arc::new(TokioClock);
    let controller = Arc::new(RunController::new(
        Arc::clone(&package_manager),
        analyzer(&config)?,
        Arc::clone(&store),
        Arc::new(ExplicitPackageResolver),
        Arc::clone(&clock),
        RunnerConfig {
            harness_dnp_name: config.harness_dnp_name.clone(),
            stabilization: StabilizationConfig {
                timeout: config.stabilization_timeout,
                poll_interval: config.stabilization_poll,
                required_samples: config.stabilization_required_samples,
            },
            log_tail: config.log_tail,
            cleanup_enabled: config.cleanup_enabled,
            cleanup_timeout: config.cleanup_timeout,
            retain_baseline_packages: config.retain_baseline_packages.clone(),
        },
    ));
    let coordinator = CoordinatorClient::new(
        &config.tropibot_url,
        config.package_harness_worker_id.clone(),
        config.package_harness_worker_token.clone(),
        config.tropibot_timeout,
    )?;
    info!(
        event = "coordinator_client_ready",
        tropibot_url = %config.tropibot_url,
        worker_id = %config.package_harness_worker_id,
        tropibot_timeout_ms = config.tropibot_timeout.as_millis() as u64,
        mcp_enabled = config.dappmanager_mcp_url.is_some(),
    );
    let accepting = Arc::new(AtomicBool::new(true));
    let worker_readiness = WorkerReadiness::default();
    worker_readiness.set_not_ready("worker is reconciling local state");
    let worker = PackageHarnessWorker::new(
        coordinator,
        WorkerDependencies {
            controller,
            package_manager: Arc::clone(&package_manager),
            store: Arc::clone(&store),
            clock,
        },
        WorkerConfig {
            worker_id: config.package_harness_worker_id.clone(),
            harness_dnp_name: config.harness_dnp_name.clone(),
            poll_interval: config.package_harness_poll,
            heartbeat_interval: config.package_harness_heartbeat,
            cleanup_timeout: config.cleanup_timeout,
        },
        worker_readiness.clone(),
        Arc::clone(&accepting),
    );
    let worker = tokio::spawn(worker.run());
    debug!(event = "worker_spawned");
    let state = ApiState {
        config: Arc::clone(&config),
        package_manager,
        worker_readiness,
    };
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(address = %config.listen_addr, event = "supervision_server_started");
    debug!(event = "supervision_server_binding_complete");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal(Arc::clone(&accepting)))
        .await?;
    info!(event = "supervision_server_stopped");
    match tokio::time::timeout(Duration::from_secs(300), worker).await {
        Ok(result) => {
            info!(event = "worker_shutdown_complete");
            result?;
        }
        Err(_) => {
            error!(event = "worker_shutdown_timeout", timeout_seconds = 300);
        }
    }
    Ok(())
}

fn package_manager(config: &Config) -> Arc<dyn PackageManager> {
    match config.package_manager_mode {
        PackageManagerMode::Fake => Arc::new(FakePackageManager::new()),
        PackageManagerMode::Mcp => match (
            config.dappmanager_mcp_url.clone(),
            config.dappmanager_mcp_token.clone(),
        ) {
            (Some(url), Some(token)) => DappmanagerPackageManager::new(
                url,
                token,
                config.mcp_timeout,
                config.mcp_mutation_timeout,
                config.mcp_mutation_attempts,
                config.mcp_mutation_retry_delay,
            )
            .map_or_else(
                |error| {
                    Arc::new(UnavailablePackageManager::new(error.to_string()))
                        as Arc<dyn PackageManager>
                },
                |manager| Arc::new(manager) as Arc<dyn PackageManager>,
            ),
            _ => Arc::new(UnavailablePackageManager::new(
                "Dappmanager MCP configuration is incomplete",
            )),
        },
    }
}

fn analyzer(config: &Config) -> Result<Arc<dyn LogAnalyzer>, Box<dyn Error>> {
    match &config.nexus_api_key {
        Some(api_key) => {
            let nexus = NexusLogAnalyzer::new(
                api_key.clone(),
                config.nexus_base_url.clone(),
                config.nexus_model.clone(),
                config.nexus_timeout,
                config.nexus_max_input_bytes,
            )?;
            Ok(Arc::new(CompositeLogAnalyzer::new(nexus)))
        }
        None => Ok(Arc::new(HeuristicLogAnalyzer)),
    }
}

async fn mcp_smoke(package_manager: Arc<dyn PackageManager>) -> Result<(), Box<dyn Error>> {
    let tools = package_manager.verify_tools().await?;
    if !tools
        .available
        .iter()
        .any(|tool| tool == "dappnode_list_packages")
    {
        return Err("dappnode_list_packages is not available".into());
    }
    let packages = package_manager.list_packages().await?;
    println!("{}", serde_json::to_string_pretty(&packages)?);
    Ok(())
}

async fn shutdown_signal(accepting: Arc<AtomicBool>) {
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
    accepting.store(false, Ordering::SeqCst);
    info!(event = "shutdown_started");
}
