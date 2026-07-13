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
    analysis::{
        CompositeLogAnalyzer, HeuristicLogAnalyzer, LogAnalyzer, NexusLogAnalyzer,
        redaction::truncate_utf8,
    },
    api::{ApiState, router},
    clock::{Clock, TokioClock},
    config::{Config, PackageManagerMode, ResultReporterMode},
    model::{CleanupResult, CleanupStatus, ExecutionStatus, ExplicitPackageResolver, RunRecord},
    package_manager::{
        DappmanagerPackageManager, FakePackageManager, PackageManager, UnavailablePackageManager,
    },
    reporting::{GithubPrCommentReporter, ResultReporter, WebhookResultReporter},
    runner::{
        RunController, RunnerConfig, cleanup::cleanup_target, stabilization::StabilizationConfig,
    },
    storage::{FileRunStore, RunStore},
};
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load environment variables from a local .env file if one exists.
    // Existing process env vars always win. Safe to call when no .env is present.
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let config = Arc::new(Config::from_env()?);
    let package_manager = package_manager(&config);
    if env::args().any(|argument| argument == "--mcp-smoke") {
        return mcp_smoke(package_manager).await;
    }
    let store: Arc<dyn RunStore> = Arc::new(FileRunStore::new(config.data_dir.clone()).await?);
    let clock: Arc<dyn Clock> = Arc::new(TokioClock);
    let analyzer = analyzer(&config)?;
    let reporter = reporter(&config, Arc::clone(&clock))?;
    let controller = Arc::new(RunController::new(
        Arc::clone(&package_manager),
        analyzer,
        reporter,
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
        },
    ));
    let (queue_sender, mut queue_receiver) = mpsc::channel(256);
    let accepting = Arc::new(AtomicBool::new(true));

    for mut record in store.load_all().await? {
        match record.status {
            ExecutionStatus::Queued => {
                queue_sender.send(record.request.run_id).await?;
            }
            ExecutionStatus::Running => {
                record.interrupt();
                if config.recover_cleanup_on_start {
                    recover_interrupted_target(
                        &config,
                        package_manager.as_ref(),
                        Arc::clone(&clock),
                        &mut record,
                    )
                    .await;
                }
                store.save(&record).await?;
            }
            ExecutionStatus::Completed | ExecutionStatus::Interrupted => {}
        }
    }

    let worker = tokio::spawn(async move {
        while let Some(run_id) = queue_receiver.recv().await {
            if let Err(run_error) = controller.execute(&run_id).await {
                error!(run_id = %run_id, event = "run_worker_error", error = %run_error);
            }
        }
    });
    let state = ApiState {
        config: Arc::clone(&config),
        store,
        package_manager,
        queue: queue_sender,
        accepting: Arc::clone(&accepting),
    };
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(address = %config.listen_addr, event = "server_started");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal(accepting))
        .await?;
    match tokio::time::timeout(Duration::from_secs(300), worker).await {
        Ok(result) => result?,
        Err(_) => error!(event = "worker_shutdown_timeout"),
    }
    Ok(())
}

async fn recover_interrupted_target(
    config: &Config,
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    record: &mut RunRecord,
) {
    let target = &record.request.package.dnp_name;
    if target.as_str() == config.harness_dnp_name {
        return;
    }
    let packages = match package_manager.list_packages().await {
        Ok(packages) => packages,
        Err(cleanup_error) => {
            record.cleanup = CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(&cleanup_error.to_string(), 300)),
            };
            return;
        }
    };
    let target_package = packages.iter().find(|package| package.dnp_name == *target);
    if target_package.is_none_or(|package| package.is_core) {
        return;
    }
    record.cleanup = cleanup_target(package_manager, clock, target, config.cleanup_timeout).await;
}

fn package_manager(config: &Config) -> Arc<dyn PackageManager> {
    match config.package_manager_mode {
        PackageManagerMode::Fake => Arc::new(FakePackageManager::new()),
        PackageManagerMode::Mcp => match (
            config.dappmanager_mcp_url.clone(),
            config.dappmanager_mcp_token.clone(),
        ) {
            (Some(url), Some(token)) => {
                DappmanagerPackageManager::new(url, token, config.mcp_timeout).map_or_else(
                    |error| {
                        Arc::new(UnavailablePackageManager::new(error.to_string()))
                            as Arc<dyn PackageManager>
                    },
                    |manager| Arc::new(manager) as Arc<dyn PackageManager>,
                )
            }
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

fn reporter(
    config: &Config,
    clock: Arc<dyn Clock>,
) -> Result<Option<Arc<dyn ResultReporter>>, Box<dyn Error>> {
    match config.result_reporter_mode {
        ResultReporterMode::None => Ok(None),
        ResultReporterMode::Webhook => {
            let url = config
                .result_callback_url
                .as_ref()
                .ok_or("RESULT_CALLBACK_URL is required for webhook reporting")?;
            let secret = config
                .result_callback_hmac_secret
                .as_ref()
                .ok_or("RESULT_CALLBACK_HMAC_SECRET is required for webhook reporting")?;
            Ok(Some(Arc::new(WebhookResultReporter::new(
                url.clone(),
                secret.clone(),
                config.result_callback_timeout,
                clock,
            )?)))
        }
        ResultReporterMode::GithubPrComment => {
            let app_id = config
                .github_app_id
                .as_ref()
                .ok_or("GITHUB_APP_ID is required for github_pr_comment reporting")?;
            let private_key = config.github_app_private_key.as_ref().ok_or(
                "GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_FILE is required for github_pr_comment reporting",
            )?;
            Ok(Some(Arc::new(GithubPrCommentReporter::new(
                config.github_api_base_url.clone(),
                app_id.clone(),
                private_key.clone(),
                config.result_callback_timeout,
                clock,
            )?)))
        }
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
