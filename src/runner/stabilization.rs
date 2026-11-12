use crate::{
    analysis::redaction::redact_and_bound,
    clock::Clock,
    model::{DnpName, StabilizationResult, StabilizationSample},
    package_manager::PackageManager,
    runner::{
        RunControl, RunProgress,
        readiness::{self, PackageReadiness, ProbeResult},
    },
};
use std::{sync::Arc, time::Duration};
use tokio::time::Instant;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy)]
pub struct StabilizationConfig {
    /// Wall-clock deadline covering reads, probes, and polling sleeps.
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub required_samples: usize,
}

/// Require a stable, healthy container identity set and successful configured
/// application probes for consecutive samples, all within one real deadline.
pub async fn stabilize(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    config: StabilizationConfig,
    progress: &dyn RunProgress,
    policy: &PackageReadiness,
) -> StabilizationResult {
    let started = clock.now();
    let deadline = Instant::now() + config.timeout;
    let max_attempts = ((config.timeout.as_millis() / config.poll_interval.as_millis().max(1))
        as usize)
        .saturating_add(1)
        .min(10_000);
    let mut consecutive = 0;
    let mut expected_identity = None;
    let mut samples = Vec::new();
    let mut last_non_running_states = Vec::new();
    let client = if policy.probes.is_empty() {
        None
    } else {
        readiness::client().ok()
    };
    info!(event = "stabilization_started", dnp_name = %dnp_name, timeout_ms = config.timeout.as_millis() as u64,
        required_stable_samples = config.required_samples, configured_probes = policy.probes.len(), "Checking container and application readiness");
    for attempt in 0..max_attempts {
        if !matches!(progress.control(), RunControl::Continue) || Instant::now() >= deadline {
            break;
        }
        let mut sample = StabilizationSample {
            observed_at: clock.now().to_rfc3339(),
            container_names: Vec::new(),
            all_running: false,
            non_running_states: Vec::new(),
            error: None,
            probe_results: Vec::new(),
        };
        let mut identity = Vec::new();
        match tokio::time::timeout_at(deadline, package_manager.get_package_details(dnp_name)).await
        {
            Ok(Ok(details)) if details.dnp_name == *dnp_name => {
                for container in &details.containers {
                    sample.container_names.push(container.name.clone());
                    identity.push((
                        container.name.clone(),
                        container.container_id.clone(),
                        container.created.clone(),
                        container.restart_count,
                        container.started_at.clone(),
                    ));
                    if !container.running
                        || container
                            .state
                            .as_deref()
                            .is_some_and(|state| state != "running")
                    {
                        sample.non_running_states.push(format!(
                            "{}:{}",
                            container.name,
                            container.state.as_deref().unwrap_or("unknown")
                        ));
                    }
                    match container.health.as_deref() {
                        Some("healthy") => {}
                        None | Some("none") if !policy.require_docker_health => {}
                        health => sample.non_running_states.push(format!(
                            "{}:Docker health {}",
                            container.name,
                            health.unwrap_or("not reported")
                        )),
                    }
                }
                identity.sort();
                sample.container_names.sort();
                sample.all_running =
                    !details.containers.is_empty() && sample.non_running_states.is_empty();
                if sample.all_running {
                    if let Some(client) = &client {
                        for probe in &policy.probes {
                            let result = match tokio::time::timeout_at(
                                deadline,
                                probe.check(client),
                            )
                            .await
                            {
                                Ok(result) => result,
                                Err(_) => ProbeResult {
                                    name: probe.name().to_owned(),
                                    passed: false,
                                    error: Some("readiness deadline exceeded".to_owned()),
                                },
                            };
                            sample.probe_results.push(result);
                            if Instant::now() >= deadline {
                                break;
                            }
                        }
                    } else if !policy.probes.is_empty() {
                        sample.error =
                            Some("could not initialize application probe client".to_owned());
                    }
                }
            }
            Ok(Ok(_)) => sample.error = Some("Dappmanager returned a different package".to_owned()),
            Ok(Err(error)) => sample.error = Some(redact_and_bound(&error.to_string(), 300)),
            Err(_) => {
                sample.error = Some("package details exceeded the readiness deadline".to_owned())
            }
        }
        let ready = sample.all_running
            && sample.error.is_none()
            && sample.probe_results.len() == policy.probes.len()
            && sample.probe_results.iter().all(|result| result.passed);
        if ready {
            consecutive = if expected_identity.as_ref() == Some(&identity) {
                consecutive + 1
            } else {
                1
            };
            expected_identity = Some(identity);
        } else {
            consecutive = 0;
            expected_identity = None;
        }
        if !sample.non_running_states.is_empty() {
            last_non_running_states = sample.non_running_states.clone();
        }
        for probe in &sample.probe_results {
            if !probe.passed {
                last_non_running_states.push(format!(
                    "probe {}: {}",
                    probe.name,
                    probe.error.as_deref().unwrap_or("not ready")
                ));
            }
        }
        last_non_running_states.truncate(100);
        info!(event = "stabilization_sample", dnp_name = %dnp_name, sample = attempt + 1,
            all_ready = ready, stable_samples = consecutive, non_running = ?sample.non_running_states,
            probe_results = ?sample.probe_results, error = sample.error.as_deref(), "Readiness sample collected");
        if samples.len() == 100 {
            samples.remove(0);
        }
        samples.push(sample);
        if consecutive >= config.required_samples && Instant::now() < deadline {
            return StabilizationResult {
                passed: true,
                stable_samples: consecutive,
                duration_ms: elapsed_ms(started, clock.now()),
                samples,
                last_non_running_states,
            };
        }
        if attempt + 1 < max_attempts {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if tokio::time::timeout_at(deadline, clock.sleep(config.poll_interval.min(remaining)))
                .await
                .is_err()
            {
                break;
            }
        }
    }
    warn!(event = "stabilization_incomplete", dnp_name = %dnp_name, stable_samples = consecutive,
        "Container and application readiness did not pass");
    StabilizationResult {
        passed: false,
        stable_samples: consecutive,
        duration_ms: elapsed_ms(started, clock.now()),
        samples,
        last_non_running_states,
    }
}

fn elapsed_ms(start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}
