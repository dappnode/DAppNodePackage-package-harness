use std::{sync::Arc, time::Duration};

use crate::{
    clock::Clock,
    model::{DnpName, StabilizationResult, StabilizationSample},
    package_manager::PackageManager,
    runner::RunProgress,
};

/// Polling policy for the container stabilization hard check.
#[derive(Debug, Clone, Copy)]
pub struct StabilizationConfig {
    /// Maximum wall-clock time spent waiting for stable containers.
    pub timeout: Duration,
    /// Delay between package detail samples.
    pub poll_interval: Duration,
    /// Consecutive identical all-running samples required to pass.
    pub required_samples: usize,
}

/// Waits until every container in the package is running for enough samples.
///
/// A single all-running sample is not enough: the container name set must stay
/// identical across the required consecutive samples. That catches packages
/// that briefly report healthy while containers are still being recreated.
pub async fn stabilize(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    config: StabilizationConfig,
    progress: &dyn RunProgress,
) -> StabilizationResult {
    let started = clock.now();
    let poll_millis = config.poll_interval.as_millis().max(1);
    let max_attempts = ((config.timeout.as_millis() / poll_millis) as usize)
        .saturating_add(1)
        .min(10_000);
    let mut consecutive = 0_usize;
    let mut expected_names: Option<Vec<String>> = None;
    let mut samples = Vec::new();
    let mut last_non_running_states = Vec::new();

    for attempt in 0..max_attempts {
        if !matches!(progress.control(), crate::runner::RunControl::Continue) {
            break;
        }
        let observed_at = clock.now().to_rfc3339();
        match package_manager.get_package_details(dnp_name).await {
            Ok(details) => {
                let mut names = details
                    .containers
                    .iter()
                    .map(|container| container.name.clone())
                    .collect::<Vec<_>>();
                names.sort();
                let non_running = details
                    .containers
                    .iter()
                    .filter(|container| !container.running)
                    .map(|container| {
                        format!(
                            "{}:{}",
                            container.name,
                            container.state.as_deref().unwrap_or("unknown")
                        )
                    })
                    .collect::<Vec<_>>();
                let all_running = !details.containers.is_empty() && non_running.is_empty();
                if !non_running.is_empty() {
                    last_non_running_states = non_running.clone();
                }
                if all_running {
                    // Require the same sorted container set on each passing
                    // sample so a replacement container resets the streak.
                    if expected_names.as_ref() == Some(&names) {
                        consecutive = consecutive.saturating_add(1);
                    } else {
                        expected_names = Some(names.clone());
                        consecutive = 1;
                    }
                } else {
                    consecutive = 0;
                    expected_names = None;
                }
                push_sample(
                    &mut samples,
                    StabilizationSample {
                        observed_at,
                        container_names: names,
                        all_running,
                        non_running_states: non_running,
                        error: None,
                    },
                );
                if consecutive >= config.required_samples {
                    return StabilizationResult {
                        passed: true,
                        stable_samples: consecutive,
                        duration_ms: elapsed_ms(started, clock.now()),
                        samples,
                        last_non_running_states,
                    };
                }
            }
            Err(error) => {
                consecutive = 0;
                expected_names = None;
                push_sample(
                    &mut samples,
                    StabilizationSample {
                        observed_at,
                        container_names: Vec::new(),
                        all_running: false,
                        non_running_states: Vec::new(),
                        error: Some(crate::analysis::redaction::truncate_utf8(
                            &error.to_string(),
                            300,
                        )),
                    },
                );
            }
        }
        if attempt + 1 < max_attempts {
            clock.sleep(config.poll_interval).await;
            if !matches!(progress.control(), crate::runner::RunControl::Continue) {
                break;
            }
        }
    }
    StabilizationResult {
        passed: false,
        stable_samples: consecutive,
        duration_ms: elapsed_ms(started, clock.now()).max(config.timeout.as_millis() as u64),
        samples,
        last_non_running_states,
    }
}

fn push_sample(samples: &mut Vec<StabilizationSample>, sample: StabilizationSample) {
    const MAX_HISTORY: usize = 100;
    // Keep evidence bounded even if callers configure a long timeout.
    if samples.len() == MAX_HISTORY {
        samples.remove(0);
    }
    samples.push(sample);
}

fn elapsed_ms(start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}
