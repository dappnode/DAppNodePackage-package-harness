use std::{collections::BTreeSet, sync::Arc, time::Duration};

use tracing::{info, warn};

use crate::{
    analysis::redaction::truncate_utf8,
    clock::Clock,
    model::{CleanupResult, CleanupStatus, DnpName, PackageRef, PackageSummary},
    package_manager::PackageManager,
};

pub async fn cleanup_target(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    timeout: Duration,
) -> CleanupResult {
    let started = clock.now();
    info!(
        event = "cleanup_remove_started",
        dnp_name = %dnp_name,
        delete_volumes = true,
        verification_timeout_ms = timeout.as_millis() as u64,
        "[cleanup] Removing the test package and its volumes"
    );
    if let Err(error) = package_manager.remove_package(dnp_name, true).await
        && !matches!(error, crate::package_manager::PackageManagerError::NotFound)
    {
        warn!(
            event = "cleanup_remove_failed",
            dnp_name = %dnp_name,
            duration_ms = elapsed_ms(started, clock.now()),
            error = %error,
            "[error] Dappmanager could not remove the test package"
        );
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    let poll = Duration::from_millis(500);
    let attempts = ((timeout.as_millis() / poll.as_millis()) as usize)
        .saturating_add(1)
        .min(1_000);
    for attempt in 0..attempts {
        match package_manager.list_packages().await {
            Ok(packages) if !packages.iter().any(|package| &package.dnp_name == dnp_name) => {
                info!(
                    event = "cleanup_remove_verified",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    verification_samples = attempt + 1,
                    "[ok] Package removal verified"
                );
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(_) => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    info!(
                        event = "cleanup_remove_waiting",
                        dnp_name = %dnp_name,
                        sample = attempt + 1,
                        max_samples = attempts,
                        elapsed_ms = elapsed_ms(started, clock.now()),
                        "[progress] Waiting for package removal to become visible"
                    );
                }
            }
            Err(error) if attempt + 1 == attempts => {
                warn!(
                    event = "cleanup_verification_failed",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    error = %error,
                    "[error] Final package-removal verification failed"
                );
                return CleanupResult {
                    status: CleanupStatus::Failed,
                    leftover_packages: Vec::new(),
                    error: Some(truncate_utf8(&error.to_string(), 300)),
                };
            }
            Err(_) => {}
        }
        if attempt + 1 < attempts {
            clock.sleep(poll).await;
        }
    }
    warn!(
        event = "cleanup_remove_timed_out",
        dnp_name = %dnp_name,
        duration_ms = elapsed_ms(started, clock.now()),
        "[error] Package remained installed after cleanup polling"
    );
    CleanupResult {
        status: CleanupStatus::TimedOut,
        leftover_packages: Vec::new(),
        error: Some("target package remained installed after bounded cleanup polling".to_owned()),
    }
}

/// Restores a package that was already present when the run began.
pub async fn restore_target(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    baseline_ref: &PackageRef,
    timeout: Duration,
) -> CleanupResult {
    let started = clock.now();
    info!(
        event = "cleanup_restore_started",
        dnp_name = %dnp_name,
        baseline_ref = %baseline_ref,
        verification_timeout_ms = timeout.as_millis() as u64,
        "[cleanup] Restoring the exact baseline version"
    );
    let installed = match package_manager.list_packages().await {
        Ok(packages) => packages.iter().any(|package| &package.dnp_name == dnp_name),
        Err(error) => {
            warn!(
                event = "cleanup_restore_inventory_failed",
                dnp_name = %dnp_name,
                error = %error,
                "[error] Could not inspect the target before restoration"
            );
            return CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(&error.to_string(), 300)),
            };
        }
    };
    info!(
        event = "cleanup_restore_action_selected",
        dnp_name = %dnp_name,
        baseline_ref = %baseline_ref,
        action = if installed { "update" } else { "install" },
        "[cleanup] Baseline restoration action selected"
    );
    let restore = if installed {
        package_manager.update_package(dnp_name, baseline_ref).await
    } else {
        package_manager
            .install_package(dnp_name, Some(baseline_ref))
            .await
    };
    if let Err(error) = restore {
        warn!(
            event = "cleanup_restore_failed",
            dnp_name = %dnp_name,
            baseline_ref = %baseline_ref,
            duration_ms = elapsed_ms(started, clock.now()),
            error = %error,
            "[error] Baseline restoration mutation failed"
        );
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    let poll = Duration::from_millis(500);
    let attempts = ((timeout.as_millis() / poll.as_millis()) as usize)
        .saturating_add(1)
        .min(1_000);
    for attempt in 0..attempts {
        match package_manager.get_package_details(dnp_name).await {
            Ok(details) if details.version.as_deref() == Some(baseline_ref.as_str()) => {
                info!(
                    event = "cleanup_restore_verified",
                    dnp_name = %dnp_name,
                    baseline_ref = %baseline_ref,
                    duration_ms = elapsed_ms(started, clock.now()),
                    verification_samples = attempt + 1,
                    "[ok] Baseline restoration verified"
                );
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(details) if attempt + 1 < attempts => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    info!(
                        event = "cleanup_restore_waiting",
                        dnp_name = %dnp_name,
                        expected_ref = %baseline_ref,
                        observed_version = details.version.as_deref().unwrap_or("unknown"),
                        sample = attempt + 1,
                        max_samples = attempts,
                        elapsed_ms = elapsed_ms(started, clock.now()),
                        "[progress] Waiting for the baseline version to become visible"
                    );
                }
            }
            Err(error) if attempt + 1 < attempts => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    warn!(
                        event = "cleanup_restore_sample_failed",
                        dnp_name = %dnp_name,
                        sample = attempt + 1,
                        max_samples = attempts,
                        error = %error,
                        "[warn] Could not verify the restored baseline yet"
                    );
                }
            }
            Ok(_) => {
                warn!(
                    event = "cleanup_restore_timed_out",
                    dnp_name = %dnp_name,
                    baseline_ref = %baseline_ref,
                    duration_ms = elapsed_ms(started, clock.now()),
                    "[error] Target did not return to its baseline version"
                );
                return CleanupResult {
                    status: CleanupStatus::TimedOut,
                    leftover_packages: Vec::new(),
                    error: Some("target package did not return to its original version".to_owned()),
                };
            }
            Err(error) => {
                warn!(
                    event = "cleanup_restore_verification_failed",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    error = %error,
                    "[error] Final baseline-restoration verification failed"
                );
                return CleanupResult {
                    status: CleanupStatus::Failed,
                    leftover_packages: Vec::new(),
                    error: Some(truncate_utf8(&error.to_string(), 300)),
                };
            }
        }
        if attempt + 1 < attempts {
            clock.sleep(poll).await;
        }
    }
    unreachable!("cleanup polling always returns before exhausting attempts")
}

fn elapsed_ms(start: chrono::DateTime<chrono::Utc>, end: chrono::DateTime<chrono::Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}

pub fn leftover_packages(
    initial: &[PackageSummary],
    final_packages: &[PackageSummary],
    retained_target: Option<&DnpName>,
) -> Vec<String> {
    let initial_names: BTreeSet<&str> = initial
        .iter()
        .map(|package| package.dnp_name.as_str())
        .collect();
    final_packages
        .iter()
        .filter(|package| {
            !initial_names.contains(package.dnp_name.as_str())
                && retained_target != Some(&package.dnp_name)
        })
        .map(|package| package.dnp_name.to_string())
        .collect()
}
