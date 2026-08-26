use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use tracing::{info, warn};

use crate::{
    analysis::redaction::truncate_utf8,
    clock::Clock,
    model::{
        CleanupResult, CleanupStatus, DnpName, PackageRef, PackageSummary, TargetRecoveryPlan,
    },
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
        "Removing the test package and its volumes"
    );
    if let Err(error) = package_manager.remove_package(dnp_name, true).await
        && !matches!(error, crate::package_manager::PackageManagerError::NotFound)
    {
        warn!(
            event = "cleanup_remove_failed",
            dnp_name = %dnp_name,
            duration_ms = elapsed_ms(started, clock.now()),
            error = %error,
            "Dappmanager could not remove the test package"
        );
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    let poll = Duration::from_millis(500);
    let verification_started = Instant::now();
    let attempts = ((timeout.as_millis() / poll.as_millis()) as usize)
        .saturating_add(1)
        .min(1_000);
    for attempt in 0..attempts {
        let remaining = timeout.saturating_sub(verification_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, package_manager.list_packages()).await {
            Ok(Ok(packages)) if !packages.iter().any(|package| &package.dnp_name == dnp_name) => {
                info!(
                    event = "cleanup_remove_verified",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    verification_samples = attempt + 1,
                    "Package removal verified"
                );
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(Ok(_)) => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    info!(
                        event = "cleanup_remove_waiting",
                        dnp_name = %dnp_name,
                        sample = attempt + 1,
                        max_samples = attempts,
                        elapsed_ms = elapsed_ms(started, clock.now()),
                        "Waiting for package removal to become visible"
                    );
                }
            }
            Ok(Err(error)) if attempt + 1 == attempts => {
                warn!(
                    event = "cleanup_verification_failed",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    error = %error,
                    "Final package-removal verification failed"
                );
                return CleanupResult {
                    status: CleanupStatus::Failed,
                    leftover_packages: Vec::new(),
                    error: Some(truncate_utf8(&error.to_string(), 300)),
                };
            }
            Ok(Err(_)) => {}
            Err(_) => break,
        }
        if attempt + 1 < attempts {
            let remaining = timeout.saturating_sub(verification_started.elapsed());
            if remaining.is_zero() {
                break;
            }
            clock.sleep(poll.min(remaining)).await;
        }
    }
    warn!(
        event = "cleanup_remove_timed_out",
        dnp_name = %dnp_name,
        duration_ms = elapsed_ms(started, clock.now()),
        "Package remained installed after cleanup polling"
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
    expected_version: &str,
    timeout: Duration,
) -> CleanupResult {
    let started = clock.now();
    let restore_ref = if baseline_ref.is_ipfs() {
        baseline_ref.clone()
    } else {
        match package_manager
            .preview_install(dnp_name, Some(baseline_ref))
            .await
        {
            Ok(preview) => preview
                .resolved_ref
                .as_deref()
                .and_then(|resolved| PackageRef::parse(resolved).ok())
                .unwrap_or_else(|| baseline_ref.clone()),
            Err(error) => {
                warn!(
                    event = "cleanup_restore_resolution_failed",
                    dnp_name = %dnp_name,
                    baseline_ref = %baseline_ref,
                    expected_version,
                    error = %error,
                    "Could not resolve the baseline's immutable reference"
                );
                return CleanupResult {
                    status: CleanupStatus::Failed,
                    leftover_packages: Vec::new(),
                    error: Some(truncate_utf8(&error.to_string(), 300)),
                };
            }
        }
    };
    info!(
        event = "cleanup_restore_started",
        dnp_name = %dnp_name,
        baseline_ref = %restore_ref,
        expected_version,
        verification_timeout_ms = timeout.as_millis() as u64,
        "Restoring the exact baseline version"
    );
    let installed_version = match package_manager.list_packages().await {
        Ok(packages) => packages
            .iter()
            .find(|package| &package.dnp_name == dnp_name)
            .and_then(|package| package.version.clone()),
        Err(error) => {
            warn!(
                event = "cleanup_restore_inventory_failed",
                dnp_name = %dnp_name,
                error = %error,
                "Could not inspect the target before restoration"
            );
            return CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(&error.to_string(), 300)),
            };
        }
    };
    if installed_version.as_deref() == Some(expected_version) {
        info!(
            event = "cleanup_restore_already_complete",
            dnp_name = %dnp_name,
            baseline_ref = %restore_ref,
            expected_version,
            duration_ms = elapsed_ms(started, clock.now()),
            "Target is already at the baseline version"
        );
        return CleanupResult {
            status: CleanupStatus::Passed,
            leftover_packages: Vec::new(),
            error: None,
        };
    }
    let installed = installed_version.is_some();
    info!(
        event = "cleanup_restore_action_selected",
        dnp_name = %dnp_name,
        baseline_ref = %restore_ref,
        expected_version,
        observed_version = installed_version.as_deref().unwrap_or("not_installed"),
        action = if installed { "update" } else { "install" },
        "Baseline restoration action selected"
    );
    let restore = if installed {
        package_manager.update_package(dnp_name, &restore_ref).await
    } else {
        package_manager
            .install_package(dnp_name, Some(&restore_ref))
            .await
    };
    if let Err(error) = restore {
        warn!(
            event = "cleanup_restore_failed",
            dnp_name = %dnp_name,
            baseline_ref = %restore_ref,
            expected_version,
            duration_ms = elapsed_ms(started, clock.now()),
            error = %error,
            "Baseline restoration mutation failed"
        );
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    if installed {
        match package_manager.get_package_details(dnp_name).await {
            Ok(details) if details.version.as_deref() == Some(expected_version) => {
                info!(
                    event = "cleanup_restore_verified",
                    dnp_name = %dnp_name,
                    baseline_ref = %restore_ref,
                    expected_version,
                    duration_ms = elapsed_ms(started, clock.now()),
                    verification_samples = 1,
                    "Baseline restoration verified"
                );
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(details) => {
                warn!(
                    event = "cleanup_restore_update_noop",
                    dnp_name = %dnp_name,
                    baseline_ref = %restore_ref,
                    expected_version,
                    observed_version = details.version.as_deref().unwrap_or("unknown"),
                    "Dappmanager reported a successful update without applying the baseline; forcing a volume-preserving reinstall"
                );
                if let Err(error) = package_manager.remove_package(dnp_name, false).await {
                    return CleanupResult {
                        status: CleanupStatus::Failed,
                        leftover_packages: Vec::new(),
                        error: Some(truncate_utf8(&error.to_string(), 300)),
                    };
                }
                if let Err(error) = package_manager
                    .install_package(dnp_name, Some(&restore_ref))
                    .await
                {
                    return CleanupResult {
                        status: CleanupStatus::Failed,
                        leftover_packages: Vec::new(),
                        error: Some(truncate_utf8(&error.to_string(), 300)),
                    };
                }
            }
            Err(error) => {
                warn!(
                    event = "cleanup_restore_immediate_verification_failed",
                    dnp_name = %dnp_name,
                    error = %error,
                    "Could not immediately verify restoration; continuing bounded polling"
                );
            }
        }
    }
    let poll = Duration::from_secs(5);
    let verification_started = Instant::now();
    let attempts = ((timeout.as_millis() / poll.as_millis()) as usize)
        .saturating_add(1)
        .min(1_000);
    for attempt in 0..attempts {
        let remaining = timeout.saturating_sub(verification_started.elapsed());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, package_manager.get_package_details(dnp_name)).await {
            Ok(Ok(details)) if details.version.as_deref() == Some(expected_version) => {
                info!(
                    event = "cleanup_restore_verified",
                    dnp_name = %dnp_name,
                    baseline_ref = %restore_ref,
                    expected_version,
                    duration_ms = elapsed_ms(started, clock.now()),
                    verification_samples = attempt + 1,
                    "Baseline restoration verified"
                );
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(Ok(details)) if attempt + 1 < attempts => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    info!(
                        event = "cleanup_restore_waiting",
                        dnp_name = %dnp_name,
                        baseline_ref = %restore_ref,
                        expected_version,
                        observed_version = details.version.as_deref().unwrap_or("unknown"),
                        sample = attempt + 1,
                        max_samples = attempts,
                        elapsed_ms = elapsed_ms(started, clock.now()),
                        "Waiting for the baseline version to become visible"
                    );
                }
            }
            Ok(Err(error)) if attempt + 1 < attempts => {
                if attempt == 0 || (attempt + 1) % 10 == 0 {
                    warn!(
                        event = "cleanup_restore_sample_failed",
                        dnp_name = %dnp_name,
                        sample = attempt + 1,
                        max_samples = attempts,
                        error = %error,
                        "Could not verify the restored baseline yet"
                    );
                }
            }
            Ok(Ok(_)) => {
                warn!(
                    event = "cleanup_restore_timed_out",
                    dnp_name = %dnp_name,
                    baseline_ref = %restore_ref,
                    expected_version,
                    duration_ms = elapsed_ms(started, clock.now()),
                    "Target did not return to its baseline version"
                );
                return CleanupResult {
                    status: CleanupStatus::TimedOut,
                    leftover_packages: Vec::new(),
                    error: Some("target package did not return to its baseline version".to_owned()),
                };
            }
            Ok(Err(error)) => {
                warn!(
                    event = "cleanup_restore_verification_failed",
                    dnp_name = %dnp_name,
                    duration_ms = elapsed_ms(started, clock.now()),
                    error = %error,
                    "Final baseline-restoration verification failed"
                );
                return CleanupResult {
                    status: CleanupStatus::Failed,
                    leftover_packages: Vec::new(),
                    error: Some(truncate_utf8(&error.to_string(), 300)),
                };
            }
            Err(_) => break,
        }
        if attempt + 1 < attempts {
            let remaining = timeout.saturating_sub(verification_started.elapsed());
            if remaining.is_zero() {
                break;
            }
            clock.sleep(poll.min(remaining)).await;
        }
    }
    warn!(
        event = "cleanup_restore_timed_out",
        dnp_name = %dnp_name,
        baseline_ref = %restore_ref,
        expected_version,
        duration_ms = elapsed_ms(started, clock.now()),
        "Target did not return to its baseline version"
    );
    CleanupResult {
        status: CleanupStatus::TimedOut,
        leftover_packages: Vec::new(),
        error: Some("target package did not return to its baseline version".to_owned()),
    }
}

/// Reinstalls the latest published release while preserving package volumes.
pub async fn restore_latest_target(
    package_manager: &dyn PackageManager,
    dnp_name: &DnpName,
) -> CleanupResult {
    info!(
        event = "cleanup_restore_latest_started",
        dnp_name = %dnp_name,
        delete_volumes = false,
        baseline_ref = "*",
        "Reinstalling the latest published release while preserving volumes"
    );
    if let Err(error) = package_manager.remove_package(dnp_name, false).await
        && !matches!(error, crate::package_manager::PackageManagerError::NotFound)
    {
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    if let Err(error) = package_manager.install_package(dnp_name, None).await {
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    match package_manager.list_packages().await {
        Ok(packages) if packages.iter().any(|package| package.dnp_name == *dnp_name) => {
            info!(
                event = "cleanup_restore_latest_verified",
                dnp_name = %dnp_name,
                baseline_ref = "*",
                "Latest published release reinstall verified"
            );
            CleanupResult {
                status: CleanupStatus::Passed,
                leftover_packages: Vec::new(),
                error: None,
            }
        }
        Ok(_) => CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some("latest published release was not present after reinstall".to_owned()),
        },
        Err(error) => CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        },
    }
}

/// Applies a persisted target recovery plan and verifies the complete package inventory.
pub async fn reconcile_target(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    plan: &TargetRecoveryPlan,
    initial_packages: &[PackageSummary],
    timeout: Duration,
) -> (CleanupResult, Vec<PackageSummary>) {
    let mut cleanup = match plan {
        TargetRecoveryPlan::RestoreLatest => restore_latest_target(package_manager, dnp_name).await,
        TargetRecoveryPlan::Restore {
            baseline_ref,
            expected_version,
            ..
        } => match PackageRef::parse(baseline_ref) {
            Ok(baseline_ref) => {
                let expected_version = expected_version.as_deref().unwrap_or(baseline_ref.as_str());
                restore_target(
                    package_manager,
                    Arc::clone(&clock),
                    dnp_name,
                    &baseline_ref,
                    expected_version,
                    timeout,
                )
                .await
            }
            Err(error) => CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(
                    &format!("saved baseline reference is invalid: {error}"),
                    300,
                )),
            },
        },
        TargetRecoveryPlan::Remove => {
            cleanup_target(package_manager, Arc::clone(&clock), dnp_name, timeout).await
        }
    };

    let final_packages = match package_manager.list_packages().await {
        Ok(packages) => packages,
        Err(error) => {
            if cleanup.status == CleanupStatus::Passed {
                cleanup.status = CleanupStatus::Failed;
            }
            if cleanup.error.is_none() {
                cleanup.error = Some(truncate_utf8(&error.to_string(), 300));
            }
            return (cleanup, Vec::new());
        }
    };
    let retained_target =
        matches!(plan, TargetRecoveryPlan::Restore { retained: true, .. }).then_some(dnp_name);
    cleanup.leftover_packages =
        leftover_packages(initial_packages, &final_packages, retained_target);
    if cleanup.status == CleanupStatus::Passed && !cleanup.leftover_packages.is_empty() {
        cleanup.status = CleanupStatus::Failed;
        cleanup.error = Some(truncate_utf8(
            &format!(
                "cleanup left packages that were not present before the run: {}",
                cleanup.leftover_packages.join(", ")
            ),
            300,
        ));
    }
    (cleanup, final_packages)
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
