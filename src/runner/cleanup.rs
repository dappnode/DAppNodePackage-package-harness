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
        same_install_origin,
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

/// Reinstalls the latest published release while preserving package volumes.
pub async fn restore_latest_target(
    package_manager: &dyn PackageManager,
    dnp_name: &DnpName,
) -> CleanupResult {
    restore_target(package_manager, dnp_name, None).await
}

async fn restore_target(
    package_manager: &dyn PackageManager,
    dnp_name: &DnpName,
    reference: Option<&PackageRef>,
) -> CleanupResult {
    info!(
        event = "cleanup_restore_target_started",
        dnp_name = %dnp_name,
        delete_volumes = false,
        baseline_ref = reference.map_or("*", PackageRef::as_str),
        "Reinstalling the recovery baseline while preserving volumes"
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
    if let Err(error) = package_manager.install_package(dnp_name, reference).await {
        return CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        };
    }
    if let Some(reference) = reference {
        // A success response alone is insufficient: check the immutable origin
        // before declaring a pinned recovery complete.
        let error = match package_manager.get_package_details(dnp_name).await {
            Ok(details)
                if details.dnp_name == *dnp_name
                    && same_install_origin(Some(reference.as_str()), details.origin.as_deref()) =>
            {
                None
            }
            Ok(_) => Some("restored package does not match the pinned IPFS baseline".to_owned()),
            Err(error) => Some(error.to_string()),
        };
        if let Some(error) = error {
            return CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(&error, 300)),
            };
        }
    }
    match package_manager.list_packages().await {
        Ok(packages) if packages.iter().any(|package| package.dnp_name == *dnp_name) => {
            info!(
                event = "cleanup_restore_target_verified",
                dnp_name = %dnp_name,
                baseline_ref = reference.map_or("*", PackageRef::as_str),
                "Recovery baseline reinstall verified"
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
            error: Some("recovery baseline was not present after reinstall".to_owned()),
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
    plan: TargetRecoveryPlan,
    baseline_ref: Option<&PackageRef>,
    initial_packages: &[PackageSummary],
    timeout: Duration,
) -> (CleanupResult, Vec<PackageSummary>) {
    let mut cleanup = match plan {
        TargetRecoveryPlan::RestoreLatest => restore_latest_target(package_manager, dnp_name).await,
        TargetRecoveryPlan::RestoreBaseline => match baseline_ref.filter(|reference| reference.is_ipfs()) {
            Some(reference) => restore_target(package_manager, dnp_name, Some(reference)).await,
            None => CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some("pinned recovery requires an explicit IPFS baselineRef; package was not changed".to_owned()),
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
    cleanup.leftover_packages = leftover_packages(initial_packages, &final_packages);
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
) -> Vec<String> {
    let initial_names: BTreeSet<&str> = initial
        .iter()
        .map(|package| package.dnp_name.as_str())
        .collect();
    final_packages
        .iter()
        .filter(|package| !initial_names.contains(package.dnp_name.as_str()))
        .map(|package| package.dnp_name.to_string())
        .collect()
}
