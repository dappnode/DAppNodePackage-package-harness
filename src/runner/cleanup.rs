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
    runner::{
        NoopRunProgress,
        readiness::PackageReadiness,
        stabilization::{StabilizationConfig, stabilize},
    },
};

pub struct RecoverySpec<'a> {
    pub plan: TargetRecoveryPlan,
    pub baseline_ref: Option<&'a PackageRef>,
    pub initial_packages: &'a [PackageSummary],
    pub readiness: &'a PackageReadiness,
    pub stabilization: StabilizationConfig,
}

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
    let mut expected = None;
    restore_target(
        package_manager,
        dnp_name,
        None,
        Duration::from_secs(60),
        &mut expected,
    )
    .await
}

struct RestorationExpectation {
    version: Option<String>,
    origin: Option<String>,
    deadline: tokio::time::Instant,
}

impl RestorationExpectation {
    fn matches(&self, details: &crate::model::PackageDetails, name: &DnpName) -> bool {
        details.dnp_name == *name
            && self
                .version
                .as_ref()
                .is_none_or(|version| details.version.as_ref() == Some(version))
            && match &self.origin {
                Some(origin) => same_install_origin(Some(origin), details.origin.as_deref()),
                None => details.origin.is_none(),
            }
    }
}

async fn restore_target(
    package_manager: &dyn PackageManager,
    dnp_name: &DnpName,
    reference: Option<&PackageRef>,
    timeout: Duration,
    expected: &mut Option<RestorationExpectation>,
) -> CleanupResult {
    let failed = |message: String| CleanupResult {
        status: CleanupStatus::Failed,
        leftover_packages: Vec::new(),
        error: Some(truncate_utf8(&message, 300)),
    };
    // Resolve the expected registry release before removal, so an unavailable
    // registry or ambiguous restore target cannot destroy an installed package.
    let (expected_version, expected_origin) = if let Some(reference) = reference {
        (None, Some(reference.to_string()))
    } else {
        let preview = match package_manager.preview_install(dnp_name, None).await {
            Ok(preview) => preview,
            Err(error) => {
                return failed(format!(
                    "cannot resolve latest recovery release before removal: {error}"
                ));
            }
        };
        if preview
            .package_name
            .as_deref()
            .is_some_and(|name| name != dnp_name.as_str())
            || preview
                .version
                .as_ref()
                .is_none_or(|version| version.trim().is_empty())
        {
            return failed("latest recovery preview did not identify the expected package and resolved version; package was not changed".to_owned());
        }
        (preview.version, preview.resolved_ref)
    };
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
    let deadline = tokio::time::Instant::now() + timeout;
    *expected = Some(RestorationExpectation {
        version: expected_version,
        origin: expected_origin,
        deadline,
    });
    {
        let error = match tokio::time::timeout_at(
            deadline,
            package_manager.get_package_details(dnp_name),
        )
        .await
        {
            Ok(Ok(details))
                if expected
                    .as_ref()
                    .is_some_and(|expected| expected.matches(&details, dnp_name)) =>
            {
                None
            }
            Ok(Ok(_)) => Some(
                if reference.is_some() {
                    "restored package does not match the pinned IPFS baseline"
                } else {
                    "restored package does not match the resolved latest release version and origin"
                }
                .to_owned(),
            ),
            Ok(Err(error)) => Some(error.to_string()),
            Err(_) => Some(
                "restored package details exceeded the cleanup verification deadline".to_owned(),
            ),
        };
        if let Some(error) = error {
            return CleanupResult {
                status: CleanupStatus::Failed,
                leftover_packages: Vec::new(),
                error: Some(truncate_utf8(&error, 300)),
            };
        }
    }
    match tokio::time::timeout_at(deadline, package_manager.list_packages()).await {
        Ok(Ok(packages)) if packages.iter().any(|package| package.dnp_name == *dnp_name) => {
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
        Ok(Ok(_)) => CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some("recovery baseline was not present after reinstall".to_owned()),
        },
        Ok(Err(error)) => CleanupResult {
            status: CleanupStatus::Failed,
            leftover_packages: Vec::new(),
            error: Some(truncate_utf8(&error.to_string(), 300)),
        },
        Err(_) => {
            failed("restored inventory exceeded the cleanup verification deadline".to_owned())
        }
    }
}

/// Applies a persisted target recovery plan and verifies the complete package inventory.
pub async fn reconcile_target(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    spec: RecoverySpec<'_>,
    timeout: Duration,
) -> (CleanupResult, Vec<PackageSummary>) {
    let mut expected = None;
    let mut cleanup = match spec.plan {
        TargetRecoveryPlan::RestoreLatest => restore_target(package_manager, dnp_name, None, timeout, &mut expected).await,
        TargetRecoveryPlan::RestoreBaseline => match spec.baseline_ref.filter(|reference| reference.is_ipfs()) {
            Some(reference) => restore_target(package_manager, dnp_name, Some(reference), timeout, &mut expected).await,
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

    let deadline = expected.as_ref().map_or_else(
        || tokio::time::Instant::now() + timeout,
        |expected| expected.deadline,
    );
    if cleanup.status == CleanupStatus::Passed && spec.plan != TargetRecoveryPlan::Remove {
        let config = StabilizationConfig {
            timeout: deadline.saturating_duration_since(tokio::time::Instant::now()),
            ..spec.stabilization
        };
        let readiness = stabilize(
            package_manager,
            Arc::clone(&clock),
            dnp_name,
            config,
            &NoopRunProgress,
            spec.readiness,
        )
        .await;
        if !readiness.passed {
            cleanup.status = CleanupStatus::TimedOut;
            let detail = readiness
                .samples
                .last()
                .and_then(|sample| sample.error.clone())
                .or_else(|| readiness.last_non_running_states.last().cloned())
                .unwrap_or_else(|| {
                    "no stable healthy container/application observations".to_owned()
                });
            cleanup.error = Some(truncate_utf8(
                &format!("restored package did not pass readiness verification: {detail}"),
                300,
            ));
        }
        if cleanup.status == CleanupStatus::Passed
            && let Some(expected) = &expected
        {
            let verified =
                tokio::time::timeout_at(deadline, package_manager.get_package_details(dnp_name))
                    .await;
            if !matches!(verified, Ok(Ok(ref details)) if expected.matches(details, dnp_name)) {
                cleanup.status = CleanupStatus::Failed;
                cleanup.error = Some(
                    "restored version/origin could not be confirmed after readiness verification"
                        .to_owned(),
                );
            }
        }
    }

    let final_packages =
        match tokio::time::timeout_at(deadline, package_manager.list_packages()).await {
            Ok(Ok(packages)) => packages,
            result => {
                if cleanup.status == CleanupStatus::Passed {
                    cleanup.status = CleanupStatus::Failed;
                }
                if cleanup.error.is_none() {
                    cleanup.error = Some(match result {
                    Ok(Err(error)) => truncate_utf8(&error.to_string(), 300),
                    _ => "final inventory verification exceeded the cleanup verification deadline"
                        .to_owned(),
                });
                }
                return (cleanup, Vec::new());
            }
        };
    cleanup.leftover_packages = leftover_packages(spec.initial_packages, &final_packages);
    let target_present = final_packages
        .iter()
        .any(|package| package.dnp_name == *dnp_name);
    if cleanup.status == CleanupStatus::Passed
        && target_present != (spec.plan != TargetRecoveryPlan::Remove)
    {
        cleanup.status = CleanupStatus::Failed;
        cleanup.error = Some("final inventory does not match the target recovery plan".to_owned());
    }
    let changed = spec
        .initial_packages
        .iter()
        .filter(|package| package.dnp_name != *dnp_name)
        .filter(|package| {
            final_packages
                .iter()
                .find(|current| current.dnp_name == package.dnp_name)
                .is_none_or(|current| {
                    package.version.is_some() && current.version != package.version
                })
        })
        .map(|package| package.dnp_name.to_string())
        .collect::<Vec<_>>();
    if cleanup.status == CleanupStatus::Passed && !changed.is_empty() {
        cleanup.status = CleanupStatus::Failed;
        cleanup.error = Some(truncate_utf8(
            &format!(
                "cleanup changed or removed pre-existing packages: {}",
                changed.join(", ")
            ),
            300,
        ));
    }
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
