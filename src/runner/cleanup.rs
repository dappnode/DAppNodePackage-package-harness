use std::{collections::BTreeSet, sync::Arc, time::Duration};

use crate::{
    analysis::redaction::truncate_utf8,
    clock::Clock,
    model::{CleanupResult, CleanupStatus, DnpName, PackageSummary},
    package_manager::PackageManager,
};

pub async fn cleanup_target(
    package_manager: &dyn PackageManager,
    clock: Arc<dyn Clock>,
    dnp_name: &DnpName,
    timeout: Duration,
) -> CleanupResult {
    if let Err(error) = package_manager.remove_package(dnp_name, true).await
        && !matches!(error, crate::package_manager::PackageManagerError::NotFound)
    {
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
                return CleanupResult {
                    status: CleanupStatus::Passed,
                    leftover_packages: Vec::new(),
                    error: None,
                };
            }
            Ok(_) => {}
            Err(error) if attempt + 1 == attempts => {
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
    CleanupResult {
        status: CleanupStatus::TimedOut,
        leftover_packages: Vec::new(),
        error: Some("target package remained installed after bounded cleanup polling".to_owned()),
    }
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
