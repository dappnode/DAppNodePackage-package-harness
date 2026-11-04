use serde::{Deserialize, Serialize};

use super::DnpName;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageSummary {
    pub dnp_name: DnpName,
    pub version: Option<String>,
    pub is_core: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerSnapshot {
    pub name: String,
    pub service_name: Option<String>,
    pub state: Option<String>,
    pub running: bool,
    pub image: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageDetails {
    pub dnp_name: DnpName,
    pub version: Option<String>,
    /// Exact reference the package was installed from. Dappmanager reports it
    /// only for IPFS installs, so it tells apart two builds with one version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    pub containers: Vec<ContainerSnapshot>,
}

/// Content identifier of an IPFS package reference or install origin.
///
/// Accepts the forms Dappmanager uses (`/ipfs/<cid>`, `ipfs://<cid>`, or a
/// bare CID). Registry references such as `1.2.3` or `*` have none.
pub fn ipfs_cid(reference: &str) -> Option<&str> {
    let reference = reference.trim();
    let (cid, prefixed) = match reference
        .strip_prefix("/ipfs/")
        .or_else(|| reference.strip_prefix("ipfs://"))
    {
        Some(cid) => (cid, true),
        None => (reference, false),
    };
    let cid = cid.trim_end_matches('/');
    let bare_cid =
        (cid.len() == 46 && cid.starts_with("Qm")) || (cid.len() > 50 && cid.starts_with("baf"));
    let well_formed = !cid.is_empty() && cid.chars().all(|c| c.is_ascii_alphanumeric());
    (well_formed && (prefixed || bare_cid)).then_some(cid)
}

/// Whether an installed package's origin is the one a request resolved to.
///
/// Registry installs have no origin, so two registry references are equal
/// here; the caller compares versions for those.
pub fn same_install_origin(expected: Option<&str>, installed: Option<&str>) -> bool {
    expected.and_then(ipfs_cid) == installed.and_then(ipfs_cid)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerLog {
    pub container: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageLogs {
    pub entries: Vec<ContainerLog>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewSummary {
    pub package_name: Option<String>,
    pub version: Option<String>,
    /// Exact immutable reference resolved by DAppManager. Used only while
    /// building the local rollback plan, not as persisted test evidence.
    #[serde(skip)]
    pub resolved_ref: Option<String>,
    pub image_count: Option<usize>,
    pub requires_user_input: bool,
    pub summary: String,
}

impl PreviewSummary {
    /// The semantic version the preview resolves to. `version` falls back to
    /// the requested reference, which is not a version for IPFS or `*` refs.
    pub fn semantic_version(&self) -> Option<&str> {
        self.version
            .as_deref()
            .filter(|version| version.starts_with(|c: char| c.is_ascii_digit()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StabilizationSample {
    pub observed_at: String,
    pub container_names: Vec<String>,
    pub all_running: bool,
    pub non_running_states: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StabilizationResult {
    pub passed: bool,
    pub stable_samples: usize,
    pub duration_ms: u64,
    pub samples: Vec<StabilizationSample>,
    pub last_non_running_states: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureEvidence {
    pub install_status: StepStatus,
    pub install_duration_ms: u64,
    pub preview: Option<PreviewSummary>,
    pub details: Option<PackageDetails>,
    pub stabilization: StabilizationResult,
    pub logs: Option<PackageLogs>,
    pub log_error: Option<String>,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComparisonEvidence {
    pub baseline_hard_check: bool,
    pub candidate_hard_check: bool,
    pub baseline_containers: Vec<String>,
    pub candidate_containers: Vec<String>,
    pub containers_added: Vec<String>,
    pub containers_removed: Vec<String>,
    pub baseline_version: Option<String>,
    pub candidate_version: Option<String>,
    pub baseline_stabilization_ms: u64,
    pub candidate_stabilization_ms: u64,
    pub baseline_last_non_running_states: Vec<String>,
    pub candidate_last_non_running_states: Vec<String>,
    pub baseline_logs_collected: bool,
    pub candidate_logs_collected: bool,
    pub deterministic_regressions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{ipfs_cid, same_install_origin};

    const CID: &str = "QmVQ2ei1wmizEAQvoZj1gaNDhh2rrm9mWdjxuEYFhZFiNS";

    #[test]
    fn extracts_cid_from_every_ipfs_reference_form() {
        assert_eq!(ipfs_cid(&format!("/ipfs/{CID}")), Some(CID));
        assert_eq!(ipfs_cid(&format!("ipfs://{CID}")), Some(CID));
        assert_eq!(ipfs_cid(&format!(" /ipfs/{CID}/ ")), Some(CID));
        assert_eq!(ipfs_cid(CID), Some(CID));
        assert_eq!(ipfs_cid("/ipfs/QmCandidate"), Some("QmCandidate"));
    }

    #[test]
    fn registry_references_have_no_cid() {
        assert_eq!(ipfs_cid("0.1.10"), None);
        assert_eq!(ipfs_cid("*"), None);
        assert_eq!(ipfs_cid("QmShort"), None);
        assert_eq!(ipfs_cid("/ipfs/"), None);
        assert_eq!(ipfs_cid("/ipfs/Qm bad"), None);
    }

    #[test]
    fn compares_install_origins_by_cid() {
        let path = format!("/ipfs/{CID}");
        let uri = format!("ipfs://{CID}");
        assert!(same_install_origin(Some(&path), Some(&uri)));
        assert!(same_install_origin(None, None));
        // A registry release and an IPFS build of the same version differ.
        assert!(!same_install_origin(None, Some(&path)));
        assert!(!same_install_origin(Some(&path), None));
        assert!(!same_install_origin(
            Some(&path),
            Some("/ipfs/QmSBi96gxQ8UDvT96xSVfbBoEpVWDm4MPkNxNzHJ8sRWPJ")
        ));
    }
}
