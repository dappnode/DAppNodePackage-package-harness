use std::collections::BTreeSet;

use crate::model::{
    AnalyzerStatus, CaptureEvidence, ComparisonEvidence, LogAnalysisResult, ReasonCode, Verdict,
};

pub fn compare(baseline: &CaptureEvidence, candidate: &CaptureEvidence) -> ComparisonEvidence {
    let baseline_containers = container_names(baseline);
    let candidate_containers = container_names(candidate);
    let baseline_set: BTreeSet<&str> = baseline_containers.iter().map(String::as_str).collect();
    let candidate_set: BTreeSet<&str> = candidate_containers.iter().map(String::as_str).collect();
    let containers_added = candidate_set
        .difference(&baseline_set)
        .map(ToString::to_string)
        .collect();
    let containers_removed = baseline_set
        .difference(&candidate_set)
        .map(ToString::to_string)
        .collect();
    let mut deterministic_regressions = Vec::new();
    if baseline.stabilization.passed && !candidate.stabilization.passed {
        deterministic_regressions
            .push("candidate containers did not become stably running".to_owned());
    }
    ComparisonEvidence {
        baseline_hard_check: baseline.stabilization.passed,
        candidate_hard_check: candidate.stabilization.passed,
        baseline_containers,
        candidate_containers,
        containers_added,
        containers_removed,
        baseline_version: baseline
            .details
            .as_ref()
            .and_then(|details| details.version.clone()),
        candidate_version: candidate
            .details
            .as_ref()
            .and_then(|details| details.version.clone()),
        baseline_stabilization_ms: baseline.stabilization.duration_ms,
        candidate_stabilization_ms: candidate.stabilization.duration_ms,
        baseline_last_non_running_states: baseline.stabilization.last_non_running_states.clone(),
        candidate_last_non_running_states: candidate.stabilization.last_non_running_states.clone(),
        baseline_logs_collected: baseline.logs.is_some(),
        candidate_logs_collected: candidate.logs.is_some(),
        deterministic_regressions,
    }
}

pub fn deterministic_verdict(
    comparison: &ComparisonEvidence,
    analysis: &LogAnalysisResult,
) -> (Verdict, ReasonCode, String) {
    match (
        comparison.baseline_hard_check,
        comparison.candidate_hard_check,
    ) {
        (true, false) => (
            Verdict::Failed,
            ReasonCode::CandidateContainersUnstable,
            "The canonical baseline stabilized, but the candidate did not".to_owned(),
        ),
        (true, true) if analysis.status == AnalyzerStatus::Critical => (
            Verdict::Warning,
            ReasonCode::CandidateContainersStable,
            "Both versions stabilized; advisory log analysis found a critical candidate-only signature"
                .to_owned(),
        ),
        (true, true) => (
            Verdict::Passed,
            ReasonCode::CandidateContainersStable,
            "Baseline and candidate containers became stably running".to_owned(),
        ),
        (false, true) => (
            Verdict::Warning,
            ReasonCode::BaselineContainersUnstable,
            "The candidate stabilized, but the canonical control was unhealthy, so this is not a clean pass"
                .to_owned(),
        ),
        (false, false) => (
            Verdict::Inconclusive,
            ReasonCode::BaselineContainersUnstable,
            "Neither baseline nor candidate became stably running".to_owned(),
        ),
    }
}

fn container_names(capture: &CaptureEvidence) -> Vec<String> {
    let mut names = capture
        .details
        .as_ref()
        .map(|details| {
            details
                .containers
                .iter()
                .map(|container| container.name.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    names.sort();
    names
}
