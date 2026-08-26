use chrono::Utc;

use crate::{
    analysis::redaction::truncate_utf8,
    model::{
        AnalysisSide, AnalyzerKind, AnalyzerStatus, CaptureEvidence, ComparisonEvidence,
        ExecutionStatus, HardCheckResult, HarnessResult, InstallResult, LogAnalysisResult,
        LogCollectionResult, ReasonCode, ResultExecution, ResultPackage, ResultSide, ResultSource,
        RunRecord, StepStatus, Verdict,
    },
};

use super::comparison::compare;

pub(super) fn analysis_failure(message: &str) -> LogAnalysisResult {
    LogAnalysisResult {
        analyzer: AnalyzerKind::Heuristic,
        status: AnalyzerStatus::Inconclusive,
        summary: "Log analysis was unavailable".to_owned(),
        baseline: AnalysisSide {
            status: AnalyzerStatus::Inconclusive,
            summary: "Analysis unavailable".to_owned(),
        },
        candidate: AnalysisSide {
            status: AnalyzerStatus::Inconclusive,
            summary: "Analysis unavailable".to_owned(),
        },
        new_findings: Vec::new(),
        analyzer_errors: vec![truncate_utf8(message, 300)],
        components: Vec::new(),
    }
}

pub(super) fn inconclusive_analysis() -> LogAnalysisResult {
    analysis_failure("run ended before comparative log analysis")
}

pub(super) fn comparison_from_partial(record: &RunRecord) -> ComparisonEvidence {
    match (&record.evidence.baseline, &record.evidence.candidate) {
        (Some(baseline), Some(candidate)) => compare(baseline, candidate),
        _ => ComparisonEvidence {
            baseline_hard_check: record
                .evidence
                .baseline
                .as_ref()
                .is_some_and(|capture| capture.stabilization.passed),
            candidate_hard_check: false,
            baseline_containers: Vec::new(),
            candidate_containers: Vec::new(),
            containers_added: Vec::new(),
            containers_removed: Vec::new(),
            baseline_version: record
                .evidence
                .baseline
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
            candidate_version: None,
            baseline_stabilization_ms: record
                .evidence
                .baseline
                .as_ref()
                .map_or(0, |capture| capture.stabilization.duration_ms),
            candidate_stabilization_ms: 0,
            baseline_last_non_running_states: Vec::new(),
            candidate_last_non_running_states: Vec::new(),
            baseline_logs_collected: record
                .evidence
                .baseline
                .as_ref()
                .is_some_and(|capture| capture.logs.is_some()),
            candidate_logs_collected: false,
            deterministic_regressions: Vec::new(),
        },
    }
}

pub(super) fn build_result(
    record: &RunRecord,
    comparison: ComparisonEvidence,
    analysis: LogAnalysisResult,
    verdict: Verdict,
    reason_code: ReasonCode,
    summary: String,
) -> HarnessResult {
    let baseline = result_side(
        record.evidence.baseline.as_ref(),
        ReasonCode::BaselineContainersUnstable,
    );
    let candidate = result_side(
        record.evidence.candidate.as_ref(),
        ReasonCode::CandidateContainersUnstable,
    );
    let started = record.started_at.unwrap_or(record.created_at);
    let finished = record.finished_at.unwrap_or_else(Utc::now);
    HarnessResult {
        schema_version: 1,
        run_id: record.request.run_id.to_string(),
        source: ResultSource::from_request(&record.request),
        package: ResultPackage {
            dnp_name: record.request.package.dnp_name.to_string(),
            baseline_requested_ref: record
                .request
                .package
                .baseline_ref
                .as_ref()
                .map(ToString::to_string),
            baseline_resolved_version: record
                .evidence
                .baseline
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
            candidate_ref: record.request.package.candidate_ref.to_string(),
            candidate_reported_version: record
                .evidence
                .candidate
                .as_ref()
                .and_then(|capture| capture.details.as_ref())
                .and_then(|details| details.version.clone()),
        },
        execution: ResultExecution {
            status: ExecutionStatus::Completed,
            started_at: started.to_rfc3339(),
            finished_at: finished.to_rfc3339(),
            duration_ms: elapsed_ms(started, finished),
        },
        verdict,
        reason_code,
        summary,
        baseline,
        candidate,
        comparison,
        log_analysis: analysis,
        cleanup: record.cleanup.clone(),
        errors: record.errors.clone(),
    }
}

fn result_side(capture: Option<&CaptureEvidence>, unstable_reason: ReasonCode) -> ResultSide {
    let containers = capture
        .and_then(|capture| capture.details.as_ref())
        .map(|details| details.containers.clone())
        .unwrap_or_default();
    ResultSide {
        install: InstallResult {
            status: capture.map_or(StepStatus::Failed, |capture| capture.install_status),
            duration_ms: capture.map_or(0, |capture| capture.install_duration_ms),
        },
        hard_check: HardCheckResult {
            passed: capture.is_some_and(|capture| capture.stabilization.passed),
            reason_codes: if capture.is_some_and(|capture| capture.stabilization.passed) {
                Vec::new()
            } else {
                vec![unstable_reason]
            },
            container_count: containers.len(),
            stable_samples: capture.map_or(0, |capture| capture.stabilization.stable_samples),
        },
        containers,
        log_collection: LogCollectionResult {
            status: if capture.is_some_and(|capture| capture.logs.is_some()) {
                StepStatus::Passed
            } else {
                StepStatus::Failed
            },
            container_count: capture
                .and_then(|capture| capture.logs.as_ref())
                .map_or(0, |logs| logs.entries.len()),
        },
    }
}

fn elapsed_ms(start: chrono::DateTime<Utc>, end: chrono::DateTime<Utc>) -> u64 {
    end.signed_duration_since(start).num_milliseconds().max(0) as u64
}
