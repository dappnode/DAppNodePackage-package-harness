use std::collections::BTreeSet;

use async_trait::async_trait;

use crate::{
    analysis::redaction::{redact_and_bound, truncate_utf8},
    model::{
        AnalysisSide, AnalyzerKind, AnalyzerStatus, FindingSeverity, LogAnalysisInput,
        LogAnalysisResult, LogFinding,
    },
};

use super::{AnalyzerError, LogAnalyzer};

/// Case-insensitive log fragments treated as suspicious by the deterministic analyzer.
const SIGNATURES: [(&str, FindingSeverity); 8] = [
    ("panic", FindingSeverity::Critical),
    ("fatal", FindingSeverity::Critical),
    ("segmentation fault", FindingSeverity::Critical),
    ("uncaught exception", FindingSeverity::Critical),
    ("unhandled rejection", FindingSeverity::Critical),
    ("out of memory", FindingSeverity::Critical),
    ("permission denied", FindingSeverity::Warning),
    ("restart loop", FindingSeverity::Warning),
];

/// Deterministic analyzer that flags candidate-only suspicious log signatures.
#[derive(Debug, Default)]
pub struct HeuristicLogAnalyzer;

#[async_trait]
impl LogAnalyzer for HeuristicLogAnalyzer {
    async fn analyze(&self, input: &LogAnalysisInput) -> Result<LogAnalysisResult, AnalyzerError> {
        Ok(analyze_heuristically(input))
    }
}

/// Performs signature analysis without any network dependency.
///
/// Findings are reported only when the candidate contains a configured
/// signature that did not appear in that container's baseline logs.
pub fn analyze_heuristically(input: &LogAnalysisInput) -> LogAnalysisResult {
    let baseline_signatures = signatures(input.baseline.iter());
    let candidate_signatures = signatures(input.candidate.iter());
    let baseline = side(&baseline_signatures);
    let candidate = side(&candidate_signatures);
    let mut new_findings = Vec::new();
    let mut deduplicated = BTreeSet::new();

    for (container, log) in &input.candidate {
        let lower = log.to_ascii_lowercase();
        let baseline_for_container =
            signatures(input.baseline.iter().filter(|(name, _)| name == container));
        for (pattern, severity) in SIGNATURES {
            if signature_index(&lower, pattern).is_none()
                || baseline_for_container.contains(pattern)
                || !deduplicated.insert((container.clone(), pattern))
            {
                continue;
            }
            let excerpt = excerpt(log, pattern);
            new_findings.push(LogFinding {
                severity,
                container: container.clone(),
                evidence: redact_and_bound(&excerpt, 240),
                reason: format!("candidate-only log signature: {pattern}"),
            });
            if new_findings.len() == 20 {
                break;
            }
        }
        if new_findings.len() == 20 {
            break;
        }
    }
    let status = if new_findings
        .iter()
        .any(|finding| finding.severity == FindingSeverity::Critical)
    {
        AnalyzerStatus::Critical
    } else if new_findings.is_empty() {
        AnalyzerStatus::Clean
    } else {
        AnalyzerStatus::Suspicious
    };
    let summary = match status {
        AnalyzerStatus::Clean => "No configured candidate-only suspicious signature was found",
        AnalyzerStatus::Suspicious => "Candidate logs contain new advisory warning signatures",
        AnalyzerStatus::Critical => "Candidate logs contain new advisory critical signatures",
        AnalyzerStatus::Inconclusive => "Heuristic analysis was inconclusive",
    };

    LogAnalysisResult {
        analyzer: AnalyzerKind::Heuristic,
        status,
        summary: summary.to_owned(),
        baseline,
        candidate,
        new_findings,
        analyzer_errors: Vec::new(),
        components: Vec::new(),
    }
}

fn signatures<'a>(
    logs: impl Iterator<Item = &'a (Option<String>, String)>,
) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for (_, log) in logs {
        let lower = log.to_ascii_lowercase();
        for (pattern, _) in SIGNATURES {
            if signature_index(&lower, pattern).is_some() {
                found.insert(pattern);
            }
        }
    }
    found
}

fn signature_index(lower: &str, pattern: &str) -> Option<usize> {
    lower.match_indices(pattern).find_map(|(index, _)| {
        if pattern == "fatal" {
            let prefix = &lower[..index];
            if prefix.ends_with("non-")
                || prefix.ends_with("non ")
                || prefix.ends_with("non_")
                || prefix
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || lower
                    .as_bytes()
                    .get(index + pattern.len())
                    .is_some_and(u8::is_ascii_alphanumeric)
            {
                return None;
            }
        }
        Some(index)
    })
}

fn side(signatures: &BTreeSet<&str>) -> AnalysisSide {
    if signatures.is_empty() {
        AnalysisSide {
            status: AnalyzerStatus::Clean,
            summary: "No configured suspicious signature was found".to_owned(),
        }
    } else {
        AnalysisSide {
            status: AnalyzerStatus::Suspicious,
            summary: truncate_utf8(
                &format!(
                    "Configured signatures found: {}",
                    signatures.iter().copied().collect::<Vec<_>>().join(", ")
                ),
                300,
            ),
        }
    }
}

fn excerpt(log: &str, pattern: &str) -> String {
    let lower = log.to_ascii_lowercase();
    let Some(index) = signature_index(&lower, pattern) else {
        return String::new();
    };
    let start = index.saturating_sub(80);
    let end = (index + pattern.len() + 120).min(log.len());
    let mut safe_start = start;
    let mut safe_end = end;
    while safe_start < index && !log.is_char_boundary(safe_start) {
        safe_start += 1;
    }
    while safe_end > index && !log.is_char_boundary(safe_end) {
        safe_end -= 1;
    }
    log.get(safe_start..safe_end).unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::analyze_heuristically;
    use crate::model::{AnalyzerStatus, LogAnalysisInput};

    #[test]
    fn nonfatal_messages_are_not_critical_but_a_later_actual_fatal_is_detected() {
        let mut input = LogAnalysisInput {
            candidate: vec![(
                Some("bitcoin".into()),
                "fee estimator: non-fatal warning; nonfatal condition; non_fatal fallback".into(),
            )],
            ..Default::default()
        };
        assert_eq!(analyze_heuristically(&input).status, AnalyzerStatus::Clean);
        input.candidate[0].1.push_str("\nFATAL: engine crashed");
        let result = analyze_heuristically(&input);
        assert_eq!(result.status, AnalyzerStatus::Critical);
        assert!(result.new_findings[0].evidence.contains("engine crashed"));
    }

    #[test]
    fn a_baseline_error_in_one_service_does_not_hide_a_new_error_in_another() {
        let input = LogAnalysisInput {
            baseline: vec![(Some("cache".into()), "fatal: cache error".into())],
            candidate: vec![
                (Some("cache".into()), "fatal: cache error".into()),
                (Some("api".into()), "fatal: database failed".into()),
            ],
            ..Default::default()
        };
        let result = analyze_heuristically(&input);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].container.as_deref(), Some("api"));
    }
}
