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
/// signature that did not appear anywhere in the baseline logs.
pub fn analyze_heuristically(input: &LogAnalysisInput) -> LogAnalysisResult {
    let baseline_signatures = signatures(&input.baseline);
    let candidate_signatures = signatures(&input.candidate);
    let baseline = side(&baseline_signatures);
    let candidate = side(&candidate_signatures);
    let mut new_findings = Vec::new();
    let mut deduplicated = BTreeSet::new();

    for (container, log) in &input.candidate {
        let lower = log.to_ascii_lowercase();
        for (pattern, severity) in SIGNATURES {
            if !lower.contains(pattern)
                || baseline_signatures.contains(pattern)
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

fn signatures(logs: &[(Option<String>, String)]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for (_, log) in logs {
        let lower = log.to_ascii_lowercase();
        for (pattern, _) in SIGNATURES {
            if lower.contains(pattern) {
                found.insert(pattern);
            }
        }
    }
    found
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
    let Some(index) = lower.find(pattern) else {
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
