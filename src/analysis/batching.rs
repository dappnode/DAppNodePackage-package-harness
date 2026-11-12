//! Lossless partitioning of collected log windows into valid JSON requests.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{LogAnalysisInput, LogCollectionContext};

use super::AnalyzerError;

pub(super) const MAX_BATCHES: usize = 64;

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Batch {
    baseline: Vec<(Option<String>, String)>,
    candidate: Vec<(Option<String>, String)>,
    collection: Option<LogCollectionContext>,
    scope: Scope,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Scope {
    batch: usize,
    total_batches: usize,
    collected_windows_only: bool,
    baseline_containers: usize,
    candidate_containers: usize,
    partial_service_windows: bool,
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            // Reserve enough digits while planning so final numbering fits.
            batch: MAX_BATCHES,
            total_batches: MAX_BATCHES,
            collected_windows_only: true,
            baseline_containers: 0,
            candidate_containers: 0,
            partial_service_windows: false,
        }
    }
}

fn json(batch: &Batch) -> Result<String, AnalyzerError> {
    serde_json::to_string(batch).map_err(|error| AnalyzerError::InvalidResponse(error.to_string()))
}

fn prefix(text: &str, bytes: usize) -> &str {
    let mut end = bytes.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Includes every container and every byte of its captured text. Container pairs
/// stay together when they fit. Large pairs are partitioned into windows rather
/// than cutting serialized JSON or discarding later services.
pub(super) fn plan(input: &LogAnalysisInput, limit: usize) -> Result<Vec<String>, AnalyzerError> {
    let empty = Batch {
        collection: input.context.clone(),
        scope: Scope {
            baseline_containers: input.baseline.len(),
            candidate_containers: input.candidate.len(),
            ..Scope::default()
        },
        ..Batch::default()
    };
    let mut groups = BTreeMap::<Option<String>, (Vec<&str>, Vec<&str>)>::new();
    for (name, text) in &input.baseline {
        groups.entry(name.clone()).or_default().0.push(text);
    }
    for (name, text) in &input.candidate {
        groups.entry(name.clone()).or_default().1.push(text);
    }
    let mut batches = Vec::new();
    let mut current = empty.clone();
    for (name, (baseline, candidate)) in groups {
        let baseline = (!baseline.is_empty()).then(|| baseline.join("\n"));
        let candidate = (!candidate.is_empty()).then(|| candidate.join("\n"));
        let mut left = baseline.as_deref();
        let mut right = candidate.as_deref();
        let mut windowed = false;
        loop {
            let append = |bytes: usize, batch: &Batch| -> Batch {
                let mut batch = batch.clone();
                batch.scope.partial_service_windows |= windowed;
                if let Some(text) = left {
                    batch
                        .baseline
                        .push((name.clone(), prefix(text, bytes).to_owned()));
                }
                if let Some(text) = right {
                    batch
                        .candidate
                        .push((name.clone(), prefix(text, bytes).to_owned()));
                }
                batch
            };
            let remaining = left
                .unwrap_or_default()
                .len()
                .max(right.unwrap_or_default().len());
            let full = append(remaining, &current);
            if json(&full)?.len() <= limit {
                current = full;
                break;
            }
            if !current.baseline.is_empty() || !current.candidate.is_empty() {
                batches.push(current);
                current = empty.clone();
                if batches.len() >= MAX_BATCHES {
                    return Err(too_many_batches());
                }
                continue;
            }
            let (mut low, mut high) = (0, remaining);
            while low < high {
                let middle = low + (high - low).div_ceil(2);
                if json(&append(middle, &current))?.len() <= limit {
                    low = middle;
                } else {
                    high = middle - 1;
                }
            }
            let consumed_left = prefix(left.unwrap_or_default(), low).len();
            let consumed_right = prefix(right.unwrap_or_default(), low).len();
            if consumed_left + consumed_right == 0 {
                return Err(AnalyzerError::Configuration(
                    "NEXUS_MAX_INPUT_BYTES cannot fit collection metadata and a log window"
                        .to_owned(),
                ));
            }
            let mut partial = append(low, &current);
            partial.scope.partial_service_windows = true;
            batches.push(partial);
            if batches.len() >= MAX_BATCHES {
                return Err(too_many_batches());
            }
            left = left
                .and_then(|text| (consumed_left < text.len()).then_some(&text[consumed_left..]));
            right = right
                .and_then(|text| (consumed_right < text.len()).then_some(&text[consumed_right..]));
            windowed = true;
        }
    }
    batches.push(current);
    let total = batches.len();
    batches
        .into_iter()
        .enumerate()
        .map(|(index, mut batch)| {
            batch.scope.batch = index + 1;
            batch.scope.total_batches = total;
            let body = json(&batch)?;
            if body.len() > limit {
                return Err(AnalyzerError::Configuration(
                    "NEXUS_MAX_INPUT_BYTES cannot fit collection metadata".to_owned(),
                ));
            }
            Ok(body)
        })
        .collect()
}

fn too_many_batches() -> AnalyzerError {
    AnalyzerError::Configuration(format!(
        "collected logs require more than {MAX_BATCHES} Nexus requests; increase NEXUS_MAX_INPUT_BYTES"
    ))
}

#[cfg(test)]
mod tests {
    use super::plan;
    use crate::model::LogAnalysisInput;
    use std::{collections::BTreeMap, error::Error};

    #[test]
    fn batches_preserve_every_container_and_every_utf8_and_escaped_byte()
    -> Result<(), Box<dyn Error>> {
        let mut input = LogAnalysisInput::default();
        for i in 0..24 {
            let name = Some(format!("service-{i:02}"));
            input.baseline.push((
                name.clone(),
                format!("{}baseline end {i}", "🦀é\"\\\n".repeat(80)),
            ));
            input.candidate.push((
                name,
                format!("{}candidate end {i}", "\t\"é🦀\n".repeat(100)),
            ));
        }
        let batches = plan(&input, 4096)?;
        assert!(batches.len() > 1);
        let mut recovered = BTreeMap::<(String, Option<String>), String>::new();
        for (index, body) in batches.iter().enumerate() {
            assert!(body.len() <= 4096);
            let value: serde_json::Value = serde_json::from_str(body)?;
            assert_eq!(value["scope"]["batch"], index + 1);
            assert_eq!(value["scope"]["totalBatches"], batches.len());
            for side in ["baseline", "candidate"] {
                let entries: Vec<(Option<String>, String)> =
                    serde_json::from_value(value[side].clone())?;
                for (name, text) in entries {
                    recovered
                        .entry((side.to_owned(), name))
                        .or_default()
                        .push_str(&text);
                }
            }
        }
        for (side, entries) in [("baseline", input.baseline), ("candidate", input.candidate)] {
            for (name, text) in entries {
                assert_eq!(recovered.get(&(side.to_owned(), name)), Some(&text));
            }
        }
        Ok(())
    }

    #[test]
    fn large_service_windows_are_explicitly_marked() -> Result<(), Box<dyn Error>> {
        let input = LogAnalysisInput {
            baseline: vec![(Some("service".to_owned()), "baseline\n".repeat(1000))],
            candidate: vec![(Some("service".to_owned()), "candidate\n".repeat(1000))],
            ..Default::default()
        };
        let batches = plan(&input, 4096)?;
        assert!(batches.len() > 1);
        for body in batches {
            let value: serde_json::Value = serde_json::from_str(&body)?;
            assert_eq!(value["scope"]["partialServiceWindows"], true);
        }
        Ok(())
    }

    #[test]
    fn budgets_fail_explicitly_instead_of_silently_dropping_evidence() {
        let input = LogAnalysisInput {
            baseline: vec![(Some("service".to_owned()), "x".repeat(100_000))],
            ..Default::default()
        };
        assert!(plan(&input, 1024).is_err());
        assert!(plan(&LogAnalysisInput::default(), 1).is_err());
    }
}
