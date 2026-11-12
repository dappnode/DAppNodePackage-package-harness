use std::{collections::BTreeSet, error::Error, time::Duration};

use dappnode_package_harness::{
    analysis::{CompositeLogAnalyzer, LogAnalyzer, NexusLogAnalyzer},
    model::{AnalyzerStatus, LogAnalysisInput},
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

fn answer(status: &str, marker: &str) -> Value {
    json!({
        "analyzer": "nexus", "status": status, "summary": marker,
        "baseline": {"status": "clean", "summary": "baseline ready"},
        "candidate": {"status": status, "summary": marker},
        "newFindings": if status == "critical" { vec![json!({
            "severity": "critical", "container": "z-api", "evidence": marker,
            "reason": "candidate application failed"
        })] } else { vec![] }
    })
}

fn completion(status: &str, marker: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "choices": [{"message": {"content": answer(status, marker).to_string()}, "finish_reason": "stop"}]
    }))
}

fn analyzer(server: &MockServer, timeout: Duration) -> Result<NexusLogAnalyzer, Box<dyn Error>> {
    Ok(NexusLogAnalyzer::new(
        "test-key".into(),
        server.uri(),
        "test-model".into(),
        timeout,
        4096,
    )?)
}

fn large_input() -> LogAnalysisInput {
    let mut input = LogAnalysisInput::default();
    for name in ["a-cadvisor", "b-grafana", "z-api"] {
        input.baseline.push((
            Some(name.into()),
            format!("{}\nbaseline ready", "normal metric sample\n".repeat(80)),
        ));
        input.candidate.push((
            Some(name.into()),
            format!(
                "{}\n{}",
                "normal metric sample\n".repeat(80),
                if name == "z-api" {
                    "LAST_SERVICE_REGRESSION"
                } else {
                    "candidate ready"
                }
            ),
        ));
    }
    input
}

#[tokio::test]
async fn later_services_and_regressions_are_analyzed_after_large_cadvisor_logs()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(|request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            let content = body["messages"][1]["content"].as_str().unwrap_or_default();
            if content.contains("LAST_SERVICE_REGRESSION") {
                completion("critical", "LAST_SERVICE_REGRESSION")
            } else {
                completion("clean", "services healthy")
            }
        })
        .mount(&server)
        .await;
    let result = analyzer(&server, Duration::from_secs(2))?
        .analyze(&large_input())
        .await?;
    assert_eq!(result.status, AnalyzerStatus::Critical);
    assert!(
        result
            .new_findings
            .iter()
            .any(|finding| finding.evidence == "LAST_SERVICE_REGRESSION")
    );
    assert!(result.analyzer_errors.is_empty());
    let requests = server.received_requests().await.ok_or("no requests")?;
    assert!(requests.len() > 1);
    let mut names = BTreeSet::new();
    for request in requests {
        let body: Value = serde_json::from_slice(&request.body)?;
        let content = body["messages"][1]["content"].as_str().ok_or("no input")?;
        assert!(content.len() <= 4096);
        let evidence: Value = serde_json::from_str(content)?;
        for side in ["baseline", "candidate"] {
            for entry in evidence[side].as_array().ok_or("missing side")? {
                names.insert(entry[0].as_str().ok_or("missing name")?.to_owned());
            }
        }
    }
    assert_eq!(
        names,
        ["a-cadvisor", "b-grafana", "z-api"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    Ok(())
}

#[tokio::test]
async fn a_slow_batch_preserves_other_findings_and_reports_incomplete_coverage()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(|request: &wiremock::Request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
            if body.to_string().contains("a-cadvisor") {
                completion("clean", "slow").set_delay(Duration::from_secs(2))
            } else if body.to_string().contains("LAST_SERVICE_REGRESSION") {
                completion("critical", "LAST_SERVICE_REGRESSION")
            } else {
                completion("clean", "healthy")
            }
        })
        .mount(&server)
        .await;
    let nexus = analyzer(&server, Duration::from_millis(300))?;
    let composite = CompositeLogAnalyzer::new(nexus);
    let result = composite.analyze(&large_input()).await?;
    assert_eq!(result.status, AnalyzerStatus::Critical);
    assert!(!result.analyzer_errors.is_empty());
    assert!(result.summary.contains("Partial analysis"));
    assert!(
        result
            .new_findings
            .iter()
            .any(|finding| finding.evidence == "LAST_SERVICE_REGRESSION")
    );
    Ok(())
}

#[tokio::test]
async fn failed_batches_never_produce_a_clean_full_coverage_result() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(|request: &wiremock::Request| {
            if String::from_utf8_lossy(&request.body).contains("a-cadvisor") {
                ResponseTemplate::new(500)
            } else {
                completion("clean", "healthy")
            }
        })
        .mount(&server)
        .await;
    let result = analyzer(&server, Duration::from_secs(2))?
        .analyze(&large_input())
        .await?;
    assert_eq!(result.status, AnalyzerStatus::Inconclusive);
    assert!(result.summary.contains("Partial analysis"));
    assert!(!result.analyzer_errors.is_empty());
    Ok(())
}

#[tokio::test]
async fn output_token_truncation_is_detected_even_if_the_json_is_parseable()
-> Result<(), Box<dyn Error>> {
    for message in [
        json!({"content": answer("clean", "apparently healthy").to_string()}),
        json!({"role": "assistant"}),
        json!({"content": null}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": message, "finish_reason": "length"}]
            })))
            .mount(&server)
            .await;
        let error = analyzer(&server, Duration::from_secs(1))?
            .analyze(&LogAnalysisInput::default())
            .await
            .err()
            .ok_or("truncated output accepted")?;
        assert!(error.to_string().contains("output token limit"));
    }
    Ok(())
}

#[tokio::test]
async fn analysis_requires_content_even_when_startup_access_is_valid() -> Result<(), Box<dyn Error>>
{
    for message in [json!({"role": "assistant"}), json!({"content": null})] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": message, "finish_reason": "stop"}]
            })))
            .mount(&server)
            .await;
        let error = analyzer(&server, Duration::from_secs(1))?
            .analyze(&LogAnalysisInput::default())
            .await
            .err()
            .ok_or("empty analysis accepted")?;
        assert!(error.to_string().contains("missing choice content"));
    }
    Ok(())
}

fn decision(choice: &str, confidence: f64, probability: f64) -> Value {
    let remainder = (1.0 - probability) / 2.0;
    let probabilities = ["collect_more", "proceed", "unknown"]
        .into_iter()
        .map(|key| {
            (
                key.to_owned(),
                json!(if key == choice {
                    probability
                } else {
                    remainder
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"answers": {"startup": {"type": "choice", "choice": choice, "confidence": confidence, "probabilities": probabilities}}})
}

#[tokio::test]
async fn classifier_only_requests_more_data_for_a_confident_valid_decision()
-> Result<(), Box<dyn Error>> {
    for (choice, confidence, probability, expected) in [
        ("collect_more", 1.0, 1.0, true),
        ("collect_more", 0.67, 0.78, false),
        ("proceed", 1.0, 1.0, false),
        ("unknown", 0.9, 0.9, false),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/systemone"))
            .and(header("authorization", "Bearer test-key"))
            .and(header(
                "user-agent",
                format!("dappnode-package-harness/{}", env!("CARGO_PKG_VERSION")),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(decision(
                choice,
                confidence,
                probability,
            )))
            .expect(1)
            .mount(&server)
            .await;
        let nexus =
            analyzer(&server, Duration::from_secs(1))?.with_classifier_model(Some("jev".into()));
        let input = LogAnalysisInput {
            candidate: vec![(Some("service".into()), "migrations 3/47".into())],
            ..Default::default()
        };
        assert_eq!(nexus.needs_more_logs(&input).await?, expected);
        let request = server
            .received_requests()
            .await
            .ok_or("no request")?
            .remove(0);
        let body: Value = serde_json::from_slice(&request.body)?;
        assert_eq!(body["model"], "jev");
        assert!(body.get("messages").is_none());
        assert!(body["state"].as_str().is_some());
    }
    Ok(())
}

#[tokio::test]
async fn malformed_and_unavailable_classifier_responses_are_errors() -> Result<(), Box<dyn Error>> {
    for response in [
        ResponseTemplate::new(403),
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_json(json!({"answers": {}})),
        ResponseTemplate::new(200).set_body_json(decision("collect_more", 9.0, 1.0)),
        ResponseTemplate::new(200).set_body_json(decision("unexpected", 1.0, 1.0)),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        let nexus =
            analyzer(&server, Duration::from_secs(1))?.with_classifier_model(Some("jev".into()));
        assert!(
            nexus
                .needs_more_logs(&LogAnalysisInput::default())
                .await
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn classifier_uses_its_own_budget_without_omitting_later_containers()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/systemone"))
        .respond_with(ResponseTemplate::new(200).set_body_json(decision("proceed", 1.0, 1.0)))
        .expect(1)
        .mount(&server)
        .await;
    let nexus = NexusLogAnalyzer::new(
        "test-key".into(),
        server.uri(),
        "test-model".into(),
        Duration::from_secs(1),
        1024 * 1024,
    )?
    .with_classifier_model(Some("jev".into()));
    let input = LogAnalysisInput {
        candidate: (0..60)
            .map(|i| {
                (
                    Some(format!("service-{i}")),
                    format!("{}\nlatest-ready-{i}", "\"\\\n🦀".repeat(900)),
                )
            })
            .collect(),
        ..Default::default()
    };
    assert!(!nexus.needs_more_logs(&input).await?);
    let request = server
        .received_requests()
        .await
        .ok_or("no request")?
        .remove(0);
    assert!(request.body.len() <= 48 * 1024);
    let body: Value = serde_json::from_slice(&request.body)?;
    let state: Value = serde_json::from_str(body["state"].as_str().ok_or("no classifier state")?)?;
    let entries: Vec<(Option<String>, String)> =
        serde_json::from_value(state["candidate"].clone())?;
    assert_eq!(entries.len(), 60);
    for (index, (name, text)) in entries.into_iter().enumerate() {
        assert_eq!(name.as_deref(), Some(format!("service-{index}").as_str()));
        assert!(text.ends_with(&format!("latest-ready-{index}")));
    }
    Ok(())
}

#[tokio::test]
async fn critical_nexus_findings_survive_a_full_list_of_heuristic_warnings()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(completion("critical", "important new failure"))
        .mount(&server)
        .await;
    let composite = CompositeLogAnalyzer::new(analyzer(&server, Duration::from_secs(1))?);
    let input = LogAnalysisInput {
        candidate: (0..20)
            .map(|i| (Some(format!("service-{i}")), "permission denied".to_owned()))
            .collect(),
        ..Default::default()
    };
    let result = composite.analyze(&input).await?;
    assert_eq!(result.status, AnalyzerStatus::Critical);
    assert_eq!(result.new_findings.len(), 20);
    assert!(
        result
            .new_findings
            .iter()
            .any(|finding| finding.evidence == "important new failure")
    );
    Ok(())
}
