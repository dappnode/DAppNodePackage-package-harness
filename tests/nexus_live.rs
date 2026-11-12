use dappnode_package_harness::{
    analysis::{LogAnalyzer, NexusLogAnalyzer},
    model::{LogAnalysisInput, LogCollectionContext},
};
use std::{collections::BTreeMap, error::Error, time::Duration};

#[tokio::test]
#[ignore = "manual Nexus startup probe; uses one synthetic inference token"]
async fn startup_live_probe() -> Result<(), Box<dyn Error>> {
    let settings: BTreeMap<String, String> =
        dotenvy::from_path_iter(".env")?.collect::<Result<_, _>>()?;
    let nexus = NexusLogAnalyzer::new(
        settings
            .get("NEXUS_API_KEY")
            .ok_or("Nexus key missing")?
            .clone(),
        settings
            .get("NEXUS_BASE_URL")
            .ok_or("Nexus base URL missing")?,
        settings
            .get("NEXUS_MODEL")
            .cloned()
            .unwrap_or_else(|| "nexus/auto".into()),
        Duration::from_secs(30),
        65536,
    )?;
    nexus.validate_access().await?;
    println!("Live Nexus startup inference access verified");
    Ok(())
}

#[tokio::test]
#[ignore = "manual Nexus contract probe; uses configured inference credit and synthetic logs"]
async fn synthetic_live_probe() -> Result<(), Box<dyn Error>> {
    let settings: BTreeMap<String, String> =
        dotenvy::from_path_iter(".env")?.collect::<Result<_, _>>()?;
    let key = settings
        .get("NEXUS_API_KEY")
        .ok_or("Nexus key missing")?
        .clone();
    let url = settings
        .get("NEXUS_BASE_URL")
        .ok_or("Nexus base URL missing")?;
    let nexus = NexusLogAnalyzer::new(
        key,
        url,
        "nexus/auto".into(),
        Duration::from_secs(90),
        65536,
    )?
    .with_classifier_model(Some("jev".into()));
    for (text, expected) in [
        (
            "HTTP server listening on port 8080. Startup complete.",
            false,
        ),
        (
            "Database migration 3 of 47 in progress. Migrating records, 8 percent completed.",
            true,
        ),
    ] {
        let input = LogAnalysisInput {
            candidate: vec![(Some("api".into()), text.into())],
            ..Default::default()
        };
        let actual = nexus.needs_more_logs(&input).await?;
        println!("live classifier: expected_more={expected}, actual_more={actual}");
        assert_eq!(actual, expected);
    }
    let routine = "cadvisor: CPU and memory statistics collected normally.\n".repeat(900);
    let input = LogAnalysisInput {
        baseline: vec![(Some("a-cadvisor".into()), routine.clone()), (Some("z-api".into()), "HTTP server listening. Application ready.".into())],
        candidate: vec![(Some("a-cadvisor".into()), routine), (Some("z-api".into()), "ERROR: application cannot start: database permission denied. Exiting with status 1.".into())],
        context: Some(LogCollectionContext { baseline_stable: true, candidate_stable: true, baseline_expected_containers: 2, candidate_expected_containers: 2, ..Default::default() }),
    };
    let result = nexus.analyze(&input).await?;
    println!(
        "live multi-container analysis: status={:?}, findings={}, errors={}, summary={}",
        result.status,
        result.new_findings.len(),
        result.analyzer_errors.len(),
        result.summary
    );
    assert!(result.analyzer_errors.is_empty());
    assert!(!result.new_findings.is_empty());
    Ok(())
}
