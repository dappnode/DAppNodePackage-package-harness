use dappnode_package_harness::{
    model::DnpName,
    package_manager::{DappmanagerPackageManager, PackageManager},
};
use std::{collections::BTreeMap, error::Error, time::Duration};

#[tokio::test]
#[ignore = "read-only live MCP probe; requires local .env credentials"]
async fn live_readiness_metadata() -> Result<(), Box<dyn Error>> {
    let settings: BTreeMap<String, String> =
        dotenvy::from_path_iter(".env")?.collect::<Result<_, _>>()?;
    let manager = DappmanagerPackageManager::new(
        settings
            .get("DAPPMANAGER_MCP_URL")
            .ok_or("MCP URL missing")?
            .clone(),
        settings
            .get("DAPPMANAGER_MCP_TOKEN")
            .ok_or("MCP token missing")?
            .clone(),
        Duration::from_secs(15),
        Duration::from_secs(30),
        1,
        Duration::from_secs(1),
    )?;
    let name = DnpName::parse("dappmanager.dnp.dappnode.eth")?;
    let details = manager.get_package_details(&name).await?;
    assert_eq!(details.dnp_name, name);
    assert!(!details.containers.is_empty());
    println!(
        "live containers={}, identity_available={}, Docker_health_available={}, restart_count_available={}",
        details.containers.len(),
        details
            .containers
            .iter()
            .filter(|container| container.container_id.is_some())
            .count(),
        details
            .containers
            .iter()
            .filter(|container| container.health.is_some())
            .count(),
        details
            .containers
            .iter()
            .filter(|container| container.restart_count.is_some())
            .count()
    );
    Ok(())
}
