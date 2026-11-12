use std::{error::Error, time::Duration};

use dappnode_package_harness::{
    config::{Config, PackageManagerMode},
    coordinator::CoordinatorClient,
    package_manager::{DappmanagerPackageManager, MUTATING_MCP_TOOLS, REQUIRED_MCP_TOOLS},
    startup::validate_dependencies,
    storage::{FileRunStore, RunStore},
};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{header, method, path},
};

fn config() -> Result<Config, Box<dyn Error>> {
    Ok(Config {
        listen_addr: "127.0.0.1:8080".parse()?,
        data_dir: "/data".into(),
        harness_dnp_name: "package-harness.dnp.dappnode.eth".into(),
        allow_destructive_tests: true,
        package_manager_mode: PackageManagerMode::Mcp,
        dappmanager_mcp_url: Some("http://my.dappnode/mcp".into()),
        dappmanager_mcp_token: Some("mcp-test-token".into()),
        mcp_timeout: Duration::from_millis(500),
        mcp_mutation_timeout: Duration::from_secs(1),
        mcp_mutation_attempts: 1,
        mcp_mutation_retry_delay: Duration::from_millis(100),
        stabilization_timeout: Duration::from_secs(1),
        stabilization_poll: Duration::from_millis(100),
        stabilization_required_samples: 1,
        log_tail: 1,
        cleanup_timeout: Duration::from_secs(1),
        readiness_profiles: Default::default(),
        nexus_api_key: None,
        nexus_base_url: "https://nexus.example/v1".into(),
        nexus_model: "nexus/auto".into(),
        nexus_classifier_model: None,
        nexus_timeout: Duration::from_millis(500),
        nexus_max_input_bytes: 1024,
        tropibot_url: "https://tropibot.example".into(),
        package_harness_worker_id: "worker-01".into(),
        package_harness_worker_token: "worker-test-token".into(),
        package_harness_poll: Duration::from_secs(1),
        package_harness_heartbeat: Duration::from_secs(1),
        tropibot_timeout: Duration::from_millis(500),
    })
}

#[derive(Clone, Default)]
struct McpResponse {
    read_only: bool,
    failing_tool: Option<&'static str>,
    invalid_inventory: bool,
}

impl wiremock::Respond for McpResponse {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let result = match body["method"].as_str() {
            Some("initialize") => json!({
                "protocolVersion": "2025-03-26", "capabilities": {"tools": {}},
                "serverInfo": {"name": "dappnode", "version": "test"}
            }),
            Some("notifications/initialized") => return ResponseTemplate::new(202),
            Some("tools/list") => json!({"tools": REQUIRED_MCP_TOOLS.iter()
                .filter(|tool| !self.read_only || !MUTATING_MCP_TOOLS.contains(tool))
                .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
                .collect::<Vec<_>>() }),
            Some("tools/call") => {
                let tool = body["params"]["name"].as_str().unwrap_or_default();
                let output = match tool {
                    "dappnode_list_packages" if self.invalid_inventory => json!({"unexpected": []}),
                    "dappnode_list_packages" => {
                        json!([{"dnpName": "dappmanager.dnp.dappnode.eth", "version": "0.1.0", "isCore": true}])
                    }
                    "dappnode_get_package_details" => {
                        json!({"dnpName": "dappmanager.dnp.dappnode.eth", "containers": []})
                    }
                    "dappnode_get_package_logs" => {
                        json!({"dnpName": "dappmanager.dnp.dappnode.eth", "containers": {"test": "private startup log"}})
                    }
                    "dappnode_fetch_install_preview" => {
                        json!({"dnpName": "dappmanager.dnp.dappnode.eth", "semVersion": "0.1.0"})
                    }
                    _ => return ResponseTemplate::new(400),
                };
                let failed = self.failing_tool == Some(tool);
                json!({"isError": failed, "content": [{"type": "text", "text": if failed {
                    "permission denied: mcp-test-token worker-test-token".to_owned()
                } else { output.to_string() }}]})
            }
            _ => return ResponseTemplate::new(400),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

async fn validate(config: &Config, server: &MockServer) -> Result<(), Box<dyn Error>> {
    let manager = DappmanagerPackageManager::new(
        format!("{}/mcp", server.uri()),
        "mcp-test-token".into(),
        config.mcp_timeout,
        config.mcp_mutation_timeout,
        1,
        Duration::from_millis(100),
    )?;
    let coordinator = CoordinatorClient::new(
        &server.uri(),
        config.package_harness_worker_id.clone(),
        config.package_harness_worker_token.clone(),
        config.tropibot_timeout,
    )?;
    validate_dependencies(config, &manager, &coordinator).await?;
    Ok(())
}

async fn mount_mcp(server: &MockServer, response: McpResponse) {
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("authorization", "Bearer mcp-test-token"))
        .respond_with(response)
        .mount(server)
        .await;
}

async fn mount_coordinator(server: &MockServer, response: ResponseTemplate, calls: u64) {
    Mock::given(method("GET"))
        .and(path("/v1/package-harness/workers/worker-01/lost-job"))
        .and(header("authorization", "Bearer worker-test-token"))
        .respond_with(response)
        .expect(calls)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/package-harness/jobs/claim"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(server)
        .await;
}

#[tokio::test]
async fn startup_checks_real_mcp_reads_and_coordinator_without_mutations_or_claims()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    mount_mcp(&server, McpResponse::default()).await;
    mount_coordinator(&server, ResponseTemplate::new(204), 1).await;
    validate(&config()?, &server).await?;
    let requests = server
        .received_requests()
        .await
        .ok_or("no requests captured")?;
    let calls: Vec<Value> = requests
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter(|body| body["method"] == "tools/call")
        .collect();
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|body| {
        !MUTATING_MCP_TOOLS.contains(&body["params"]["name"].as_str().unwrap_or_default())
    }));
    let logs = calls
        .iter()
        .find(|body| body["params"]["name"] == "dappnode_get_package_logs")
        .ok_or("logs not probed")?;
    assert_eq!(logs["params"]["arguments"]["tail"], 1);
    Ok(())
}

#[tokio::test]
async fn startup_rejects_missing_mutation_permissions() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    mount_mcp(
        &server,
        McpResponse {
            read_only: true,
            ..Default::default()
        },
    )
    .await;
    mount_coordinator(&server, ResponseTemplate::new(204), 0).await;
    let error = validate(&config()?, &server)
        .await
        .err()
        .ok_or("startup accepted read-only MCP")?
        .to_string();
    for tool in MUTATING_MCP_TOOLS {
        assert!(error.contains(tool));
    }
    assert!(error.contains("System > Advanced"));
    Ok(())
}

#[tokio::test]
async fn startup_rejects_each_read_failure_and_redacts_credentials() -> Result<(), Box<dyn Error>> {
    for tool in REQUIRED_MCP_TOOLS
        .into_iter()
        .filter(|tool| !MUTATING_MCP_TOOLS.contains(tool))
    {
        let server = MockServer::start().await;
        mount_mcp(
            &server,
            McpResponse {
                failing_tool: Some(tool),
                ..Default::default()
            },
        )
        .await;
        mount_coordinator(&server, ResponseTemplate::new(204), 0).await;
        let error = validate(&config()?, &server)
            .await
            .err()
            .ok_or("startup accepted failed read")?
            .to_string();
        assert!(error.contains("permission denied"));
        assert!(!error.contains("mcp-test-token"));
        assert!(!error.contains("worker-test-token"));
    }
    Ok(())
}

#[tokio::test]
async fn startup_rejects_invalid_inventory_and_mcp_authentication() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    mount_mcp(
        &server,
        McpResponse {
            invalid_inventory: true,
            ..Default::default()
        },
    )
    .await;
    assert!(validate(&config()?, &server).await.is_err());
    server.reset().await;
    Mock::given(path("/mcp"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    assert!(validate(&config()?, &server).await.is_err());
    server.reset().await;
    Mock::given(path("/mcp"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;
    let error = validate(&config()?, &server)
        .await
        .err()
        .ok_or("MCP timeout was accepted")?
        .to_string();
    assert!(error.contains("timed out"));
    Ok(())
}

#[tokio::test]
async fn startup_rejects_coordinator_authentication_protocol_and_timeout_failures()
-> Result<(), Box<dyn Error>> {
    for response in [
        ResponseTemplate::new(401),
        ResponseTemplate::new(403),
        ResponseTemplate::new(200).set_body_json(json!({"schemaVersion": 999})),
        ResponseTemplate::new(204).set_delay(Duration::from_secs(2)),
    ] {
        let server = MockServer::start().await;
        mount_mcp(&server, McpResponse::default()).await;
        mount_coordinator(&server, response, 1).await;
        let error = validate(&config()?, &server)
            .await
            .err()
            .ok_or("startup accepted invalid coordinator")?
            .to_string();
        assert!(error.contains("Tropibot authentication and worker protocol"));
    }
    Ok(())
}

#[tokio::test]
async fn startup_preserves_lost_job_for_worker_recovery() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    mount_mcp(&server, McpResponse::default()).await;
    mount_coordinator(
        &server,
        ResponseTemplate::new(200)
            .set_body_string(include_str!("fixtures/worker-lost-job-response.json")),
        1,
    )
    .await;
    validate(&config()?, &server).await
}

#[tokio::test]
async fn startup_checks_configured_nexus_access_before_acceptance() -> Result<(), Box<dyn Error>> {
    for status in [200, 401, 402, 403, 404, 500] {
        let server = MockServer::start().await;
        mount_mcp(&server, McpResponse::default()).await;
        mount_coordinator(&server, ResponseTemplate::new(204), 1).await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer nexus-test-key"))
            .and(wiremock::matchers::body_json(json!({
                "model": "nexus/auto", "messages": [{"role": "user", "content": "Reply OK."}],
                "stream": false, "max_tokens": 1
            })))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(json!({"choices": [{"message": {"content": "OK"}}]})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut config = config()?;
        config.nexus_api_key = Some("nexus-test-key".into());
        config.nexus_base_url = format!("{}/v1", server.uri());
        assert_eq!(validate(&config, &server).await.is_ok(), status == 200);
    }
    Ok(())
}

#[tokio::test]
async fn startup_accepts_token_limited_nexus_completions_without_content()
-> Result<(), Box<dyn Error>> {
    for message in [
        json!({"role": "assistant"}),
        json!({"role": "assistant", "content": null}),
        json!({"role": "assistant", "content": ""}),
        json!({"role": "assistant", "reasoning_content": "thinking"}),
    ] {
        let server = MockServer::start().await;
        mount_mcp(&server, McpResponse::default()).await;
        mount_coordinator(&server, ResponseTemplate::new(204), 1).await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer nexus-test-key"))
            .and(wiremock::matchers::body_json(json!({
                "model": "nexus/auto", "messages": [{"role": "user", "content": "Reply OK."}],
                "stream": false, "max_tokens": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "choices": [{"message": message, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 201, "completion_tokens": 1, "total_tokens": 202}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let mut config = config()?;
        config.nexus_api_key = Some("nexus-test-key".into());
        config.nexus_base_url = format!("{}/v1", server.uri());
        validate(&config, &server).await?;
    }
    Ok(())
}

#[tokio::test]
async fn startup_still_rejects_empty_malformed_and_error_nexus_responses()
-> Result<(), Box<dyn Error>> {
    for response in [
        ResponseTemplate::new(200).set_body_json(json!({"choices": []})),
        ResponseTemplate::new(200).set_body_json(json!({"error": {"message": "denied"}})),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{}]})),
        ResponseTemplate::new(200).set_body_string("not JSON"),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"role": "assistant"}}]})),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"content": null}, "finish_reason": "stop"}]})),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"content": " "}, "finish_reason": "stop"}]})),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"content": []}, "finish_reason": "length"}]})),
        ResponseTemplate::new(200).set_body_json(json!({"choices": [{"message": {"content": "filtered"}, "finish_reason": "content_filter"}]})),
        ResponseTemplate::new(200).set_delay(Duration::from_secs(2)),
    ] {
        let server = MockServer::start().await;
        mount_mcp(&server, McpResponse::default()).await;
        mount_coordinator(&server, ResponseTemplate::new(204), 1).await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let mut config = config()?;
        config.nexus_api_key = Some("nexus-test-key".into());
        config.nexus_base_url = format!("{}/v1", server.uri());
        let error = validate(&config, &server)
            .await
            .err()
            .ok_or("startup accepted invalid Nexus inference response")?
            .to_string();
        assert!(error.contains("Nexus inference access"));
        assert!(!error.contains("nexus-test-key"));
    }
    Ok(())
}

#[test]
fn configuration_rejects_invalid_settings_without_exposing_secrets() -> Result<(), Box<dyn Error>> {
    let valid = config()?;
    valid.validate()?;
    let mut invalid = valid.clone();
    invalid.dappmanager_mcp_token = Some("secret token\n".into());
    let error = invalid
        .validate()
        .err()
        .ok_or("invalid token accepted")?
        .to_string();
    assert!(error.contains("DAPPMANAGER_MCP_TOKEN"));
    assert!(!error.contains("secret token"));
    for url in [
        "file:///tmp/mcp",
        "http://user:secret@node/mcp",
        "http://node/mcp?token=secret",
        "http://node/mcp#fragment",
    ] {
        let mut invalid = valid.clone();
        invalid.dappmanager_mcp_url = Some(url.into());
        assert!(invalid.validate().is_err());
    }
    let mut invalid = valid.clone();
    invalid.harness_dnp_name = "wrong package name".into();
    assert!(invalid.validate().is_err());
    let mut invalid = valid.clone();
    invalid.dappmanager_mcp_token = None;
    assert!(invalid.validate().is_err());
    invalid.package_manager_mode = PackageManagerMode::Fake;
    invalid.validate()?;
    invalid.allow_destructive_tests = false;
    assert!(invalid.acceptance_error().is_some());
    let mut invalid = valid.clone();
    invalid.listen_addr.set_port(0);
    assert!(invalid.validate().is_err());
    let mut invalid = valid.clone();
    invalid.data_dir = "".into();
    assert!(invalid.validate().is_err());
    let mut invalid = valid.clone();
    invalid.package_harness_worker_token = "has whitespace".into();
    assert!(invalid.validate().is_err());
    let mut invalid = valid;
    invalid.nexus_api_key = Some("nexus-test-key".into());
    invalid.nexus_model = " ".into();
    assert!(invalid.validate().is_err());
    Ok(())
}

#[tokio::test]
async fn storage_validation_leaves_no_probe_files_or_records() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = FileRunStore::new(directory.path().into()).await?;
    assert!(store.load_all().await?.is_empty());
    assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
    let file = tempfile::NamedTempFile::new()?;
    assert!(FileRunStore::new(file.path().into()).await.is_err());
    Ok(())
}

#[tokio::test]
async fn binary_exits_before_starting_worker_when_mcp_permissions_are_missing()
-> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    mount_mcp(
        &server,
        McpResponse {
            read_only: true,
            ..Default::default()
        },
    )
    .await;
    let endpoint = format!("{}/mcp", server.uri());
    let output = tokio::task::spawn_blocking(move || -> Result<_, Box<dyn Error + Send + Sync>> {
        // A clean environment and working directory prevent local .env credentials
        // from entering the child process or contacting real services.
        let directory = tempfile::tempdir()?;
        Ok(
            std::process::Command::new(env!("CARGO_BIN_EXE_dappnode-package-harness"))
                .env_clear()
                .current_dir(directory.path())
                .env("DATA_DIR", directory.path())
                .env("PACKAGE_MANAGER_MODE", "mcp")
                .env("ALLOW_DESTRUCTIVE_PACKAGE_TESTS", "true")
                .env("DAPPMANAGER_MCP_URL", endpoint)
                .env("DAPPMANAGER_MCP_TOKEN", "mcp-test-token")
                .env("MCP_TIMEOUT_MS", "1000")
                .env("TROPIBOT_URL", "https://unused.invalid")
                .env("PACKAGE_HARNESS_WORKER_ID", "worker-01")
                .env("PACKAGE_HARNESS_WORKER_TOKEN", "worker-test-token")
                .env("PACKAGE_HARNESS_POLL_SECONDS", "1")
                .env("PACKAGE_HARNESS_HEARTBEAT_SECONDS", "1")
                .output()?,
        )
    })
    .await?
    .map_err(|error| -> Box<dyn Error> { error })?;
    assert!(!output.status.success());
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(logs.contains("Dappmanager tools and token"));
    assert!(logs.contains("dappnode_install_package"));
    assert!(!logs.contains("worker_polling_started"));
    assert!(!logs.contains("worker_spawned"));
    assert!(!logs.contains("mcp-test-token"));
    assert!(!logs.contains("worker-test-token"));
    Ok(())
}
