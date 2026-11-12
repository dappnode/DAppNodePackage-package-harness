//! Operator-configured, bounded application observations. Targets never come
//! from coordinator jobs, package manifests, or model output.

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct ReadinessProfiles(pub BTreeMap<String, PackageReadiness>);

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageReadiness {
    #[serde(default)]
    pub probes: Vec<ReadinessProbe>,
    #[serde(default)]
    pub require_docker_health: bool,
}

#[derive(Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReadinessProbe {
    Http {
        name: String,
        url: String,
        #[serde(default = "ok_status")]
        expected_status: u16,
        #[serde(default)]
        body_contains: Option<String>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
    Tcp {
        name: String,
        host: String,
        port: u16,
    },
    JsonRpc {
        name: String,
        url: String,
        method: String,
        #[serde(default)]
        params: Vec<Value>,
        #[serde(default)]
        expected_result: Option<Value>,
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
}

fn ok_status() -> u16 {
    200
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub name: String,
    pub passed: bool,
    pub error: Option<String>,
}

impl ReadinessProfiles {
    pub fn from_json(value: &str) -> Result<Self, String> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }
        if value.len() > 64 * 1024 {
            return Err("must not exceed 65536 bytes".into());
        }
        let profiles: Self = serde_json::from_str(value).map_err(|error| {
            format!(
                "expected a package-name to readiness-profile JSON object (line {}, column {})",
                error.line(),
                error.column()
            )
        })?;
        if profiles.0.len() > 100 {
            return Err("must not contain more than 100 packages".into());
        }
        for (name, profile) in &profiles.0 {
            crate::model::DnpName::parse(name)
                .map_err(|_| "profile key must be a Dappnode package name".to_owned())?;
            if profile.probes.len() > 16 {
                return Err("each profile may contain at most 16 probes".into());
            }
            let mut names = std::collections::BTreeSet::new();
            for probe in &profile.probes {
                let name = probe.name();
                if name.is_empty()
                    || name.len() > 64
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                    || !names.insert(name)
                {
                    return Err(
                        "probe names must be unique 1-64 character ASCII identifiers".into(),
                    );
                }
                match probe {
                    ReadinessProbe::Http {
                        url,
                        expected_status,
                        body_contains,
                        headers,
                        ..
                    } => {
                        validate_url(url)?;
                        if !(200..=399).contains(expected_status)
                            || body_contains.as_ref().is_some_and(|text| text.len() > 4096)
                        {
                            return Err("HTTP expectedStatus must be 200-399 and bodyContains at most 4096 bytes".into());
                        }
                        validate_headers(headers)?;
                    }
                    ReadinessProbe::Tcp { host, port, .. } => {
                        if *port == 0
                            || host.is_empty()
                            || host.len() > 253
                            || !host
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || ".-:_".contains(c))
                        {
                            return Err(
                                "TCP probes require a hostname/IP and a nonzero port".into()
                            );
                        }
                    }
                    ReadinessProbe::JsonRpc {
                        url,
                        method,
                        params,
                        headers,
                        ..
                    } => {
                        validate_url(url)?;
                        if ![
                            "web3_clientVersion",
                            "eth_blockNumber",
                            "eth_syncing",
                            "net_listening",
                            "getblockchaininfo",
                            "getnetworkinfo",
                        ]
                        .contains(&method.as_str())
                            || serde_json::to_vec(params).map_or(true, |bytes| bytes.len() > 4096)
                        {
                            return Err("JSON-RPC method must be a supported read-only readiness method; params must fit 4096 bytes".into());
                        }
                        validate_headers(headers)?;
                    }
                }
            }
        }
        Ok(profiles)
    }

    pub fn for_package(&self, name: &str) -> PackageReadiness {
        self.0.get(name).cloned().unwrap_or_default()
    }
}

fn validate_url(value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| "probe URL must be an absolute HTTP(S) URL".to_owned())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || value.chars().any(char::is_whitespace)
    {
        return Err("probe URL must use HTTP(S), contain a host, and omit credentials/fragments/whitespace; use headers for credentials".into());
    }
    Ok(())
}

fn validate_headers(headers: &BTreeMap<String, String>) -> Result<(), String> {
    if headers.len() > 16 {
        return Err("at most 16 probe headers are allowed".into());
    }
    for (name, value) in headers {
        if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || value.len() > 4096
            || reqwest::header::HeaderValue::from_str(value).is_err()
        {
            return Err("probe header name or value is invalid".into());
        }
        if ["host", "content-length", "transfer-encoding"]
            .contains(&name.to_ascii_lowercase().as_str())
        {
            return Err("probe headers cannot override Host or HTTP message framing".into());
        }
    }
    Ok(())
}

impl ReadinessProbe {
    pub fn name(&self) -> &str {
        match self {
            Self::Http { name, .. } | Self::Tcp { name, .. } | Self::JsonRpc { name, .. } => name,
        }
    }

    pub async fn check(&self, client: &reqwest::Client) -> ProbeResult {
        let outcome = tokio::time::timeout(Duration::from_secs(5), self.observe(client)).await;
        let error = match outcome {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(_) => Some("probe timed out".to_owned()),
        };
        ProbeResult {
            name: self.name().to_owned(),
            passed: error.is_none(),
            error,
        }
    }

    async fn observe(&self, client: &reqwest::Client) -> Result<(), String> {
        let (request, expected_status, contains, rpc) = match self {
            Self::Tcp { host, port, .. } => {
                tokio::net::TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|_| "TCP connection failed".to_owned())?;
                return Ok(());
            }
            Self::Http {
                url,
                expected_status,
                body_contains,
                headers,
                ..
            } => {
                let mut request = client.get(url);
                for (key, value) in headers {
                    request = request.header(key, value);
                }
                (request, *expected_status, body_contains.as_deref(), None)
            }
            Self::JsonRpc {
                url,
                method,
                params,
                expected_result,
                headers,
                ..
            } => {
                let mut request = client
                    .post(url)
                    .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}));
                for (key, value) in headers {
                    request = request.header(key, value);
                }
                (request, 200, None, Some((method.as_str(), expected_result)))
            }
        };
        let response = request
            .send()
            .await
            .map_err(|_| "probe request failed".to_owned())?;
        if response.status().as_u16() != expected_status {
            return Err(format!(
                "expected HTTP {expected_status}, received HTTP {}",
                response.status().as_u16()
            ));
        }
        if contains.is_none() && rpc.is_none() {
            return Ok(());
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "probe response could not be read".to_owned())?;
            if body.len() + chunk.len() > 64 * 1024 {
                return Err("probe response exceeds 65536 bytes".into());
            }
            body.extend_from_slice(&chunk);
        }
        if let Some(expected) = contains
            && !String::from_utf8_lossy(&body).contains(expected)
        {
            return Err("HTTP response did not contain the expected readiness marker".into());
        }
        if let Some((method, expected)) = rpc {
            let value: Value = serde_json::from_slice(&body)
                .map_err(|_| "probe did not return JSON".to_owned())?;
            if value["id"] != 1
                || value.get("error").is_some_and(|error| !error.is_null())
                || value.get("result").is_none_or(Value::is_null)
            {
                return Err("JSON-RPC response has no successful matching result".into());
            }
            if let Some(expected) = expected {
                if value["result"] != *expected {
                    return Err("JSON-RPC result did not match the readiness expectation".into());
                }
            } else if method == "net_listening" && value["result"] != true {
                return Err("JSON-RPC node is not listening".into());
            }
        }
        Ok(())
    }
}

pub fn client() -> Result<reqwest::Client, reqwest::Error> {
    crate::tls::ensure_crypto_provider();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .build()
}
