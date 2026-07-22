use std::{collections::BTreeSet, env, net::SocketAddr, path::PathBuf, time::Duration};

use thiserror::Error;

/// Default DNP name used to keep the harness from testing and removing itself.
pub const DEFAULT_HARNESS_DNP_NAME: &str = "package-harness.dnp.dappnode.eth";

/// Package manager implementation selected at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManagerMode {
    /// Use the real Dappmanager MCP endpoint.
    Mcp,
    /// Use the deterministic in-memory implementation for local development.
    Fake,
}

/// Runtime configuration loaded from environment variables.
///
/// Values that can make destructive execution or coordinator delivery unsafe
/// are validated before the process starts. Credentials are intentionally not
/// included in `Debug` output or any persisted model.
#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub harness_dnp_name: String,
    pub allow_destructive_tests: bool,
    pub package_manager_mode: PackageManagerMode,
    pub dappmanager_mcp_url: Option<String>,
    pub dappmanager_mcp_token: Option<String>,
    pub mcp_timeout: Duration,
    /// Timeout reserved for package installation, update, and removal calls.
    pub mcp_mutation_timeout: Duration,
    /// Maximum number of attempts for transient package mutations.
    pub mcp_mutation_attempts: usize,
    /// Initial delay between transient mutation attempts. Later delays back off.
    pub mcp_mutation_retry_delay: Duration,
    pub stabilization_timeout: Duration,
    pub stabilization_poll: Duration,
    pub stabilization_required_samples: usize,
    pub log_tail: usize,
    pub cleanup_enabled: bool,
    pub cleanup_timeout: Duration,
    /// Packages whose first successful baseline should remain installed and
    /// be restored after subsequent candidate tests.
    pub retain_baseline_packages: BTreeSet<String>,
    pub nexus_api_key: Option<String>,
    pub nexus_base_url: String,
    pub nexus_model: String,
    pub nexus_timeout: Duration,
    pub nexus_max_input_bytes: usize,
    pub tropibot_url: String,
    pub package_harness_worker_id: String,
    pub package_harness_worker_token: String,
    pub package_harness_poll: Duration,
    pub package_harness_heartbeat: Duration,
    pub tropibot_timeout: Duration,
}

impl Config {
    /// Builds complete worker configuration from process environment variables.
    pub fn from_env() -> Result<Self, ConfigError> {
        let port = parse::<u16>("PORT", 8080)?;
        let listen_addr =
            format!("0.0.0.0:{port}")
                .parse()
                .map_err(|error| ConfigError::Invalid {
                    name: "PORT",
                    message: format!("cannot form listen address: {error}"),
                })?;
        let log_tail = parse::<usize>("LOG_TAIL", 300)?;
        if !(1..=500).contains(&log_tail) {
            return Err(ConfigError::Invalid {
                name: "LOG_TAIL",
                message: "must be between 1 and 500".to_owned(),
            });
        }
        let required_samples = parse::<usize>("STABILIZATION_REQUIRED_SAMPLES", 3)?;
        if !(1..=20).contains(&required_samples) {
            return Err(ConfigError::Invalid {
                name: "STABILIZATION_REQUIRED_SAMPLES",
                message: "must be between 1 and 20".to_owned(),
            });
        }
        let mutation_attempts = parse::<usize>("MCP_MUTATION_ATTEMPTS", 3)?;
        if !(1..=10).contains(&mutation_attempts) {
            return Err(ConfigError::Invalid {
                name: "MCP_MUTATION_ATTEMPTS",
                message: "must be between 1 and 10".to_owned(),
            });
        }
        let package_manager_mode = match env::var("PACKAGE_MANAGER_MODE")
            .unwrap_or_else(|_| "mcp".to_owned())
            .as_str()
        {
            "mcp" => PackageManagerMode::Mcp,
            "fake" => PackageManagerMode::Fake,
            value => {
                return Err(ConfigError::Invalid {
                    name: "PACKAGE_MANAGER_MODE",
                    message: format!("unsupported value '{value}'"),
                });
            }
        };
        let tropibot_url = required("TROPIBOT_URL")?;
        validate_url("TROPIBOT_URL", &tropibot_url)?;
        let package_harness_worker_id = required("PACKAGE_HARNESS_WORKER_ID")?;
        validate_worker_id(&package_harness_worker_id)?;
        let package_harness_worker_token = required("PACKAGE_HARNESS_WORKER_TOKEN")?;
        if package_harness_worker_token.len() > 4_096 {
            return Err(ConfigError::Invalid {
                name: "PACKAGE_HARNESS_WORKER_TOKEN",
                message: "must not exceed 4096 bytes".to_owned(),
            });
        }
        let package_harness_poll = required_seconds("PACKAGE_HARNESS_POLL_SECONDS")?;
        let package_harness_heartbeat = required_seconds("PACKAGE_HARNESS_HEARTBEAT_SECONDS")?;

        Ok(Self {
            listen_addr,
            data_dir: env::var_os("DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/data")),
            harness_dnp_name: env::var("HARNESS_DNP_NAME")
                .unwrap_or_else(|_| DEFAULT_HARNESS_DNP_NAME.to_owned()),
            allow_destructive_tests: bool_value("ALLOW_DESTRUCTIVE_PACKAGE_TESTS", false)?,
            package_manager_mode,
            dappmanager_mcp_url: optional("DAPPMANAGER_MCP_URL"),
            dappmanager_mcp_token: optional("DAPPMANAGER_MCP_TOKEN"),
            mcp_timeout: millis("MCP_TIMEOUT_MS", 30_000)?,
            mcp_mutation_timeout: long_millis("MCP_MUTATION_TIMEOUT_MS", 1_800_000)?,
            mcp_mutation_attempts: mutation_attempts,
            mcp_mutation_retry_delay: millis("MCP_MUTATION_RETRY_DELAY_MS", 5_000)?,
            stabilization_timeout: millis("STABILIZATION_TIMEOUT_MS", 180_000)?,
            stabilization_poll: millis("STABILIZATION_POLL_MS", 5_000)?,
            stabilization_required_samples: required_samples,
            log_tail,
            cleanup_enabled: bool_value("CLEANUP_ENABLED", true)?,
            cleanup_timeout: millis("CLEANUP_TIMEOUT_MS", 60_000)?,
            retain_baseline_packages: package_list("RETAIN_BASELINE_PACKAGES")?,
            nexus_api_key: optional("NEXUS_API_KEY"),
            nexus_base_url: env::var("NEXUS_BASE_URL")
                .unwrap_or_else(|_| "https://nexus-api.dappnode.com/v1".to_owned()),
            nexus_model: env::var("NEXUS_MODEL").unwrap_or_else(|_| "nexus/auto".to_owned()),
            nexus_timeout: millis("NEXUS_TIMEOUT_MS", 300_000)?,
            nexus_max_input_bytes: parse("NEXUS_MAX_INPUT_BYTES", 64 * 1024)?,
            tropibot_url,
            package_harness_worker_id,
            package_harness_worker_token,
            package_harness_poll,
            package_harness_heartbeat,
            tropibot_timeout: millis("TROPIBOT_TIMEOUT_MS", 15_000)?,
        })
    }

    /// Returns the first startup problem that makes destructive tests unsafe.
    pub fn acceptance_error(&self) -> Option<String> {
        if !self.allow_destructive_tests {
            return Some("ALLOW_DESTRUCTIVE_PACKAGE_TESTS must be true".to_owned());
        }
        if self.package_manager_mode == PackageManagerMode::Mcp {
            if self.dappmanager_mcp_url.is_none() {
                return Some("DAPPMANAGER_MCP_URL is not configured".to_owned());
            }
            if self.dappmanager_mcp_token.is_none() {
                return Some("DAPPMANAGER_MCP_TOKEN is not configured".to_owned());
            }
        }
        None
    }
}

fn package_list(name: &'static str) -> Result<BTreeSet<String>, ConfigError> {
    let Some(value) = optional(name) else {
        return Ok(BTreeSet::new());
    };
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            crate::model::DnpName::parse(value)
                .map(|name| name.to_string())
                .map_err(|error| ConfigError::Invalid {
                    name,
                    message: format!("invalid package '{value}': {error}"),
                })
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    optional(name).ok_or_else(|| ConfigError::Invalid {
        name,
        message: "must be configured".to_owned(),
    })
}

fn optional(name: &'static str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn validate_url(name: &'static str, value: &str) -> Result<(), ConfigError> {
    let parsed = reqwest::Url::parse(value).map_err(|error| ConfigError::Invalid {
        name,
        message: error.to_string(),
    })?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() {
        return Err(ConfigError::Invalid {
            name,
            message: "must be an absolute HTTPS URL".to_owned(),
        });
    }
    Ok(())
}

fn validate_worker_id(value: &str) -> Result<(), ConfigError> {
    if !(1..=128).contains(&value.len())
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(ConfigError::Invalid {
            name: "PACKAGE_HARNESS_WORKER_ID",
            message: "must contain 1-128 ASCII letters, digits, '.', '_' or '-'".to_owned(),
        });
    }
    Ok(())
}

fn parse<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(value) => value.parse::<T>().map_err(|error| ConfigError::Invalid {
            name,
            message: error.to_string(),
        }),
        Err(_) => Ok(default),
    }
}

fn millis(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    let value = parse(name, default)?;
    if !(100..=600_000).contains(&value) {
        return Err(ConfigError::Invalid {
            name,
            message: "must be between 100 and 600000 milliseconds".to_owned(),
        });
    }
    Ok(Duration::from_millis(value))
}

fn long_millis(name: &'static str, default: u64) -> Result<Duration, ConfigError> {
    let value = parse(name, default)?;
    if !(100..=3_600_000).contains(&value) {
        return Err(ConfigError::Invalid {
            name,
            message: "must be between 100 and 3600000 milliseconds".to_owned(),
        });
    }
    Ok(Duration::from_millis(value))
}

fn required_seconds(name: &'static str) -> Result<Duration, ConfigError> {
    let value = required(name)?
        .parse::<u64>()
        .map_err(|error| ConfigError::Invalid {
            name,
            message: error.to_string(),
        })?;
    if !(1..=300).contains(&value) {
        return Err(ConfigError::Invalid {
            name,
            message: "must be between 1 and 300 seconds".to_owned(),
        });
    }
    Ok(Duration::from_secs(value))
}

fn bool_value(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Err(_) => Ok(default),
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => Err(ConfigError::Invalid {
            name,
            message: "must be 'true' or 'false'".to_owned(),
        }),
    }
}
