use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

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
    pub cleanup_timeout: Duration,
    pub readiness_profiles: crate::runner::readiness::ReadinessProfiles,
    pub nexus_api_key: Option<String>,
    pub nexus_base_url: String,
    pub nexus_model: String,
    /// Optional advisory startup-evidence classifier on the System One API.
    pub nexus_classifier_model: Option<String>,
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
        let stabilization_timeout = millis("STABILIZATION_TIMEOUT_MS", 180_000)?;
        let stabilization_poll = millis("STABILIZATION_POLL_MS", 5_000)?;
        let intervals = u32::try_from(required_samples.saturating_sub(1)).map_err(|error| {
            ConfigError::Invalid {
                name: "STABILIZATION_REQUIRED_SAMPLES",
                message: error.to_string(),
            }
        })?;
        let minimum_stabilization_window = stabilization_poll.saturating_mul(intervals);
        if stabilization_timeout < minimum_stabilization_window {
            return Err(ConfigError::Invalid {
                name: "STABILIZATION_TIMEOUT_MS",
                message: format!(
                    "must allow {required_samples} samples at the configured poll interval"
                ),
            });
        }
        let nexus_max_input_bytes = parse("NEXUS_MAX_INPUT_BYTES", 64 * 1024)?;
        if !(1_024..=1024 * 1024).contains(&nexus_max_input_bytes) {
            return Err(ConfigError::Invalid {
                name: "NEXUS_MAX_INPUT_BYTES",
                message: "must be between 1024 and 1048576 bytes".to_owned(),
            });
        }

        let config = Self {
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
            stabilization_timeout,
            stabilization_poll,
            stabilization_required_samples: required_samples,
            log_tail,
            cleanup_timeout: millis("CLEANUP_TIMEOUT_MS", 60_000)?,
            readiness_profiles: crate::runner::readiness::ReadinessProfiles::from_json(
                &env::var("READINESS_PROFILES").unwrap_or_else(|_| "{}".to_owned()),
            )
            .map_err(|message| ConfigError::Invalid {
                name: "READINESS_PROFILES",
                message,
            })?,
            nexus_api_key: optional("NEXUS_API_KEY"),
            nexus_base_url: env::var("NEXUS_BASE_URL")
                .unwrap_or_else(|_| "https://nexus-api.dappnode.com/v1".to_owned()),
            nexus_model: env::var("NEXUS_MODEL").unwrap_or_else(|_| "nexus/auto".to_owned()),
            nexus_classifier_model: {
                let value = env::var("NEXUS_CLASSIFIER_MODEL").unwrap_or_else(|_| "jev".to_owned());
                (!value.trim().is_empty()).then_some(value)
            },
            nexus_timeout: millis("NEXUS_TIMEOUT_MS", 300_000)?,
            nexus_max_input_bytes,
            tropibot_url,
            package_harness_worker_id,
            package_harness_worker_token,
            package_harness_poll,
            package_harness_heartbeat,
            tropibot_timeout: millis("TROPIBOT_TIMEOUT_MS", 15_000)?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validates settings that would otherwise fail only after claiming work.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_addr.port() == 0 {
            return Err(invalid("PORT", "must be greater than zero"));
        }
        if self.data_dir.as_os_str().is_empty() {
            return Err(invalid("DATA_DIR", "must not be empty"));
        }
        crate::model::DnpName::parse(&self.harness_dnp_name)
            .map_err(|_| invalid("HARNESS_DNP_NAME", "must be a valid Dappnode package name"))?;
        validate_url("TROPIBOT_URL", &self.tropibot_url)?;
        validate_worker_id(&self.package_harness_worker_id)?;
        validate_token(
            "PACKAGE_HARNESS_WORKER_TOKEN",
            &self.package_harness_worker_token,
        )?;
        if self.package_manager_mode == PackageManagerMode::Mcp {
            let url = self
                .dappmanager_mcp_url
                .as_deref()
                .ok_or_else(|| invalid("DAPPMANAGER_MCP_URL", "must be configured in MCP mode"))?;
            validate_http_url("DAPPMANAGER_MCP_URL", url, false)?;
            let token = self.dappmanager_mcp_token.as_deref().ok_or_else(|| {
                invalid("DAPPMANAGER_MCP_TOKEN", "must be configured in MCP mode")
            })?;
            validate_token("DAPPMANAGER_MCP_TOKEN", token)?;
        }
        if let Some(key) = &self.nexus_api_key {
            validate_token("NEXUS_API_KEY", key)?;
            validate_http_url("NEXUS_BASE_URL", &self.nexus_base_url, false)?;
            if self.nexus_model.trim().is_empty() || self.nexus_model.trim() != self.nexus_model {
                return Err(invalid(
                    "NEXUS_MODEL",
                    "must be nonempty without surrounding whitespace",
                ));
            }
            if self
                .nexus_classifier_model
                .as_ref()
                .is_some_and(|model| model.trim().is_empty() || model.trim() != model)
            {
                return Err(invalid(
                    "NEXUS_CLASSIFIER_MODEL",
                    "must not contain surrounding whitespace",
                ));
            }
        }
        Ok(())
    }

    /// Returns the first startup problem that makes destructive tests unsafe.
    pub fn acceptance_error(&self) -> Option<String> {
        if let Err(error) = self.validate() {
            return Some(error.to_string());
        }
        if !self.allow_destructive_tests {
            return Some("ALLOW_DESTRUCTIVE_PACKAGE_TESTS must be true".to_owned());
        }
        None
    }
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
    validate_http_url(name, value, true)
}

fn invalid(name: &'static str, message: &str) -> ConfigError {
    ConfigError::Invalid {
        name,
        message: message.to_owned(),
    }
}

fn validate_token(name: &'static str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 4096
        || !value.bytes().all(|byte| (33..=126).contains(&byte))
    {
        return Err(invalid(
            name,
            "must contain 1-4096 visible ASCII characters without whitespace",
        ));
    }
    Ok(())
}

fn validate_http_url(name: &'static str, value: &str, https_only: bool) -> Result<(), ConfigError> {
    let parsed = reqwest::Url::parse(value).map_err(|error| ConfigError::Invalid {
        name,
        message: error.to_string(),
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || (https_only && parsed.scheme() != "https")
        || parsed.host_str().is_none()
    {
        return Err(ConfigError::Invalid {
            name,
            message: if https_only {
                "must be an absolute HTTPS URL"
            } else {
                "must be an absolute HTTP(S) URL"
            }
            .to_owned(),
        });
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid(
            name,
            "must not contain credentials, a query, a fragment, whitespace, or control characters",
        ));
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
