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

/// Optional external sink for completed run results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultReporterMode {
    /// Disable result delivery.
    None,
    /// Send the raw signed harness result JSON to a configured callback URL.
    Webhook,
    /// Render the result as Markdown and post it directly to the source PR.
    GithubPrComment,
}

/// Runtime configuration loaded from environment variables.
///
/// The validation here intentionally rejects surprisingly large values for
/// timeouts, log tails, and sample counts. Those limits keep the PoC bounded
/// when it is exposed as an API.
#[derive(Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub harness_api_token: Option<String>,
    pub harness_dnp_name: String,
    pub allow_destructive_tests: bool,
    pub package_manager_mode: PackageManagerMode,
    pub dappmanager_mcp_url: Option<String>,
    pub dappmanager_mcp_token: Option<String>,
    pub mcp_timeout: Duration,
    pub stabilization_timeout: Duration,
    pub stabilization_poll: Duration,
    pub stabilization_required_samples: usize,
    pub log_tail: usize,
    pub cleanup_enabled: bool,
    pub cleanup_timeout: Duration,
    pub recover_cleanup_on_start: bool,
    pub nexus_api_key: Option<String>,
    pub nexus_base_url: String,
    pub nexus_model: String,
    pub nexus_timeout: Duration,
    pub nexus_max_input_bytes: usize,
    pub result_reporter_mode: ResultReporterMode,
    pub result_callback_url: Option<String>,
    pub result_callback_hmac_secret: Option<String>,
    pub result_callback_timeout: Duration,
    pub github_app_id: Option<String>,
    pub github_app_private_key: Option<String>,
    pub github_api_base_url: String,
}

impl Config {
    /// Builds configuration from process environment variables.
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
        if log_tail == 0 || log_tail > 500 {
            return Err(ConfigError::Invalid {
                name: "LOG_TAIL",
                message: "must be between 1 and 500".to_owned(),
            });
        }
        let required_samples = parse::<usize>("STABILIZATION_REQUIRED_SAMPLES", 3)?;
        if required_samples == 0 || required_samples > 20 {
            return Err(ConfigError::Invalid {
                name: "STABILIZATION_REQUIRED_SAMPLES",
                message: "must be between 1 and 20".to_owned(),
            });
        }
        let mode = match env::var("PACKAGE_MANAGER_MODE")
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
        let result_reporter_mode = match env::var("RESULT_REPORTER")
            .unwrap_or_else(|_| "auto".to_owned())
            .as_str()
        {
            "auto" => {
                if optional("RESULT_CALLBACK_URL").is_some() {
                    ResultReporterMode::Webhook
                } else {
                    ResultReporterMode::None
                }
            }
            "none" => ResultReporterMode::None,
            "webhook" => ResultReporterMode::Webhook,
            "github_pr_comment" => ResultReporterMode::GithubPrComment,
            value => {
                return Err(ConfigError::Invalid {
                    name: "RESULT_REPORTER",
                    message: format!("unsupported value '{value}'"),
                });
            }
        };

        Ok(Self {
            listen_addr,
            data_dir: env::var_os("DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/data")),
            harness_api_token: optional("HARNESS_API_TOKEN"),
            harness_dnp_name: env::var("HARNESS_DNP_NAME")
                .unwrap_or_else(|_| DEFAULT_HARNESS_DNP_NAME.to_owned()),
            allow_destructive_tests: bool_value("ALLOW_DESTRUCTIVE_PACKAGE_TESTS", false)?,
            package_manager_mode: mode,
            dappmanager_mcp_url: optional("DAPPMANAGER_MCP_URL"),
            dappmanager_mcp_token: optional("DAPPMANAGER_MCP_TOKEN"),
            mcp_timeout: millis("MCP_TIMEOUT_MS", 30_000)?,
            stabilization_timeout: millis("STABILIZATION_TIMEOUT_MS", 180_000)?,
            stabilization_poll: millis("STABILIZATION_POLL_MS", 5_000)?,
            stabilization_required_samples: required_samples,
            log_tail,
            cleanup_enabled: bool_value("CLEANUP_ENABLED", true)?,
            cleanup_timeout: millis("CLEANUP_TIMEOUT_MS", 60_000)?,
            recover_cleanup_on_start: bool_value("RECOVER_CLEANUP_ON_START", false)?,
            nexus_api_key: optional("NEXUS_API_KEY"),
            nexus_base_url: env::var("NEXUS_BASE_URL")
                .unwrap_or_else(|_| "https://nexus-api.dappnode.com/v1".to_owned()),
            nexus_model: env::var("NEXUS_MODEL").unwrap_or_else(|_| "nexus/auto".to_owned()),
            nexus_timeout: millis("NEXUS_TIMEOUT_MS", 30_000)?,
            nexus_max_input_bytes: parse("NEXUS_MAX_INPUT_BYTES", 64 * 1024)?,
            result_reporter_mode,
            result_callback_url: optional("RESULT_CALLBACK_URL"),
            result_callback_hmac_secret: optional("RESULT_CALLBACK_HMAC_SECRET"),
            result_callback_timeout: millis("RESULT_CALLBACK_TIMEOUT_MS", 15_000)?,
            github_app_id: optional("GITHUB_APP_ID"),
            github_app_private_key: github_app_private_key()?,
            github_api_base_url: env::var("GITHUB_API_BASE_URL")
                .unwrap_or_else(|_| "https://api.github.com".to_owned()),
        })
    }

    /// Returns the first startup problem that makes destructive tests unsafe.
    ///
    /// The HTTP server can still start without satisfying these checks, but
    /// `/readyz` will report the issue and run submission will be rejected.
    pub fn acceptance_error(&self) -> Option<String> {
        if self.harness_api_token.is_none() {
            return Some("HARNESS_API_TOKEN is not configured".to_owned());
        }
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
        if self.result_callback_url.is_some() != self.result_callback_hmac_secret.is_some() {
            return Some(
                "RESULT_CALLBACK_URL and RESULT_CALLBACK_HMAC_SECRET must be configured together"
                    .to_owned(),
            );
        }
        match self.result_reporter_mode {
            ResultReporterMode::None => {}
            ResultReporterMode::Webhook => {
                if self.result_callback_url.is_none() || self.result_callback_hmac_secret.is_none()
                {
                    return Some(
                        "RESULT_CALLBACK_URL and RESULT_CALLBACK_HMAC_SECRET must be configured for webhook reporting"
                            .to_owned(),
                    );
                }
            }
            ResultReporterMode::GithubPrComment => {
                if self.github_app_id.is_none() {
                    return Some(
                        "GITHUB_APP_ID must be configured for github_pr_comment reporting"
                            .to_owned(),
                    );
                }
                if self.github_app_private_key.is_none() {
                    return Some(
                        "GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_FILE must be configured for github_pr_comment reporting"
                            .to_owned(),
                    );
                }
            }
        }
        None
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid configuration {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

fn optional(name: &'static str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn github_app_private_key() -> Result<Option<String>, ConfigError> {
    if let Some(value) = optional("GITHUB_APP_PRIVATE_KEY") {
        return Ok(Some(value.replace("\\n", "\n")));
    }
    if let Some(path) = optional("GITHUB_APP_PRIVATE_KEY_FILE") {
        return std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|error| ConfigError::Invalid {
                name: "GITHUB_APP_PRIVATE_KEY_FILE",
                message: format!("cannot read private key file '{path}': {error}"),
            });
    }
    Ok(None)
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
    let value = parse::<u64>(name, default)?;
    if value == 0 || value > 3_600_000 {
        return Err(ConfigError::Invalid {
            name,
            message: "must be between 1 and 3600000 milliseconds".to_owned(),
        });
    }
    Ok(Duration::from_millis(value))
}

fn bool_value(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match env::var(name) {
        Ok(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        Ok(_) => Err(ConfigError::Invalid {
            name,
            message: "must be true, false, 1, or 0".to_owned(),
        }),
        Err(_) => Ok(default),
    }
}
