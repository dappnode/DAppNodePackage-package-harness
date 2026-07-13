use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{clock::Clock, model::HarnessResult};

use super::{ReportOutcome, ReporterError, ResultReporter};

pub struct GithubPrCommentReporter {
    client: reqwest::Client,
    api_base_url: String,
    auth: GithubAuth,
    timeout: Duration,
    clock: Arc<dyn Clock>,
}

enum GithubAuth {
    App {
        app_id: String,
        private_key_pem: String,
    },
    Token(String),
}

impl GithubPrCommentReporter {
    pub fn new(
        api_base_url: String,
        app_id: String,
        private_key_pem: String,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ReporterError> {
        let _ = app_jwt(&app_id, &private_key_pem, clock.now().timestamp())?;
        Self::new_with_auth(
            api_base_url,
            GithubAuth::App {
                app_id,
                private_key_pem,
            },
            timeout,
            clock,
        )
    }

    pub fn new_with_token(
        api_base_url: String,
        token: String,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ReporterError> {
        Self::new_with_auth(api_base_url, GithubAuth::Token(token), timeout, clock)
    }

    fn new_with_auth(
        api_base_url: String,
        auth: GithubAuth,
        timeout: Duration,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ReporterError> {
        crate::tls::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ReporterError {
                attempts: 0,
                http_status: None,
                message: error.to_string(),
            })?;
        Ok(Self {
            client,
            api_base_url: api_base_url.trim_end_matches('/').to_owned(),
            auth,
            timeout,
            clock,
        })
    }

    async fn comment_token(&self, repository: &str) -> Result<String, ReporterError> {
        match &self.auth {
            GithubAuth::Token(token) => Ok(token.clone()),
            GithubAuth::App {
                app_id,
                private_key_pem,
            } => {
                let jwt = app_jwt(app_id, private_key_pem, self.clock.now().timestamp())?;
                let installation_id = self.installation_id(repository, &jwt).await?;
                self.installation_token(installation_id, &jwt).await
            }
        }
    }

    async fn installation_id(&self, repository: &str, jwt: &str) -> Result<u64, ReporterError> {
        let url = format!("{}/repos/{repository}/installation", self.api_base_url);
        let response = self
            .client
            .get(url)
            .bearer_auth(jwt)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", "dappnode-package-harness")
            .send()
            .await
            .map_err(|error| ReporterError {
                attempts: 0,
                http_status: None,
                message: error.to_string(),
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ReporterError {
                attempts: 0,
                http_status: Some(status.as_u16()),
                message: format!(
                    "GitHub installation lookup returned HTTP {}",
                    status.as_u16()
                ),
            });
        }
        let body = response
            .json::<InstallationResponse>()
            .await
            .map_err(|error| ReporterError {
                attempts: 0,
                http_status: Some(status.as_u16()),
                message: format!("GitHub installation lookup response was invalid: {error}"),
            })?;
        Ok(body.id)
    }

    async fn installation_token(
        &self,
        installation_id: u64,
        jwt: &str,
    ) -> Result<String, ReporterError> {
        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.api_base_url
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(jwt)
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", "2022-11-28")
            .header("user-agent", "dappnode-package-harness")
            .send()
            .await
            .map_err(|error| ReporterError {
                attempts: 0,
                http_status: None,
                message: error.to_string(),
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(ReporterError {
                attempts: 0,
                http_status: Some(status.as_u16()),
                message: format!(
                    "GitHub installation token returned HTTP {}",
                    status.as_u16()
                ),
            });
        }
        let body = response
            .json::<InstallationTokenResponse>()
            .await
            .map_err(|error| ReporterError {
                attempts: 0,
                http_status: Some(status.as_u16()),
                message: format!("GitHub installation token response was invalid: {error}"),
            })?;
        Ok(body.token)
    }
}

#[async_trait]
impl ResultReporter for GithubPrCommentReporter {
    async fn report(&self, result: &HarnessResult) -> Result<ReportOutcome, ReporterError> {
        let token = self.comment_token(&result.source.repository).await?;
        let url = format!(
            "{}/repos/{}/issues/{}/comments",
            self.api_base_url, result.source.repository, result.source.pull_request
        );
        let body = json!({ "body": markdown_comment(result) });
        let mut last_error = "GitHub PR comment delivery failed".to_owned();
        let mut last_status = None;

        for attempt in 1..=3_u8 {
            let response = tokio::time::timeout(
                self.timeout,
                self.client
                    .post(&url)
                    .bearer_auth(&token)
                    .header("accept", "application/vnd.github+json")
                    .header("x-github-api-version", "2022-11-28")
                    .header("user-agent", "dappnode-package-harness")
                    .json(&body)
                    .send(),
            )
            .await;
            match response {
                Ok(Ok(response)) if response.status().is_success() => {
                    return Ok(ReportOutcome {
                        attempts: attempt,
                        http_status: Some(response.status().as_u16()),
                    });
                }
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    last_status = Some(status);
                    last_error = format!("GitHub returned HTTP {status}");
                    if !transient_status(status) {
                        return Err(ReporterError {
                            attempts: attempt,
                            http_status: last_status,
                            message: last_error,
                        });
                    }
                }
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => last_error = "GitHub request timed out".to_owned(),
            }
            if attempt < 3 {
                self.clock
                    .sleep(Duration::from_millis(
                        100 * 2_u64.pow(u32::from(attempt - 1)),
                    ))
                    .await;
            }
        }
        Err(ReporterError {
            attempts: 3,
            http_status: last_status,
            message: last_error,
        })
    }
}

#[derive(Debug, Serialize)]
struct AppJwtClaims<'a> {
    iat: i64,
    exp: i64,
    iss: &'a str,
}

#[derive(Debug, Deserialize)]
struct InstallationResponse {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
}

fn app_jwt(app_id: &str, private_key_pem: &str, now: i64) -> Result<String, ReporterError> {
    let claims = AppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now.saturating_add(540),
        iss: app_id,
    };
    let key =
        EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|error| ReporterError {
            attempts: 0,
            http_status: None,
            message: format!("invalid GitHub App private key: {error}"),
        })?;
    encode(&Header::new(Algorithm::RS256), &claims, &key).map_err(|error| ReporterError {
        attempts: 0,
        http_status: None,
        message: format!("could not create GitHub App JWT: {error}"),
    })
}

pub fn markdown_comment(result: &HarnessResult) -> String {
    let icon = match result.verdict {
        crate::model::Verdict::Passed => "✅",
        crate::model::Verdict::Warning => "⚠️",
        crate::model::Verdict::Failed => "❌",
        crate::model::Verdict::Inconclusive => "❔",
        crate::model::Verdict::InfrastructureError => "🛠️",
    };
    let findings = result.log_analysis.new_findings.len();
    let errors = if result.errors.is_empty() {
        "None".to_owned()
    } else {
        result
            .errors
            .iter()
            .map(|error| format!("- `{:?}`: {}", error.phase, error.message))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"<!-- dappnode-package-harness:{run_id} -->
### {icon} Dappnode package harness: {verdict:?}

{summary}

| Field | Value |
| --- | --- |
| Run ID | `{run_id}` |
| Package | `{dnp_name}` |
| Baseline | `{baseline}` |
| Candidate | `{candidate}` |
| Candidate reported version | `{candidate_version}` |
| Reason | `{reason:?}` |
| Duration | {duration_ms} ms |
| Cleanup | `{cleanup:?}` |
| Log analysis | `{analysis:?}` ({findings} new finding(s)) |

<details>
<summary>Analyzer summary</summary>

{analysis_summary}

</details>

<details>
<summary>Errors</summary>

{errors}

</details>
"#,
        icon = icon,
        verdict = result.verdict,
        summary = result.summary,
        run_id = result.run_id,
        dnp_name = result.package.dnp_name,
        baseline = result
            .package
            .baseline_resolved_version
            .as_deref()
            .or(result.package.baseline_requested_ref.as_deref())
            .unwrap_or("latest"),
        candidate = result.package.candidate_ref,
        candidate_version = result
            .package
            .candidate_reported_version
            .as_deref()
            .unwrap_or("unknown"),
        reason = result.reason_code,
        duration_ms = result.execution.duration_ms,
        cleanup = result.cleanup.status,
        analysis = result.log_analysis.status,
        findings = findings,
        analysis_summary = result.log_analysis.summary,
        errors = errors,
    )
}

fn transient_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500..=599)
}
