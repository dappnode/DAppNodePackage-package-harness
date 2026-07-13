use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::{clock::Clock, model::HarnessResult};

use super::{ReportOutcome, ReporterError, ResultReporter};

pub struct WebhookResultReporter {
    client: reqwest::Client,
    url: String,
    secret: Vec<u8>,
    timeout: Duration,
    clock: Arc<dyn Clock>,
}

impl WebhookResultReporter {
    pub fn new(
        url: String,
        secret: String,
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
            url,
            secret: secret.into_bytes(),
            timeout,
            clock,
        })
    }
}

#[async_trait]
impl ResultReporter for WebhookResultReporter {
    async fn report(&self, result: &HarnessResult) -> Result<ReportOutcome, ReporterError> {
        let body = serde_json::to_vec(result).map_err(|error| ReporterError {
            attempts: 0,
            http_status: None,
            message: error.to_string(),
        })?;
        let signature = signature(&self.secret, &body)?;
        let mut last_error = "callback delivery failed".to_owned();
        let mut last_status = None;

        for attempt in 1..=3_u8 {
            let response = tokio::time::timeout(
                self.timeout,
                self.client
                    .post(&self.url)
                    .header("content-type", "application/json")
                    .header(
                        "x-dappnode-harness-signature",
                        format!("sha256={signature}"),
                    )
                    .header("x-dappnode-harness-run-id", &result.run_id)
                    .body(body.clone())
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
                    last_error = format!("callback returned HTTP {status}");
                    if !transient_status(status) {
                        return Err(ReporterError {
                            attempts: attempt,
                            http_status: last_status,
                            message: last_error,
                        });
                    }
                }
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => last_error = "callback timed out".to_owned(),
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

pub fn signature(secret: &[u8], body: &[u8]) -> Result<String, ReporterError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|error| ReporterError {
        attempts: 0,
        http_status: None,
        message: error.to_string(),
    })?;
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn transient_status(status: u16) -> bool {
    matches!(status, 408 | 429 | 500..=599)
}
