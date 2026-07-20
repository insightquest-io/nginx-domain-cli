//! Post-reload health check for nginx.
//!
//! After a configuration reload, we perform a smoke test by sending an HTTP
//! GET request to a configurable health endpoint. This catches cases where
//! nginx accepted the config but the proxy target is misconfigured or
//! unreachable.
//!
//! The health check is optional and can be disabled in the config.

use crate::config::HealthSection;
use anyhow::{bail, Context, Result};
use std::time::Duration;

/// Result of a health check.
#[derive(Debug, Clone)]
pub enum HealthStatus {
    /// Health check passed (HTTP 2xx).
    Healthy,
    /// Health check failed with details.
    Unhealthy(String),
    /// Health check is disabled in configuration.
    Disabled,
}

impl HealthStatus {
    /// Whether the health check passed or was skipped.
    pub fn is_ok(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Disabled)
    }
}

/// Perform a post-reload health check.
///
/// Sends an HTTP GET to the configured health URL and checks for a 2xx
/// response. Uses a separate reqwest client with a short timeout to avoid
/// blocking.
///
/// # Arguments
/// - `config` - Health check configuration
///
/// # Returns
/// `HealthStatus::Healthy` if the check passes, `HealthStatus::Unhealthy` with
/// a description if it fails, or `HealthStatus::Disabled` if health checks
/// are turned off.
pub async fn check_health(config: &HealthSection) -> HealthStatus {
    if !config.enabled {
        tracing::debug!("health check is disabled");
        return HealthStatus::Disabled;
    }

    tracing::info!(url = %config.url, "performing post-reload health check");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_secs))
        .connect_timeout(Duration::from_secs(5))
        // Don't follow redirects — we want to see the actual response
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("failed to build health check HTTP client: {}", e);
            tracing::error!("{}", msg);
            return HealthStatus::Unhealthy(msg);
        }
    };

    match do_health_request(&client, &config.url).await {
        Ok(()) => {
            tracing::info!(url = %config.url, "health check passed");
            HealthStatus::Healthy
        }
        Err(e) => {
            let msg = format!("{}", e);
            tracing::error!(url = %config.url, error = %msg, "health check FAILED");
            HealthStatus::Unhealthy(msg)
        }
    }
}

/// Perform the actual HTTP health check request.
async fn do_health_request(client: &reqwest::Client, url: &str) -> Result<()> {
    let response = client
        .get(url)
        .send()
        .await
        .context("health check request failed")?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable>".to_string());
        bail!("health check returned HTTP {}: {}", status.as_u16(), body);
    }
}

/// Perform a health check with retries.
///
/// Retries up to `max_retries` times with a 1-second delay between attempts.
/// This is useful because nginx may take a moment to fully reload and start
/// accepting connections on the new configuration.
pub async fn check_health_with_retries(config: &HealthSection, max_retries: u32) -> HealthStatus {
    if !config.enabled {
        return HealthStatus::Disabled;
    }

    let mut last_status = HealthStatus::Unhealthy("no attempts made".to_string());

    for attempt in 0..=max_retries {
        if attempt > 0 {
            tracing::debug!(
                attempt = attempt,
                max_retries = max_retries,
                "retrying health check"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        last_status = check_health(config).await;
        if last_status.is_ok() {
            return last_status;
        }
    }

    tracing::error!(
        retries = max_retries,
        "health check failed after all retries"
    );
    last_status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_is_ok() {
        assert!(HealthStatus::Healthy.is_ok());
        assert!(HealthStatus::Disabled.is_ok());
        assert!(!HealthStatus::Unhealthy("fail".to_string()).is_ok());
    }

    #[tokio::test]
    async fn test_disabled_health_check() {
        let config = HealthSection {
            url: "http://localhost:99999/health".to_string(),
            timeout_secs: 1,
            enabled: false,
        };
        let status = check_health(&config).await;
        assert!(matches!(status, HealthStatus::Disabled));
    }

    #[tokio::test]
    async fn test_health_check_unreachable() {
        let config = HealthSection {
            // Port 1 is almost certainly not listening
            url: "http://127.0.0.1:1/health".to_string(),
            timeout_secs: 1,
            enabled: true,
        };
        let status = check_health(&config).await;
        assert!(matches!(status, HealthStatus::Unhealthy(_)));
    }
}
