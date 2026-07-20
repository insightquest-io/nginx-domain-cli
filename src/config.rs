//! Configuration module for the nginx-domain-cli.
//!
//! Reads a TOML configuration file and deserializes it into strongly-typed
//! structs using serde. Every field has a sensible default so the CLI can
//! run with a minimal config file.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level CLI configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CliConfig {
    /// Nginx-related paths and commands.
    #[serde(default)]
    pub nginx: NginxSection,

    /// Safety settings.
    #[serde(default)]
    pub safety: SafetySection,

    /// Health check settings.
    #[serde(default)]
    pub health: HealthSection,

    /// ACME (Let's Encrypt) configuration. Optional — when omitted, the CLI
    /// runs in legacy mode and expects certs to be pre-materialized.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,

    /// DNS provider configuration. Required when `[acme]` is set.
    #[serde(default)]
    pub dns_provider: Option<DnsProviderConfig>,
}

/// Nginx paths and binary location.
#[derive(Debug, Clone, Deserialize)]
pub struct NginxSection {
    /// Path to the nginx binary.
    #[serde(default = "default_nginx_bin")]
    pub bin: PathBuf,

    /// Directory where live domain config files are stored.
    #[serde(default = "default_live_dir")]
    pub live_dir: PathBuf,

    /// Staging directory for candidate configs.
    #[serde(default = "default_staging_dir")]
    pub staging_dir: PathBuf,

    /// Previous-generation backup directory.
    #[serde(default = "default_prev_dir")]
    pub prev_dir: PathBuf,

    /// Base directory for SSL certificates.
    #[serde(default = "default_ssl_base_dir")]
    pub ssl_base_dir: PathBuf,

    /// Path to the shared proxy config included by each InUse domain vhost.
    #[serde(default = "default_proxy_conf")]
    pub proxy_conf: PathBuf,

    /// Path to the main nginx.conf (used as template for test configs).
    #[serde(default = "default_nginx_conf")]
    pub nginx_conf: PathBuf,

    /// Temp directory for nginx test configs.
    #[serde(default = "default_temp_dir")]
    pub temp_dir: PathBuf,
}

impl Default for NginxSection {
    fn default() -> Self {
        Self {
            bin: default_nginx_bin(),
            live_dir: default_live_dir(),
            staging_dir: default_staging_dir(),
            prev_dir: default_prev_dir(),
            ssl_base_dir: default_ssl_base_dir(),
            proxy_conf: default_proxy_conf(),
            nginx_conf: default_nginx_conf(),
            temp_dir: default_temp_dir(),
        }
    }
}

/// Safety settings to prevent catastrophic misconfigurations.
#[derive(Debug, Clone, Deserialize)]
pub struct SafetySection {
    /// Deprecated compatibility field. Empty desired state is valid for sync.
    #[serde(default = "default_min_expected_domains")]
    pub min_expected_domains: usize,

    /// Maximum number of domain config removals allowed per sync cycle.
    #[serde(default = "default_max_removals")]
    pub max_removals_per_cycle: usize,
}

impl Default for SafetySection {
    fn default() -> Self {
        Self {
            min_expected_domains: default_min_expected_domains(),
            max_removals_per_cycle: default_max_removals(),
        }
    }
}

/// ACME (Let's Encrypt) configuration for automatic certificate issuance.
///
/// When `[acme]` and `[dns_provider]` are both set in the config file, `sync`
/// will invoke `acme.sh` to issue/renew certificates for desired domains
/// before computing the diff. Both sections must be set together, or both
/// omitted (legacy mode).
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    /// Email address registered with the ACME account.
    pub email: String,

    /// ACME directory URL. Defaults to Let's Encrypt production.
    /// Used only when `staging = false`. With `staging = true`, the
    /// server arg passed to `acme.sh --server` is hard-coded to
    /// `letsencrypt_test` and this field is not read.
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,

    /// When true, use Let's Encrypt staging (avoids prod rate limits).
    #[serde(default)]
    pub staging: bool,

    /// Renew certificates this many days before they expire.
    #[serde(default = "default_renewal_window_days")]
    pub renewal_window_days: u32,

    /// Path to the `acme.sh` home directory. MUST be absolute when set.
    /// `None` resolves at runtime to `$HOME/.acme.sh`.
    #[serde(default)]
    pub acme_sh_home: Option<PathBuf>,

    /// Path to the `acme.sh` binary. Defaults to `acme.sh` (PATH lookup).
    /// Override at test time via `CERT_ISSUER_ACME_BIN` env var.
    #[serde(default = "default_acme_bin")]
    pub acme_bin: PathBuf,

    /// Directory for per-domain advisory file locks.
    #[serde(default = "default_acme_lock_dir")]
    pub lock_dir: PathBuf,
}

impl AcmeConfig {
    /// Resolve the effective `acme.sh` home directory.
    ///
    /// Returns the configured `acme_sh_home` if set, otherwise constructs
    /// `$HOME/.acme.sh` from the runtime environment. Errors when neither
    /// is available.
    pub fn resolved_acme_sh_home(&self) -> Result<PathBuf> {
        if let Some(p) = &self.acme_sh_home {
            return Ok(p.clone());
        }
        let home = std::env::var("HOME")
            .map_err(|_| anyhow!("HOME env var not set and acme.acme_sh_home not configured"))?;
        Ok(PathBuf::from(home).join(".acme.sh"))
    }
}

/// DNS provider for ACME DNS-01 challenges.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsProviderConfig {
    /// Provider identifier. Currently only `"cloudflare"` is supported.
    pub provider: String,

    /// API token. When `None`, the runtime falls back to the `CF_Token` env
    /// var at `ensure_certs_for_desired` entry. Either source is acceptable.
    pub api_token: Option<String>,
}

/// Health check settings for post-reload verification.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthSection {
    /// URL to GET after nginx reload to verify it is healthy.
    #[serde(default = "default_health_url")]
    pub url: String,

    /// Timeout in seconds for the health check request.
    #[serde(default = "default_health_timeout")]
    pub timeout_secs: u64,

    /// Whether to perform health checks after reload.
    #[serde(default = "default_health_enabled")]
    pub enabled: bool,
}

impl Default for HealthSection {
    fn default() -> Self {
        Self {
            url: default_health_url(),
            timeout_secs: default_health_timeout(),
            enabled: default_health_enabled(),
        }
    }
}

// --- Default value functions ---

fn default_nginx_bin() -> PathBuf {
    PathBuf::from("/usr/sbin/nginx")
}
fn default_live_dir() -> PathBuf {
    PathBuf::from("/etc/nginx/myapp-domains")
}
fn default_staging_dir() -> PathBuf {
    PathBuf::from("/etc/nginx/myapp-domains-staging")
}
fn default_prev_dir() -> PathBuf {
    PathBuf::from("/etc/nginx/myapp-domains-prev")
}
fn default_ssl_base_dir() -> PathBuf {
    PathBuf::from("/etc/ssl/myapp-domains")
}
fn default_proxy_conf() -> PathBuf {
    PathBuf::from("/etc/nginx/myapp-proxy.conf")
}
fn default_nginx_conf() -> PathBuf {
    PathBuf::from("/etc/nginx/nginx.conf")
}
fn default_temp_dir() -> PathBuf {
    PathBuf::from("/tmp")
}
fn default_min_expected_domains() -> usize {
    0
}
fn default_max_removals() -> usize {
    2
}
fn default_health_url() -> String {
    "http://127.0.0.1:7070/health".to_string()
}
fn default_health_timeout() -> u64 {
    5
}
fn default_health_enabled() -> bool {
    true
}
fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_renewal_window_days() -> u32 {
    30
}
fn default_acme_bin() -> PathBuf {
    PathBuf::from("acme.sh")
}
fn default_acme_lock_dir() -> PathBuf {
    PathBuf::from("/var/lock/nginx-domain-cli")
}

/// Load and parse configuration from a TOML file at the given path.
///
/// Returns an error if the file cannot be read or if the TOML is malformed.
/// Also enforces cross-field validation between `[acme]` and `[dns_provider]`:
///
/// - Both sections must be present together, or both omitted (legacy mode).
/// - Only `provider = "cloudflare"` is supported.
/// - When `acme.acme_sh_home` is set, it must be an absolute path
///   (no tilde expansion).
///
/// Note: env-var checks (e.g. `CF_Token`) are deferred to
/// `cert_issuer::ensure_certs_for_desired` so commands that don't issue
/// certs (`list`, `status`, `health`) succeed even when ACME is partially
/// configured.
pub fn load_config(path: &Path) -> Result<CliConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let config: CliConfig =
        toml::from_str(&contents).with_context(|| "failed to parse config TOML")?;
    validate_acme_config(&config)?;
    if config.safety.min_expected_domains != 0 {
        tracing::warn!(
            min_expected_domains = config.safety.min_expected_domains,
            "safety.min_expected_domains is deprecated and ignored; empty desired state is valid"
        );
    }
    tracing::info!(path = %path.display(), "loaded configuration");
    Ok(config)
}

/// Validate cross-field invariants between `[acme]` and `[dns_provider]`.
fn validate_acme_config(config: &CliConfig) -> Result<()> {
    match (&config.acme, &config.dns_provider) {
        (Some(_), None) | (None, Some(_)) => {
            bail!("[acme] and [dns_provider] must both be set or both omitted");
        }
        (Some(acme), Some(dp)) => {
            if dp.provider != "cloudflare" {
                bail!(
                    "unsupported dns provider: {} (only 'cloudflare' is implemented)",
                    dp.provider
                );
            }
            if let Some(home) = &acme.acme_sh_home {
                if !home.is_absolute() {
                    bail!(
                        "acme.acme_sh_home must be an absolute path, got: {}",
                        home.display()
                    );
                }
            }
            // lock_dir must be absolute too — relative paths resolve
            // against the cwd, so two ndc invocations from different
            // working directories would lock different files for the
            // same domain, defeating the single-writer invariant the
            // flock provides.
            if !acme.lock_dir.is_absolute() {
                bail!(
                    "acme.lock_dir must be an absolute path, got: {}",
                    acme.lock_dir.display()
                );
            }
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_config() {
        let toml_str = r#"
[nginx]
bin = "/usr/local/sbin/nginx"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.nginx.bin, PathBuf::from("/usr/local/sbin/nginx"));
        assert_eq!(config.safety.min_expected_domains, 0);
    }

    #[test]
    fn test_acme_dns_both_required() {
        let toml_str = r#"
[acme]
email = "ops@example.com"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        let err = validate_acme_config(&config).unwrap_err().to_string();
        assert!(err.contains("must both be set"), "actual: {}", err);

        let toml_str_2 = r#"
[dns_provider]
provider = "cloudflare"
"#;
        let config: CliConfig = toml::from_str(toml_str_2).unwrap();
        let err = validate_acme_config(&config).unwrap_err().to_string();
        assert!(err.contains("must both be set"), "actual: {}", err);
    }

    #[test]
    fn test_acme_unsupported_dns_provider() {
        let toml_str = r#"
[acme]
email = "ops@example.com"

[dns_provider]
provider = "route53"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        let err = validate_acme_config(&config).unwrap_err().to_string();
        assert!(err.contains("unsupported dns provider"), "actual: {}", err);
        assert!(err.contains("route53"), "actual: {}", err);
    }

    #[test]
    fn test_acme_sh_home_must_be_absolute() {
        let toml_str = r#"
[acme]
email = "ops@example.com"
acme_sh_home = "relative/path"

[dns_provider]
provider = "cloudflare"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        let err = validate_acme_config(&config).unwrap_err().to_string();
        assert!(err.contains("must be an absolute path"), "actual: {}", err);
    }

    #[test]
    fn test_acme_lock_dir_must_be_absolute() {
        let toml_str = r#"
[acme]
email = "ops@example.com"
lock_dir = "relative/locks"

[dns_provider]
provider = "cloudflare"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        let err = validate_acme_config(&config).unwrap_err().to_string();
        assert!(
            err.contains("acme.lock_dir must be an absolute path"),
            "actual: {}",
            err
        );
    }

    #[test]
    fn test_acme_legacy_mode_neither() {
        let toml_str = r#"
[nginx]
bin = "/usr/sbin/nginx"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        validate_acme_config(&config).unwrap();
        assert!(config.acme.is_none());
        assert!(config.dns_provider.is_none());
    }

    #[test]
    fn test_acme_full_config() {
        let toml_str = r#"
[acme]
email = "ops@example.com"
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
staging = true
renewal_window_days = 14
acme_sh_home = "/var/lib/nginx-domain-cli/.acme.sh"
acme_bin = "/usr/local/bin/acme.sh"
lock_dir = "/var/lock/nginx-domain-cli"

[dns_provider]
provider = "cloudflare"
api_token = "tok123"
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        validate_acme_config(&config).unwrap();
        let acme = config.acme.as_ref().unwrap();
        assert_eq!(acme.email, "ops@example.com");
        assert!(acme.staging);
        assert_eq!(acme.renewal_window_days, 14);
        assert_eq!(
            acme.acme_sh_home.as_ref().unwrap(),
            &PathBuf::from("/var/lib/nginx-domain-cli/.acme.sh")
        );
        let dp = config.dns_provider.as_ref().unwrap();
        assert_eq!(dp.provider, "cloudflare");
        assert_eq!(dp.api_token.as_deref(), Some("tok123"));
    }

    #[test]
    fn test_resolved_acme_sh_home_explicit() {
        let acme = AcmeConfig {
            email: "x@y".into(),
            directory_url: default_acme_directory_url(),
            staging: false,
            renewal_window_days: 30,
            acme_sh_home: Some(PathBuf::from("/opt/acme")),
            acme_bin: default_acme_bin(),
            lock_dir: default_acme_lock_dir(),
        };
        assert_eq!(
            acme.resolved_acme_sh_home().unwrap(),
            PathBuf::from("/opt/acme")
        );
    }

    #[test]
    fn test_resolved_acme_sh_home_from_env() {
        let acme = AcmeConfig {
            email: "x@y".into(),
            directory_url: default_acme_directory_url(),
            staging: false,
            renewal_window_days: 30,
            acme_sh_home: None,
            acme_bin: default_acme_bin(),
            lock_dir: default_acme_lock_dir(),
        };
        // SAFETY: HOME is virtually always set in test envs.
        if let Ok(home) = std::env::var("HOME") {
            assert_eq!(
                acme.resolved_acme_sh_home().unwrap(),
                PathBuf::from(home).join(".acme.sh")
            );
        }
    }

    #[test]
    fn test_full_config() {
        let toml_str = r#"
[nginx]
bin = "/usr/local/sbin/nginx"
live_dir = "/opt/nginx/domains"
staging_dir = "/opt/nginx/domains-staging"
prev_dir = "/opt/nginx/domains-prev"
ssl_base_dir = "/opt/ssl/domains"
proxy_conf = "/opt/nginx/myapp-proxy.conf"
nginx_conf = "/opt/nginx/nginx.conf"
temp_dir = "/tmp/nginx-tests"

[safety]
min_expected_domains = 5
max_removals_per_cycle = 3

[health]
url = "http://127.0.0.1:8080/healthz"
timeout_secs = 10
enabled = false
"#;
        let config: CliConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.safety.min_expected_domains, 5);
        assert_eq!(config.safety.max_removals_per_cycle, 3);
        assert!(!config.health.enabled);
    }
}
