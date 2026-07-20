//! Domain name validation and the core `DomainInfo` type.
//!
//! This module defines the data model for domains along with strict validation
//! logic for domain names to prevent path-traversal attacks and other injection
//! issues.

use anyhow::{bail, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

/// Compiled regex for valid domain names.
///
/// Matches fully qualified domain names like `example.com`, `sub.domain.co.uk`,
/// etc. Rejects IP addresses, single-label names, and names with invalid chars.
static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap()
});

/// Domain status for nginx configuration.
///
/// Only `InUse` and `Standby` domains receive nginx configurations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DomainStatus {
    Pending = 0,
    Provisioning = 1,
    Standby = 2,
    InUse = 3,
    Failure = 4,
}

impl DomainStatus {
    /// Convert an integer status code to a `DomainStatus`.
    ///
    /// Returns `None` for unknown status codes.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Pending),
            1 => Some(Self::Provisioning),
            2 => Some(Self::Standby),
            3 => Some(Self::InUse),
            4 => Some(Self::Failure),
            _ => None,
        }
    }

    /// Whether this status should have an nginx config deployed.
    pub fn should_have_config(&self) -> bool {
        matches!(self, Self::InUse | Self::Standby)
    }

    /// Short label for display (e.g. in the `list` command output).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pend",
            Self::Provisioning => "prov",
            Self::Standby => "wait",
            Self::InUse => "live",
            Self::Failure => "fail",
        }
    }
}

impl fmt::Display for DomainStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::Provisioning => write!(f, "Provisioning"),
            Self::Standby => write!(f, "Standby"),
            Self::InUse => write!(f, "InUse"),
            Self::Failure => write!(f, "Failure"),
        }
    }
}

/// Information about a single domain, combining metadata with derived state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainInfo {
    /// Unique domain number.
    pub no: i64,

    /// Validated, normalized (lowercase) domain name.
    pub name: String,

    /// Current domain status.
    pub status: DomainStatus,

    /// Application this domain belongs to.
    #[serde(default)]
    pub app: String,
}

impl DomainInfo {
    /// Create a new `DomainInfo` after validating and normalizing the domain name.
    ///
    /// Returns an error if the domain name is invalid.
    pub fn new(no: i64, name: &str, status: DomainStatus, app: &str) -> Result<Self> {
        let normalized = validate_domain_name(name)?;
        Ok(Self {
            no,
            name: normalized,
            status,
            app: app.to_string(),
        })
    }

    /// The config filename for this domain (e.g. `example.com.conf`).
    pub fn config_filename(&self) -> String {
        format!("{}.conf", self.name)
    }
}

impl fmt::Display for DomainInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}(no={}, status={}, app={})",
            self.name, self.no, self.status, self.app
        )
    }
}

/// Validate and normalize a domain name.
///
/// Checks:
/// 1. No null bytes
/// 2. No path separators (`/` or `\`)
/// 3. Not empty, not too long (max 253 chars per RFC 1035)
/// 4. Matches the domain name regex
/// 5. Normalizes to lowercase
///
/// Returns the normalized domain name on success.
pub fn validate_domain_name(name: &str) -> Result<String> {
    // Reject null bytes — could cause C-string truncation in nginx
    if name.contains('\0') {
        bail!("domain name contains null byte: {:?}", name);
    }

    // Reject path separators — prevents path traversal in file operations
    if name.contains('/') || name.contains('\\') {
        bail!("domain name contains path separator: {:?}", name);
    }

    // Length check (RFC 1035: max 253 characters for a FQDN)
    if name.is_empty() {
        bail!("domain name is empty");
    }
    if name.len() > 253 {
        bail!("domain name exceeds 253 characters: {} chars", name.len());
    }

    // Normalize to lowercase before regex check
    let normalized = name.to_ascii_lowercase();

    // Regex validation
    if !DOMAIN_REGEX.is_match(&normalized) {
        bail!("domain name does not match valid pattern: {:?}", normalized);
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_domains() {
        assert!(validate_domain_name("example.com").is_ok());
        assert!(validate_domain_name("sub.domain.co.uk").is_ok());
        assert!(validate_domain_name("MY-DOMAIN.COM").is_ok());
        // Should normalize to lowercase
        assert_eq!(
            validate_domain_name("MY-DOMAIN.COM").unwrap(),
            "my-domain.com"
        );
    }

    #[test]
    fn test_invalid_domains() {
        assert!(validate_domain_name("").is_err());
        assert!(validate_domain_name("localhost").is_err());
        assert!(validate_domain_name("../etc/passwd").is_err());
        assert!(validate_domain_name("domain\0.com").is_err());
        assert!(validate_domain_name("domain/.com").is_err());
        assert!(validate_domain_name("domain\\.com").is_err());
        assert!(validate_domain_name("-invalid.com").is_err());
        assert!(validate_domain_name("invalid-.com").is_err());
    }

    #[test]
    fn test_domain_status_conversion() {
        assert_eq!(DomainStatus::from_i32(0), Some(DomainStatus::Pending));
        assert_eq!(DomainStatus::from_i32(3), Some(DomainStatus::InUse));
        assert_eq!(DomainStatus::from_i32(99), None);
    }

    #[test]
    fn test_should_have_config() {
        assert!(!DomainStatus::Pending.should_have_config());
        assert!(!DomainStatus::Provisioning.should_have_config());
        assert!(DomainStatus::Standby.should_have_config());
        assert!(DomainStatus::InUse.should_have_config());
        assert!(!DomainStatus::Failure.should_have_config());
    }
}
