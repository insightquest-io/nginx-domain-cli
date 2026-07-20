//! TLS certificate validation for domain configurations.
//!
//! Before deploying an nginx config for a domain, we must verify that the
//! required SSL certificate files exist and contain valid PEM data. This
//! module provides that validation without performing full X.509 parsing --
//! we check file existence and PEM header/footer markers, which is sufficient
//! for catching common deployment issues (missing files, empty files,
//! corrupted uploads).

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// Result of validating certificates for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertValidation {
    /// Both fullchain.pem and key.pem exist and contain valid PEM data.
    Valid,
    /// One or both certificate files are missing or invalid.
    Invalid(String),
}

impl CertValidation {
    /// Whether the certificate validation passed.
    pub fn is_valid(&self) -> bool {
        matches!(self, CertValidation::Valid)
    }
}

/// Validate that SSL certificate files exist and are well-formed for a domain.
///
/// Checks:
/// 1. `{ssl_base_dir}/{domain_name}/fullchain.pem` exists and is a file
/// 2. `{ssl_base_dir}/{domain_name}/key.pem` exists and is a file
/// 3. Both files contain valid PEM headers/footers
///
/// # Arguments
/// - `ssl_base_dir` - Base directory for SSL certificates (e.g. `/etc/ssl/myapp-domains`)
/// - `domain_name` - The validated, normalized domain name
///
/// # Returns
/// `CertValidation::Valid` if both files pass, or `CertValidation::Invalid` with
/// a description of what went wrong.
pub fn validate_certs(ssl_base_dir: &Path, domain_name: &str) -> CertValidation {
    let cert_dir = ssl_base_dir.join(domain_name);
    let fullchain_path = cert_dir.join("fullchain.pem");
    let key_path = cert_dir.join("key.pem");

    // Check fullchain.pem
    if let Err(e) = validate_pem_file(&fullchain_path, PemType::Certificate) {
        return CertValidation::Invalid(format!("fullchain.pem: {}", e));
    }

    // Check key.pem
    if let Err(e) = validate_pem_file(&key_path, PemType::PrivateKey) {
        return CertValidation::Invalid(format!("key.pem: {}", e));
    }

    tracing::debug!(
        domain = %domain_name,
        fullchain = %fullchain_path.display(),
        key = %key_path.display(),
        "certificate files validated"
    );

    CertValidation::Valid
}

/// Validate cert and key files at explicit paths (for the `add` command).
///
/// Unlike `validate_certs`, this checks specific file paths rather than
/// deriving them from a base directory + domain name.
pub fn validate_cert_files(cert_path: &Path, key_path: &Path) -> CertValidation {
    if let Err(e) = validate_pem_file(&cert_path.to_path_buf(), PemType::Certificate) {
        return CertValidation::Invalid(format!("cert: {}", e));
    }

    if let Err(e) = validate_pem_file(&key_path.to_path_buf(), PemType::PrivateKey) {
        return CertValidation::Invalid(format!("key: {}", e));
    }

    CertValidation::Valid
}

/// Type of PEM file we expect.
#[derive(Debug, Clone, Copy)]
enum PemType {
    Certificate,
    PrivateKey,
}

impl PemType {
    /// Valid PEM header markers for this type.
    fn valid_headers(&self) -> &[&str] {
        match self {
            PemType::Certificate => &["-----BEGIN CERTIFICATE-----"],
            PemType::PrivateKey => &[
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----",
            ],
        }
    }

    /// Valid PEM footer markers for this type.
    fn valid_footers(&self) -> &[&str] {
        match self {
            PemType::Certificate => &["-----END CERTIFICATE-----"],
            PemType::PrivateKey => &[
                "-----END PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
                "-----END EC PRIVATE KEY-----",
            ],
        }
    }

    fn label(&self) -> &str {
        match self {
            PemType::Certificate => "certificate",
            PemType::PrivateKey => "private key",
        }
    }
}

/// Validate a single PEM file: existence, non-empty, correct headers/footers.
fn validate_pem_file(path: &PathBuf, pem_type: PemType) -> Result<()> {
    // Check existence
    if !path.exists() {
        bail!("file does not exist: {}", path.display());
    }

    // Check it's a file (not a directory or symlink to directory)
    if !path.is_file() {
        bail!("path is not a regular file: {}", path.display());
    }

    // Read contents
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;

    let trimmed = contents.trim();

    // Check non-empty
    if trimmed.is_empty() {
        bail!("file is empty: {}", path.display());
    }

    // Check PEM header
    let has_header = pem_type.valid_headers().iter().any(|h| trimmed.contains(h));
    if !has_header {
        bail!(
            "file does not contain a valid {} PEM header: {}",
            pem_type.label(),
            path.display()
        );
    }

    // Check PEM footer
    let has_footer = pem_type.valid_footers().iter().any(|f| trimmed.contains(f));
    if !has_footer {
        bail!(
            "file does not contain a valid {} PEM footer: {}",
            pem_type.label(),
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_cert_dir(base: &Path, domain: &str, fullchain: &str, key: &str) {
        let dir = base.join(domain);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("fullchain.pem"), fullchain).unwrap();
        fs::write(dir.join("key.pem"), key).unwrap();
    }

    #[test]
    fn test_valid_certs() {
        let tmp = std::env::temp_dir().join("cert_test_valid_cli");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let fullchain = "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN PRIVATE KEY-----\nMIIEvxxx\n-----END PRIVATE KEY-----\n";
        setup_cert_dir(&tmp, "example.com", fullchain, key);

        let result = validate_certs(&tmp, "example.com");
        assert_eq!(result, CertValidation::Valid);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_missing_fullchain() {
        let tmp = std::env::temp_dir().join("cert_test_missing_cli");
        let _ = fs::remove_dir_all(&tmp);
        let dir = tmp.join("missing.com");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("key.pem"),
            "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let result = validate_certs(&tmp, "missing.com");
        assert!(matches!(result, CertValidation::Invalid(_)));
        if let CertValidation::Invalid(msg) = &result {
            assert!(msg.contains("fullchain.pem"));
            assert!(msg.contains("does not exist"));
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_empty_key() {
        let tmp = std::env::temp_dir().join("cert_test_empty_cli");
        let _ = fs::remove_dir_all(&tmp);

        let fullchain = "-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----\n";
        setup_cert_dir(&tmp, "empty.com", fullchain, "");

        let result = validate_certs(&tmp, "empty.com");
        assert!(matches!(result, CertValidation::Invalid(_)));
        if let CertValidation::Invalid(msg) = &result {
            assert!(msg.contains("key.pem"));
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_invalid_pem_header() {
        let tmp = std::env::temp_dir().join("cert_test_bad_header_cli");
        let _ = fs::remove_dir_all(&tmp);

        let fullchain = "not a pem file at all";
        let key = "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n";
        setup_cert_dir(&tmp, "bad.com", fullchain, key);

        let result = validate_certs(&tmp, "bad.com");
        assert!(matches!(result, CertValidation::Invalid(_)));
        if let CertValidation::Invalid(msg) = &result {
            assert!(msg.contains("PEM header"));
        }

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_rsa_key_accepted() {
        let tmp = std::env::temp_dir().join("cert_test_rsa_cli");
        let _ = fs::remove_dir_all(&tmp);

        let fullchain = "-----BEGIN CERTIFICATE-----\nxxx\n-----END CERTIFICATE-----\n";
        let key = "-----BEGIN RSA PRIVATE KEY-----\nxxx\n-----END RSA PRIVATE KEY-----\n";
        setup_cert_dir(&tmp, "rsa.com", fullchain, key);

        let result = validate_certs(&tmp, "rsa.com");
        assert_eq!(result, CertValidation::Valid);

        let _ = fs::remove_dir_all(&tmp);
    }
}
