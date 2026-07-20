//! Nginx configuration template rendering for domain server blocks.
//!
//! Generates nginx config file contents for InUse and Standby domains
//! based on the project's domain management contract.
//! Each domain gets a separate `.conf` file that is included by the
//! main nginx configuration.

use crate::domain::{DomainInfo, DomainStatus};
use anyhow::{bail, Result};
use std::path::Path;

/// Paths needed to render nginx domain configs.
#[derive(Debug, Clone)]
pub struct RenderPaths<'a> {
    /// Base directory for SSL certificates (e.g. `/etc/ssl/myapp-domains`).
    pub ssl_base_dir: &'a Path,
    /// Path to shared proxy config included by InUse vhosts.
    pub proxy_conf: &'a Path,
}

/// Render the nginx configuration for a given domain.
///
/// Produces different configs depending on the domain status:
/// - **InUse**: HTTP redirect to HTTPS + SSL server block that includes
///   the shared proxy config for reverse-proxy settings.
/// - **Standby**: HTTP returns 444 (connection closed) + SSL server block
///   with TLS hardening that returns 503 (service unavailable).
///
/// # Errors
/// Returns an error if the domain status is not `InUse` or `Standby`,
/// since other statuses should not have nginx configs.
pub fn render_domain_config(domain: &DomainInfo, paths: &RenderPaths<'_>) -> Result<String> {
    match domain.status {
        DomainStatus::InUse => Ok(render_inuse(domain, paths)),
        DomainStatus::Standby => Ok(render_standby(domain, paths)),
        _ => bail!(
            "cannot render config for domain {} with status {}",
            domain.name,
            domain.status
        ),
    }
}

/// Render the nginx config for an InUse domain.
fn render_inuse(domain: &DomainInfo, paths: &RenderPaths<'_>) -> String {
    let ssl_dir = paths.ssl_base_dir.join(&domain.name);
    format!(
        r#"# Managed by domain-agent — do not edit manually
# Domain: {name} (No: {no}, Status: InUse)
server {{
    listen 80;
    server_name {name};
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {name};
    ssl_certificate     {ssl_dir}/fullchain.pem;
    ssl_certificate_key {ssl_dir}/key.pem;
    include {proxy_conf};
}}
"#,
        name = domain.name,
        no = domain.no,
        ssl_dir = ssl_dir.display(),
        proxy_conf = paths.proxy_conf.display(),
    )
}

/// Render the nginx config for a Standby domain.
fn render_standby(domain: &DomainInfo, paths: &RenderPaths<'_>) -> String {
    let ssl_dir = paths.ssl_base_dir.join(&domain.name);
    format!(
        r#"# Managed by domain-agent — do not edit manually
# Domain: {name} (No: {no}, Status: Standby)
server {{
    listen 80;
    server_name {name};
    return 444;
}}

server {{
    listen 443 ssl http2;
    server_name {name};
    ssl_certificate     {ssl_dir}/fullchain.pem;
    ssl_certificate_key {ssl_dir}/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    return 503;
}}
"#,
        name = domain.name,
        no = domain.no,
        ssl_dir = ssl_dir.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_paths() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/etc/ssl/myapp-domains"),
            PathBuf::from("/etc/nginx/myapp-proxy.conf"),
        )
    }

    #[test]
    fn test_render_inuse() {
        let (ssl, proxy) = test_paths();
        let paths = RenderPaths {
            ssl_base_dir: &ssl,
            proxy_conf: &proxy,
        };
        let domain = DomainInfo {
            no: 42,
            name: "example.com".to_string(),
            status: DomainStatus::InUse,
            app: "myapp".to_string(),
        };
        let config = render_domain_config(&domain, &paths).unwrap();

        assert!(config.contains("# Managed by domain-agent"));
        assert!(config.contains("No: 42, Status: InUse"));
        assert!(config.contains("server_name example.com;"));
        assert!(config.contains("return 301 https://$server_name$request_uri;"));
        assert!(config
            .contains("ssl_certificate     /etc/ssl/myapp-domains/example.com/fullchain.pem;"));
        assert!(config.contains("include /etc/nginx/myapp-proxy.conf;"));
        assert!(!config.contains("return 503"));
    }

    #[test]
    fn test_render_standby() {
        let (ssl, proxy) = test_paths();
        let paths = RenderPaths {
            ssl_base_dir: &ssl,
            proxy_conf: &proxy,
        };
        let domain = DomainInfo {
            no: 7,
            name: "standby.example.org".to_string(),
            status: DomainStatus::Standby,
            app: "bo".to_string(),
        };
        let config = render_domain_config(&domain, &paths).unwrap();

        assert!(config.contains("No: 7, Status: Standby"));
        assert!(config.contains("return 444;"));
        assert!(config.contains("ssl_protocols TLSv1.2 TLSv1.3;"));
        assert!(config.contains("return 503;"));
        assert!(!config.contains("myapp-proxy.conf"));
    }

    #[test]
    fn test_render_custom_paths() {
        let ssl = PathBuf::from("/opt/ssl/custom");
        let proxy = PathBuf::from("/opt/nginx/my-proxy.conf");
        let paths = RenderPaths {
            ssl_base_dir: &ssl,
            proxy_conf: &proxy,
        };
        let domain = DomainInfo {
            no: 1,
            name: "custom.io".to_string(),
            status: DomainStatus::InUse,
            app: "test".to_string(),
        };
        let config = render_domain_config(&domain, &paths).unwrap();
        assert!(config.contains("/opt/ssl/custom/custom.io/fullchain.pem"));
        assert!(config.contains("include /opt/nginx/my-proxy.conf;"));
    }

    #[test]
    fn test_render_pending_fails() {
        let (ssl, proxy) = test_paths();
        let paths = RenderPaths {
            ssl_base_dir: &ssl,
            proxy_conf: &proxy,
        };
        let domain = DomainInfo {
            no: 1,
            name: "pending.com".to_string(),
            status: DomainStatus::Pending,
            app: "test".to_string(),
        };
        assert!(render_domain_config(&domain, &paths).is_err());
    }
}
