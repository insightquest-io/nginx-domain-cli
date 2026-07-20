//! Diff engine for computing configuration changes between desired and live state.
//!
//! The differ compares the set of domains that *should* have nginx configs
//! (desired state) with the set of configs that *currently exist* on disk.
//! It produces a `DiffResult` containing domains to add, remove, and update,
//! subject to per-cycle removal caps that prevent catastrophic
//! misconfigurations.

use crate::cert_validator::{self, CertValidation};
use crate::config::{NginxSection, SafetySection};
use crate::domain::DomainInfo;
use crate::renderer::RenderPaths;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The result of diffing desired state against live state.
///
/// `Default` is derived so callers can build with `..Default::default()`,
/// keeping the `cmd_up` / `cmd_down` constructors stable as new fields are
/// added (e.g. `issued`, `renewed`, `acme_failed` for ACME reporting).
#[derive(Debug, Clone, Default)]
pub struct DiffResult {
    /// Domains that need new configs created.
    pub to_add: Vec<DomainInfo>,

    /// Domain names whose configs should be removed (not in desired state).
    pub to_remove: Vec<String>,

    /// Domain names that are not in desired state but were preserved because
    /// `max_removals_per_cycle` capped this sync cycle.
    pub deferred_removals: Vec<String>,

    /// Domains whose configs need to be regenerated (status changed, etc.).
    pub to_update: Vec<DomainInfo>,

    /// Domains that already have correct configs and need no changes.
    pub unchanged: Vec<DomainInfo>,

    /// Domains skipped because their certificates are invalid.
    pub skipped_no_cert: Vec<DomainInfo>,

    /// Domains whose certs were freshly issued by ACME this cycle.
    /// Populated by `cmd_sync` from `EnsureCertReport`. Reporting only —
    /// `has_changes()` does NOT consider this field (cert-only renewals
    /// are reloaded via a separate path; see `cmd_sync` reload matrix).
    pub issued: Vec<String>,

    /// Domains whose certs were renewed by ACME this cycle. Reporting only.
    pub renewed: Vec<String>,

    /// Per-domain ACME failures (lock contention, CF token, rate limit, …).
    /// Reporting only — failed domains keep their existing live config via
    /// the defense-in-depth path in `cert_validator` / `compute_diff`.
    pub acme_failed: Vec<AcmeFailure>,
}

/// A single ACME failure for reporting in `DiffResult.acme_failed`.
#[derive(Debug, Clone)]
pub struct AcmeFailure {
    /// Domain name that failed.
    pub name: String,
    /// Human-readable reason (acme.sh stderr fragment, lock-held, etc.).
    pub reason: String,
}

impl DiffResult {
    /// Whether there are any *config* changes to apply.
    ///
    /// Cert-only renewals (`issued` / `renewed` non-empty but no
    /// add/remove/update) are intentionally excluded — they bypass
    /// `stage_and_swap` and trigger `reload_nginx` directly.
    pub fn has_changes(&self) -> bool {
        !self.to_add.is_empty() || !self.to_remove.is_empty() || !self.to_update.is_empty()
    }

    /// Total number of config changes (excludes ACME-only events).
    pub fn change_count(&self) -> usize {
        self.to_add.len() + self.to_remove.len() + self.to_update.len()
    }

    /// Move ACME outcomes from `report` into the diff for downstream
    /// reporting. Centralizes the field-by-field copy so the two structs
    /// can evolve independently. Drains `issued` and `renewed`; `failed`
    /// is mapped from `(name, reason)` tuples to the named `AcmeFailure`
    /// shape used by `cmd_sync` JSON output.
    pub fn merge_acme(&mut self, report: &mut crate::cert_issuer::EnsureCertReport) {
        self.issued = std::mem::take(&mut report.issued);
        self.renewed = std::mem::take(&mut report.renewed);
        self.acme_failed = std::mem::take(&mut report.failed)
            .into_iter()
            .map(|(name, reason)| AcmeFailure { name, reason })
            .collect();
    }
}

/// Compute the diff between desired domains and live config files.
///
/// # Safety Guards
/// This function enforces several safety invariants:
///
/// 1. **Maximum removals per cycle**: At most `safety.max_removals_per_cycle`
///    configs can be removed in a single sync. Excess removals are deferred
///    and preserved for subsequent sync cycles.
///
/// 2. **Certificate validation**: Domains without valid certs are skipped
///    rather than having configs deployed (nginx would fail to start).
pub fn compute_diff(
    desired: &[DomainInfo],
    live_config_names: &HashSet<String>,
    live_configs: &HashMap<String, String>,
    nginx: &NginxSection,
    safety: &SafetySection,
) -> Result<DiffResult> {
    let ssl_base_dir = &nginx.ssl_base_dir;
    let render_paths = RenderPaths {
        ssl_base_dir: &nginx.ssl_base_dir,
        proxy_conf: &nginx.proxy_conf,
    };
    let desired_names: HashSet<String> = desired.iter().map(|d| d.name.clone()).collect();

    let mut to_add = Vec::new();
    let mut to_update = Vec::new();
    let mut unchanged = Vec::new();
    let mut skipped_no_cert = Vec::new();

    // Process each desired domain
    for domain in desired {
        // Validate certificates
        let cert_status = cert_validator::validate_certs(ssl_base_dir, &domain.name);
        if !cert_status.is_valid() {
            if let CertValidation::Invalid(reason) = &cert_status {
                tracing::warn!(
                    domain = %domain.name,
                    domain_no = domain.no,
                    reason = %reason,
                    "skipping domain due to invalid certificates"
                );
            }
            skipped_no_cert.push(domain.clone());
            // Preserve existing live config — a temporary cert issue must not
            // silently remove a working domain's config during atomic swap.
            if live_config_names.contains(&domain.name) {
                unchanged.push(domain.clone());
            }
            continue;
        }

        if live_config_names.contains(&domain.name) {
            // Config exists — check if content needs updating
            let new_content = crate::renderer::render_domain_config(domain, &render_paths)?;
            if let Some(existing_content) = live_configs.get(&domain.name) {
                if existing_content.trim() == new_content.trim() {
                    unchanged.push(domain.clone());
                } else {
                    tracing::info!(
                        domain = %domain.name,
                        domain_no = domain.no,
                        status = %domain.status,
                        "domain config needs update"
                    );
                    to_update.push(domain.clone());
                }
            } else {
                // Shouldn't happen (name is in set but not in map), treat as add
                to_add.push(domain.clone());
            }
        } else {
            // New domain — needs config created
            tracing::info!(
                domain = %domain.name,
                domain_no = domain.no,
                status = %domain.status,
                "new domain config to add"
            );
            to_add.push(domain.clone());
        }
    }

    // Compute removals: live configs not in desired set
    let mut to_remove: Vec<String> = live_config_names
        .iter()
        .filter(|name| !desired_names.contains(*name))
        .cloned()
        .collect();

    // Sort removals for deterministic behavior
    to_remove.sort();

    // Safety guard: cap removals per cycle
    let mut deferred_removals = Vec::new();
    if to_remove.len() > safety.max_removals_per_cycle {
        deferred_removals = to_remove.split_off(safety.max_removals_per_cycle);
        let deferred = deferred_removals.len();
        tracing::warn!(
            total_removals = to_remove.len() + deferred,
            max_allowed = safety.max_removals_per_cycle,
            deferred_to_next_cycle = deferred,
            deferred_domains = ?&deferred_removals,
            "capping removals to max_removals_per_cycle — {} domains deferred to subsequent cycles",
            deferred
        );
    }

    if !to_remove.is_empty() {
        tracing::info!(
            domains = ?to_remove,
            count = to_remove.len(),
            "domain configs to remove"
        );
    }

    Ok(DiffResult {
        to_add,
        to_remove,
        deferred_removals,
        to_update,
        unchanged,
        skipped_no_cert,
        ..Default::default()
    })
}

/// Read the set of currently live domain config files from disk.
///
/// Scans `live_dir` for `*.conf` files managed by the agent (identified by
/// the header comment). Returns both the set of domain names and a map of
/// name -> file content.
///
/// Non-`.conf` files and configs without the agent header marker are ignored.
pub fn read_live_configs(live_dir: &Path) -> Result<(HashSet<String>, HashMap<String, String>)> {
    let mut names = HashSet::new();
    let mut configs = HashMap::new();

    if !live_dir.exists() {
        tracing::debug!(dir = %live_dir.display(), "live config directory does not exist yet");
        return Ok((names, configs));
    }

    let entries = std::fs::read_dir(live_dir).map_err(|e| {
        anyhow::anyhow!(
            "failed to read live config dir {}: {}",
            live_dir.display(),
            e
        )
    })?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Only process .conf files
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.ends_with(".conf") => n.to_string(),
            _ => continue,
        };

        // Extract domain name from filename (strip .conf suffix)
        let domain_name = file_name.trim_end_matches(".conf").to_string();

        // Read file content
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to read live config file, skipping"
                );
                continue;
            }
        };

        // Only track configs managed by us (check for our header marker)
        if !content.contains("Managed by domain-agent") {
            tracing::debug!(
                path = %path.display(),
                "skipping config not managed by agent"
            );
            continue;
        }

        names.insert(domain_name.clone());
        configs.insert(domain_name, content);
    }

    tracing::debug!(
        count = names.len(),
        dir = %live_dir.display(),
        "read live domain configs"
    );

    Ok((names, configs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainStatus;
    use std::fs;
    use std::path::PathBuf;

    fn make_domain(no: i64, name: &str, status: DomainStatus) -> DomainInfo {
        DomainInfo {
            no,
            name: name.to_string(),
            status,
            app: "test".to_string(),
        }
    }

    fn setup_certs(base: &Path, domain: &str) {
        let dir = base.join(domain);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("fullchain.pem"),
            "-----BEGIN CERTIFICATE-----\nMIIBxxx\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            dir.join("key.pem"),
            "-----BEGIN PRIVATE KEY-----\nMIIEvxxx\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
    }

    fn make_nginx(ssl_dir: &Path) -> NginxSection {
        NginxSection {
            ssl_base_dir: ssl_dir.to_path_buf(),
            proxy_conf: PathBuf::from("/etc/nginx/myapp-proxy.conf"),
            ..Default::default()
        }
    }

    #[test]
    fn test_empty_live_all_adds() {
        let ssl_dir = std::env::temp_dir().join("differ_test_add_cli");
        let _ = fs::remove_dir_all(&ssl_dir);
        setup_certs(&ssl_dir, "a.com");
        setup_certs(&ssl_dir, "b.com");

        let desired = vec![
            make_domain(1, "a.com", DomainStatus::InUse),
            make_domain(2, "b.com", DomainStatus::Standby),
        ];
        let live_names = HashSet::new();
        let live_configs = HashMap::new();
        let nginx = make_nginx(&ssl_dir);
        let safety = SafetySection {
            min_expected_domains: 1,
            max_removals_per_cycle: 5,
        };

        let result = compute_diff(&desired, &live_names, &live_configs, &nginx, &safety).unwrap();
        assert_eq!(result.to_add.len(), 2);
        assert!(result.to_remove.is_empty());
        assert!(result.to_update.is_empty());

        let _ = fs::remove_dir_all(&ssl_dir);
    }

    #[test]
    fn test_empty_desired_removes_all_live_configs() {
        let ssl_dir = std::env::temp_dir().join("differ_test_empty_desired_cli");
        let _ = fs::remove_dir_all(&ssl_dir);
        fs::create_dir_all(&ssl_dir).unwrap();

        let desired = Vec::new();
        let live_names = HashSet::from(["a.com".to_string(), "b.com".to_string()]);
        let live_configs = HashMap::from([
            (
                "a.com".to_string(),
                "# Managed by domain-agent\na".to_string(),
            ),
            (
                "b.com".to_string(),
                "# Managed by domain-agent\nb".to_string(),
            ),
        ]);
        let nginx = make_nginx(&ssl_dir);
        let safety = SafetySection {
            min_expected_domains: 1,
            max_removals_per_cycle: 5,
        };

        let result = compute_diff(&desired, &live_names, &live_configs, &nginx, &safety).unwrap();
        assert!(result.to_add.is_empty());
        assert!(result.to_update.is_empty());
        assert!(result.unchanged.is_empty());
        assert!(result.deferred_removals.is_empty());
        assert_eq!(result.to_remove, vec!["a.com", "b.com"]);

        let _ = fs::remove_dir_all(&ssl_dir);
    }

    #[test]
    fn test_empty_desired_defers_removals_over_cap() {
        let ssl_dir = std::env::temp_dir().join("differ_test_empty_desired_cap_cli");
        let _ = fs::remove_dir_all(&ssl_dir);
        fs::create_dir_all(&ssl_dir).unwrap();

        let desired = Vec::new();
        let live_names = HashSet::from([
            "a.com".to_string(),
            "b.com".to_string(),
            "c.com".to_string(),
        ]);
        let live_configs = HashMap::new();
        let nginx = make_nginx(&ssl_dir);
        let safety = SafetySection {
            min_expected_domains: 1,
            max_removals_per_cycle: 2,
        };

        let result = compute_diff(&desired, &live_names, &live_configs, &nginx, &safety).unwrap();
        assert_eq!(result.to_remove, vec!["a.com", "b.com"]);
        assert_eq!(result.deferred_removals, vec!["c.com"]);

        let _ = fs::remove_dir_all(&ssl_dir);
    }

    #[test]
    fn test_min_expected_domains_does_not_abort_diff() {
        let ssl_dir = std::env::temp_dir().join("differ_test_min_cli");
        let _ = fs::remove_dir_all(&ssl_dir);
        setup_certs(&ssl_dir, "a.com");

        let desired = vec![make_domain(1, "a.com", DomainStatus::InUse)];
        let nginx = make_nginx(&ssl_dir);
        let safety = SafetySection {
            min_expected_domains: 5,
            max_removals_per_cycle: 10,
        };

        let result =
            compute_diff(&desired, &HashSet::new(), &HashMap::new(), &nginx, &safety).unwrap();
        assert_eq!(result.to_add.len(), 1);
        assert!(result.to_remove.is_empty());

        let _ = fs::remove_dir_all(&ssl_dir);
    }
}
