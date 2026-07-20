//! Staging, testing, and atomic swap of nginx domain configurations.
//!
//! This module implements generation-based staging:
//!
//! 1. Build a complete staging directory with all desired domain configs.
//! 2. Generate a temporary nginx test config that includes the staging dir.
//! 3. Run `nginx -t` against the test config to validate syntax.
//! 4. On success: atomically swap staging into live via rename operations.
//! 5. On failure: discard staging and preserve the current live config.
//!
//! The atomic swap sequence:
//! ```text
//! mv live -> prev
//! mv staging -> live
//! nginx -s reload
//! ```
//! If the reload fails, we can roll back by reversing the swap.

use crate::config::NginxSection;
use crate::differ::DiffResult;
use crate::domain::DomainInfo;
use crate::renderer::{self, RenderPaths};
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Global generation counter for unique staging directory naming.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// Outcome of a staging attempt.
#[derive(Debug)]
pub enum StageOutcome {
    /// Staging, testing, swap, and reload all succeeded.
    Success {
        /// Generation number of this deployment.
        generation: u64,
        /// Number of domain configs deployed.
        domain_count: usize,
    },
    /// No changes were needed; no action taken.
    NoChanges,
    /// Nginx config test failed; live config is unchanged.
    TestFailed {
        /// The stderr output from `nginx -t`.
        error: String,
    },
}

/// Build staging dir, test config, and atomically swap if valid.
///
/// This is the main entry point for deploying configuration changes.
///
/// # Arguments
/// - `diff` - The computed diff describing what needs to change
/// - `existing_configs` - Map of domain name -> current config content for
///   unchanged domains (carried forward to staging)
/// - `nginx` - Nginx configuration paths
///
/// # Returns
/// A `StageOutcome` describing what happened.
pub async fn stage_and_swap(
    diff: &DiffResult,
    existing_configs: &HashMap<String, String>,
    nginx: &NginxSection,
) -> Result<StageOutcome> {
    if !diff.has_changes() {
        tracing::info!("no configuration changes to apply");
        return Ok(StageOutcome::NoChanges);
    }

    let generation = GENERATION.fetch_add(1, Ordering::SeqCst);
    tracing::info!(
        generation = generation,
        adds = diff.to_add.len(),
        updates = diff.to_update.len(),
        removals = diff.to_remove.len(),
        "starting staging cycle"
    );

    let render_paths = RenderPaths {
        ssl_base_dir: &nginx.ssl_base_dir,
        proxy_conf: &nginx.proxy_conf,
    };

    // Step 1: Build staging directory
    let staging_dir = &nginx.staging_dir;
    build_staging_dir(staging_dir, diff, existing_configs, &render_paths)
        .await
        .context("failed to build staging directory")?;

    // Step 2: Create temp nginx test config
    let test_conf_path = nginx
        .temp_dir
        .join(format!("nginx-agent-test-{}.conf", generation));
    create_test_config(
        &test_conf_path,
        staging_dir,
        &nginx.live_dir,
        &nginx.nginx_conf,
    )
    .await
    .context("failed to create test nginx config")?;

    // Step 3: Run nginx -t
    let test_result = run_nginx_test(&nginx.bin, &test_conf_path).await;

    // Clean up test config
    if let Err(e) = tokio::fs::remove_file(&test_conf_path).await {
        tracing::warn!(
            path = %test_conf_path.display(),
            error = %e,
            "failed to clean up test config file"
        );
    }

    match test_result {
        Ok(()) => {
            tracing::info!(generation = generation, "nginx config test passed");
        }
        Err(error_output) => {
            tracing::error!(
                generation = generation,
                error = %error_output,
                "nginx config test FAILED — discarding staging"
            );
            // Clean up staging dir
            cleanup_dir(staging_dir).await;
            return Ok(StageOutcome::TestFailed {
                error: error_output,
            });
        }
    }

    // Step 4: Atomic swap — mv live -> prev, mv staging -> live
    let live_dir = &nginx.live_dir;
    let prev_dir = &nginx.prev_dir;

    // Count configs in staging for the outcome
    let domain_count = count_conf_files(staging_dir).await;

    atomic_swap(live_dir, staging_dir, prev_dir)
        .await
        .context("failed to perform atomic swap")?;

    // Step 5: Reload nginx
    match reload_nginx(&nginx.bin).await {
        Ok(()) => {
            tracing::info!(generation = generation, "nginx reload successful");
        }
        Err(e) => {
            tracing::error!(
                generation = generation,
                error = %e,
                "nginx reload FAILED — attempting rollback"
            );
            // Attempt rollback: mv live -> staging (discard), mv prev -> live
            if let Err(rb_err) = rollback(live_dir, prev_dir).await {
                tracing::error!(
                    error = %rb_err,
                    "rollback ALSO FAILED — manual intervention required"
                );
            } else {
                tracing::info!("rollback successful — previous config restored");
                // Try to reload with rolled-back config
                if let Err(re_err) = reload_nginx(&nginx.bin).await {
                    tracing::error!(
                        error = %re_err,
                        "reload after rollback FAILED — manual intervention required"
                    );
                }
            }
            bail!("nginx reload failed after swap: {}", e);
        }
    }

    Ok(StageOutcome::Success {
        generation,
        domain_count,
    })
}

/// Build the staging directory with all kept domain configs.
///
/// Creates configs for:
/// - All domains in `to_add` and `to_update` (freshly rendered)
/// - Existing configs that are not explicitly removed or updated
/// - Domains in `to_remove` are excluded; domains deferred by
///   `max_removals_per_cycle` are preserved because they are still present in
///   `existing_configs` and absent from `to_remove`
async fn build_staging_dir(
    staging_dir: &Path,
    diff: &DiffResult,
    existing_configs: &HashMap<String, String>,
    render_paths: &RenderPaths<'_>,
) -> Result<()> {
    // Remove any leftover staging dir from a crashed previous run
    if staging_dir.exists() {
        tokio::fs::remove_dir_all(staging_dir)
            .await
            .context("failed to clean up leftover staging dir")?;
    }

    tokio::fs::create_dir_all(staging_dir)
        .await
        .context("failed to create staging directory")?;

    let removed_names: HashSet<&str> = diff.to_remove.iter().map(String::as_str).collect();
    let updated_names: HashSet<&str> = diff.to_update.iter().map(|d| d.name.as_str()).collect();

    // Carry forward every existing config unless this cycle explicitly removes
    // it or regenerates it. This also preserves removals deferred by
    // max_removals_per_cycle; those live configs have no DomainInfo in desired
    // state, so the old `unchanged`-only carry-forward path could drop them.
    let mut preserved_names: Vec<&String> = existing_configs
        .keys()
        .filter(|name| {
            !removed_names.contains(name.as_str()) && !updated_names.contains(name.as_str())
        })
        .collect();
    preserved_names.sort();
    for name in preserved_names {
        if let Some(content) = existing_configs.get(name) {
            let filename = format!("{}.conf", name);
            write_config_file(staging_dir, &filename, content).await?;
        }
    }

    // Write configs for new domains
    for domain in &diff.to_add {
        write_domain_config(staging_dir, domain, render_paths).await?;
    }

    // Write configs for updated domains
    for domain in &diff.to_update {
        write_domain_config(staging_dir, domain, render_paths).await?;
    }

    let total = count_conf_files(staging_dir).await;
    tracing::info!(
        dir = %staging_dir.display(),
        config_count = total,
        "built staging directory"
    );

    Ok(())
}

/// Render and write a single domain's nginx config to the staging directory.
async fn write_domain_config(
    staging_dir: &Path,
    domain: &DomainInfo,
    render_paths: &RenderPaths<'_>,
) -> Result<()> {
    let content = renderer::render_domain_config(domain, render_paths)?;
    let filename = domain.config_filename();
    write_config_file(staging_dir, &filename, &content).await
}

/// Write a config file atomically: write to .tmp then rename.
async fn write_config_file(dir: &Path, filename: &str, content: &str) -> Result<()> {
    let target = dir.join(filename);
    let tmp = dir.join(format!(".{}.tmp", filename));

    tokio::fs::write(&tmp, content)
        .await
        .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;

    tokio::fs::rename(&tmp, &target)
        .await
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), target.display()))?;

    Ok(())
}

/// Create a temporary nginx config file for testing that includes the staging dir.
async fn create_test_config(
    test_path: &Path,
    staging_dir: &Path,
    live_dir: &Path,
    nginx_conf: &Path,
) -> Result<()> {
    // Read the real nginx.conf
    let real_conf = tokio::fs::read_to_string(nginx_conf)
        .await
        .with_context(|| format!("failed to read nginx.conf: {}", nginx_conf.display()))?;

    // Replace: include <live_dir>/*.conf;  ->  include <staging_dir>/*.conf;
    let live_include = format!("include {}/*.conf;", live_dir.display());
    let staging_include = format!("include {}/*.conf;", staging_dir.display());

    let test_conf = if real_conf.contains(&live_include) {
        real_conf.replace(&live_include, &staging_include)
    } else {
        tracing::warn!(
            live_include = %live_include,
            "live include directive not found in nginx.conf — appending staging include"
        );
        format!(
            "{}\n# Added by nginx-domain-cli for testing\n{}\n",
            real_conf, staging_include
        )
    };

    tokio::fs::write(test_path, &test_conf)
        .await
        .with_context(|| format!("failed to write test config: {}", test_path.display()))?;

    tracing::debug!(
        test_path = %test_path.display(),
        staging_dir = %staging_dir.display(),
        "created test nginx config"
    );

    Ok(())
}

/// Run `nginx -t -c <config>` to test configuration validity.
///
/// Returns `Ok(())` if the test passes, or `Err(stderr)` if it fails.
pub async fn run_nginx_test(nginx_bin: &Path, test_conf: &Path) -> std::result::Result<(), String> {
    tracing::debug!(
        bin = %nginx_bin.display(),
        config = %test_conf.display(),
        "running nginx config test"
    );

    let output = tokio::process::Command::new(nginx_bin)
        .arg("-t")
        .arg("-c")
        .arg(test_conf)
        .output()
        .await
        .map_err(|e| format!("failed to execute nginx: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(stderr)
    }
}

/// Run `nginx -t` with the default nginx.conf.
pub async fn run_nginx_test_default(nginx_bin: &Path) -> std::result::Result<(), String> {
    tracing::debug!(
        bin = %nginx_bin.display(),
        "running nginx config test with default config"
    );

    let output = tokio::process::Command::new(nginx_bin)
        .arg("-t")
        .output()
        .await
        .map_err(|e| format!("failed to execute nginx: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        Err(stderr)
    }
}

/// Perform the atomic swap: live -> prev, staging -> live.
async fn atomic_swap(live_dir: &Path, staging_dir: &Path, prev_dir: &Path) -> Result<()> {
    // Clean up any leftover prev dir
    if prev_dir.exists() {
        tokio::fs::remove_dir_all(prev_dir)
            .await
            .context("failed to remove old prev directory")?;
    }

    // Move live -> prev (if live exists)
    if live_dir.exists() {
        tokio::fs::rename(live_dir, prev_dir)
            .await
            .with_context(|| {
                format!(
                    "failed to rename live -> prev ({} -> {})",
                    live_dir.display(),
                    prev_dir.display()
                )
            })?;
        tracing::debug!(
            from = %live_dir.display(),
            to = %prev_dir.display(),
            "moved live -> prev"
        );
    }

    // Move staging -> live
    tokio::fs::rename(staging_dir, live_dir)
        .await
        .with_context(|| {
            format!(
                "failed to rename staging -> live ({} -> {})",
                staging_dir.display(),
                live_dir.display()
            )
        })?;

    tracing::debug!(
        from = %staging_dir.display(),
        to = %live_dir.display(),
        "moved staging -> live"
    );

    Ok(())
}

/// Rollback: move live (bad) out, move prev (good) back to live.
///
/// Public so the CLI can trigger rollback on health check failure.
pub async fn rollback(live_dir: &Path, prev_dir: &Path) -> Result<()> {
    // Remove the bad live dir
    if live_dir.exists() {
        tokio::fs::remove_dir_all(live_dir)
            .await
            .context("rollback: failed to remove bad live dir")?;
    }

    // Restore prev -> live
    if prev_dir.exists() {
        tokio::fs::rename(prev_dir, live_dir)
            .await
            .context("rollback: failed to rename prev -> live")?;
        tracing::info!("rollback: restored previous config as live");
    } else {
        bail!("rollback: no prev directory available to restore");
    }

    Ok(())
}

/// Reload nginx by sending the reload signal.
pub async fn reload_nginx(nginx_bin: &Path) -> Result<()> {
    tracing::info!("sending reload signal to nginx");

    let output = tokio::process::Command::new(nginx_bin)
        .arg("-s")
        .arg("reload")
        .output()
        .await
        .context("failed to execute nginx reload")?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nginx reload failed: {}", stderr);
    }
}

/// Count .conf files in a directory.
async fn count_conf_files(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(mut entries) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".conf") {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Best-effort cleanup of a directory.
async fn cleanup_dir(dir: &Path) {
    if dir.exists() {
        if let Err(e) = tokio::fs::remove_dir_all(dir).await {
            tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "failed to clean up directory"
            );
        }
    }
}

/// Get the path where a domain's config file would live in a given directory.
pub fn domain_conf_path(dir: &Path, domain_name: &str) -> PathBuf {
    dir.join(format!("{}.conf", domain_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::DomainStatus;
    use std::fs;

    #[test]
    fn test_domain_conf_path() {
        let dir = PathBuf::from("/etc/nginx/myapp-domains");
        assert_eq!(
            domain_conf_path(&dir, "example.com"),
            PathBuf::from("/etc/nginx/myapp-domains/example.com.conf")
        );
    }

    #[tokio::test]
    async fn test_build_staging_dir() {
        let staging = std::env::temp_dir().join("stager_test_staging_cli");
        let _ = fs::remove_dir_all(&staging);

        let diff = DiffResult {
            to_add: vec![DomainInfo {
                no: 1,
                name: "new.com".to_string(),
                status: DomainStatus::InUse,
                app: "test".to_string(),
            }],
            to_remove: vec!["old.com".to_string()],
            unchanged: vec![DomainInfo {
                no: 2,
                name: "keep.com".to_string(),
                status: DomainStatus::Standby,
                app: "test".to_string(),
            }],
            ..Default::default()
        };

        let mut existing = HashMap::new();
        existing.insert(
            "keep.com".to_string(),
            "# existing config content".to_string(),
        );

        let render_paths = RenderPaths {
            ssl_base_dir: std::path::Path::new("/tmp/ssl"),
            proxy_conf: std::path::Path::new("/etc/nginx/myapp-proxy.conf"),
        };
        build_staging_dir(&staging, &diff, &existing, &render_paths)
            .await
            .unwrap();

        // new.com.conf should exist (rendered)
        assert!(staging.join("new.com.conf").exists());
        // keep.com.conf should exist (carried forward)
        assert!(staging.join("keep.com.conf").exists());
        let keep_content = fs::read_to_string(staging.join("keep.com.conf")).unwrap();
        assert_eq!(keep_content, "# existing config content");
        // old.com.conf should NOT exist (removed)
        assert!(!staging.join("old.com.conf").exists());

        let _ = fs::remove_dir_all(&staging);
    }
}
