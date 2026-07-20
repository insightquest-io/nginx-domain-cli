//! nginx-domain-cli — CLI tool for managing nginx domain configurations.
//!
//! Provides commands for listing, adding, removing, and syncing domain
//! configurations with nginx. Supports generation-based staging with
//! atomic swap and rollback capabilities.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nginx_domain_cli::{
    cert_issuer, cert_validator, config, differ, domain, health, renderer, stager,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// nginx-domain-cli — manage nginx domain configurations.
#[derive(Parser, Debug)]
#[command(name = "nginx-domain-cli", version = env!("FULL_VERSION"), about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        global = true,
        default_value = "/etc/nginx-domain-cli/config.toml"
    )]
    config: PathBuf,

    /// Output JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all apps/domains or filter by app.
    List {
        /// Optional app name to filter by.
        app: Option<String>,
    },

    /// Show nginx status and config validity.
    Status,

    /// Add a domain to an app with SSL certificates.
    Add {
        /// Application name.
        app: String,
        /// Domain name to add.
        domain: String,
        /// Path to the SSL certificate (fullchain.pem).
        #[arg(long)]
        cert: PathBuf,
        /// Path to the SSL private key (key.pem).
        #[arg(long)]
        key: PathBuf,
        /// Path to the proxy config file to include.
        #[arg(long)]
        proxy_conf: PathBuf,
    },

    /// Remove a domain from an app.
    Remove {
        /// Application name.
        app: String,
        /// Domain name to remove.
        domain: String,
    },

    /// Bring a domain up: stage -> test -> swap -> reload.
    Up {
        /// Application name.
        app: String,
        /// Domain name to bring up.
        domain: String,
    },

    /// Bring a domain down: remove config -> test -> swap -> reload.
    Down {
        /// Application name.
        app: String,
        /// Domain name to bring down.
        domain: String,
    },

    /// Full reconciliation from a desired-state JSON file.
    Sync {
        /// Path to JSON file containing desired domain state.
        #[arg(long)]
        desired: PathBuf,
    },

    /// Run nginx -t to test configuration validity.
    Test,

    /// Restore configuration from previous generation.
    Rollback,

    /// Run health check against the configured health endpoint.
    Health,
}

/// Exit codes.
const EXIT_SUCCESS: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_NGINX_TEST_FAILURE: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize tracing
    init_tracing();

    let result = run(cli).await;
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {:#}", e);
            ExitCode::from(EXIT_ERROR)
        }
    }
}

async fn run(cli: Cli) -> Result<u8> {
    let json_output = cli.json;

    match cli.command {
        Commands::List { app } => cmd_list(&cli.config, app.as_deref(), json_output).await,
        Commands::Status => cmd_status(&cli.config, json_output).await,
        Commands::Add {
            app,
            domain: domain_name,
            cert,
            key,
            proxy_conf,
        } => {
            cmd_add(
                &cli.config,
                &app,
                &domain_name,
                &cert,
                &key,
                &proxy_conf,
                json_output,
            )
            .await
        }
        Commands::Remove {
            app,
            domain: domain_name,
        } => cmd_remove(&cli.config, &app, &domain_name, json_output).await,
        Commands::Up {
            app,
            domain: domain_name,
        } => cmd_up(&cli.config, &app, &domain_name, json_output).await,
        Commands::Down {
            app,
            domain: domain_name,
        } => cmd_down(&cli.config, &app, &domain_name, json_output).await,
        Commands::Sync { desired } => cmd_sync(&cli.config, &desired, json_output).await,
        Commands::Test => cmd_test(&cli.config, json_output).await,
        Commands::Rollback => cmd_rollback(&cli.config, json_output).await,
        Commands::Health => cmd_health(&cli.config, json_output).await,
    }
}

/// Initialize tracing subscriber for CLI output.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_thread_ids(false)
        .init();
}

/// Load config, returning a helpful error if the file is missing.
fn load_config(path: &Path) -> Result<config::CliConfig> {
    config::load_config(path)
        .with_context(|| format!("failed to load config from {}", path.display()))
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

/// List domains, grouped by app.
///
/// Output format:
/// ```text
/// myapp
/// 1. [live] example.com
///
/// bo
/// 1. [live] bo.example.com
/// 2. [wait] admin.example.com
/// ```
async fn cmd_list(config_path: &Path, filter_app: Option<&str>, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;
    let (_, live_configs) = differ::read_live_configs(&cfg.nginx.live_dir)?;

    // Parse live configs into DomainInfo structs by reading the header comment
    let mut domains: Vec<domain::DomainInfo> = Vec::new();
    for (name, content) in &live_configs {
        let (no, status, app) = parse_config_header(content, name);
        domains.push(domain::DomainInfo {
            no,
            name: name.clone(),
            status,
            app,
        });
    }

    // Sort by app, then by name
    domains.sort_by(|a, b| a.app.cmp(&b.app).then(a.name.cmp(&b.name)));

    // Filter by app if specified
    if let Some(filter) = filter_app {
        domains.retain(|d| d.app == filter);
    }

    if json_output {
        let json_domains: Vec<serde_json::Value> = domains
            .iter()
            .map(|d| {
                json!({
                    "app": d.app,
                    "domain": d.name,
                    "status": d.status.to_string(),
                    "no": d.no,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_domains)?);
    } else {
        // Group by app
        let mut apps: std::collections::BTreeMap<String, Vec<&domain::DomainInfo>> =
            std::collections::BTreeMap::new();
        for d in &domains {
            apps.entry(d.app.clone()).or_default().push(d);
        }

        let mut first = true;
        for (app, app_domains) in &apps {
            if !first {
                println!();
            }
            first = false;
            println!("{}", app);
            for (i, d) in app_domains.iter().enumerate() {
                println!("{}. [{}] {}", i + 1, d.status.label(), d.name);
            }
        }

        if domains.is_empty() {
            println!("(no managed domains found)");
        }
    }

    Ok(EXIT_SUCCESS)
}

/// Parse the header comment from a managed nginx config to extract metadata.
///
/// Expected format:
/// ```text
/// # Managed by domain-agent -- do not edit manually
/// # Domain: example.com (No: 42, Status: InUse)
/// ```
fn parse_config_header(content: &str, fallback_name: &str) -> (i64, domain::DomainStatus, String) {
    let mut no: i64 = 0;
    let mut status = domain::DomainStatus::InUse;
    // Default app name: derive from domain (first segment before the root domain)
    let app = derive_app_from_domain(fallback_name);

    for line in content.lines() {
        if line.starts_with("# Domain:") {
            // Parse: # Domain: example.com (No: 42, Status: InUse)
            if let Some(paren_start) = line.find('(') {
                let meta = &line[paren_start..];
                // Extract No
                if let Some(no_start) = meta.find("No: ") {
                    let rest = &meta[no_start + 4..];
                    if let Some(end) = rest.find(',') {
                        if let Ok(n) = rest[..end].trim().parse::<i64>() {
                            no = n;
                        }
                    }
                }
                // Extract Status
                if let Some(st_start) = meta.find("Status: ") {
                    let rest = &meta[st_start + 8..];
                    let status_str = rest.trim_end_matches(')').trim();
                    status = match status_str {
                        "InUse" => domain::DomainStatus::InUse,
                        "Standby" => domain::DomainStatus::Standby,
                        "Pending" => domain::DomainStatus::Pending,
                        "Provisioning" => domain::DomainStatus::Provisioning,
                        "Failure" => domain::DomainStatus::Failure,
                        _ => domain::DomainStatus::InUse,
                    };
                }
            }
        }
    }

    (no, status, app)
}

/// Derive an app name from a domain name.
///
/// Simple heuristic: if the domain has 3+ labels, use the first label.
/// Otherwise use the second-level domain.
fn derive_app_from_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[0].to_string()
    } else {
        domain.to_string()
    }
}

/// Show nginx status.
async fn cmd_status(config_path: &Path, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;

    // Check nginx binary exists
    let nginx_exists = cfg.nginx.bin.exists();

    // Run nginx -t
    let test_result = if nginx_exists {
        match stager::run_nginx_test_default(&cfg.nginx.bin).await {
            Ok(()) => Some(true),
            Err(_) => Some(false),
        }
    } else {
        None
    };

    // Count live configs
    let (live_names, _) = differ::read_live_configs(&cfg.nginx.live_dir)?;
    let live_count = live_names.len();

    // Check dirs exist
    let live_dir_exists = cfg.nginx.live_dir.exists();
    let staging_dir_exists = cfg.nginx.staging_dir.exists();
    let prev_dir_exists = cfg.nginx.prev_dir.exists();

    if json_output {
        let output = json!({
            "nginx_bin": cfg.nginx.bin.display().to_string(),
            "nginx_bin_exists": nginx_exists,
            "config_valid": test_result,
            "live_domain_count": live_count,
            "live_dir": cfg.nginx.live_dir.display().to_string(),
            "live_dir_exists": live_dir_exists,
            "staging_dir_exists": staging_dir_exists,
            "prev_dir_exists": prev_dir_exists,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "nginx binary:    {} {}",
            cfg.nginx.bin.display(),
            if nginx_exists {
                "(found)"
            } else {
                "(NOT FOUND)"
            }
        );
        println!(
            "config valid:    {}",
            match test_result {
                Some(true) => "yes",
                Some(false) => "NO",
                None => "unknown (nginx not found)",
            }
        );
        println!("live domains:    {}", live_count);
        println!(
            "live dir:        {} {}",
            cfg.nginx.live_dir.display(),
            if live_dir_exists {
                "(exists)"
            } else {
                "(missing)"
            }
        );
        println!(
            "staging dir:     {} {}",
            cfg.nginx.staging_dir.display(),
            if staging_dir_exists {
                "(exists)"
            } else {
                "(clean)"
            }
        );
        println!(
            "prev dir:        {} {}",
            cfg.nginx.prev_dir.display(),
            if prev_dir_exists {
                "(exists — rollback available)"
            } else {
                "(clean)"
            }
        );
    }

    Ok(EXIT_SUCCESS)
}

/// Add a domain.
async fn cmd_add(
    config_path: &Path,
    app: &str,
    domain_name: &str,
    cert_path: &Path,
    key_path: &Path,
    proxy_conf_path: &Path,
    json_output: bool,
) -> Result<u8> {
    let cfg = load_config(config_path)?;

    // Validate domain name
    let normalized = domain::validate_domain_name(domain_name)?;

    // Validate cert files
    let cert_result = cert_validator::validate_cert_files(cert_path, key_path);
    if !cert_result.is_valid() {
        if let cert_validator::CertValidation::Invalid(reason) = cert_result {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "error": "certificate validation failed",
                        "reason": reason,
                    }))?
                );
            } else {
                eprintln!("error: certificate validation failed: {}", reason);
            }
            return Ok(EXIT_ERROR);
        }
    }

    // Check proxy conf exists
    if !proxy_conf_path.exists() {
        let msg = format!("proxy config not found: {}", proxy_conf_path.display());
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "error": msg }))?
            );
        } else {
            eprintln!("error: {}", msg);
        }
        return Ok(EXIT_ERROR);
    }

    // Install cert files to ssl_base_dir
    let cert_dir = cfg.nginx.ssl_base_dir.join(&normalized);
    tokio::fs::create_dir_all(&cert_dir)
        .await
        .with_context(|| format!("failed to create cert dir: {}", cert_dir.display()))?;
    tokio::fs::copy(cert_path, cert_dir.join("fullchain.pem"))
        .await
        .context("failed to copy certificate")?;
    tokio::fs::copy(key_path, cert_dir.join("key.pem"))
        .await
        .context("failed to copy key")?;

    // Create live dir if needed
    tokio::fs::create_dir_all(&cfg.nginx.live_dir)
        .await
        .context("failed to create live dir")?;

    // Render and write config
    let domain_info = domain::DomainInfo {
        no: 0,
        name: normalized.clone(),
        status: domain::DomainStatus::InUse,
        app: app.to_string(),
    };
    let render_paths = renderer::RenderPaths {
        ssl_base_dir: &cfg.nginx.ssl_base_dir,
        proxy_conf: proxy_conf_path,
    };
    let content = renderer::render_domain_config(&domain_info, &render_paths)?;
    let conf_path = cfg.nginx.live_dir.join(domain_info.config_filename());
    tokio::fs::write(&conf_path, &content)
        .await
        .with_context(|| format!("failed to write config: {}", conf_path.display()))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": "add",
                "app": app,
                "domain": normalized,
                "config_path": conf_path.display().to_string(),
            }))?
        );
    } else {
        println!(
            "added domain {} for app {} -> {}",
            normalized,
            app,
            conf_path.display()
        );
    }

    Ok(EXIT_SUCCESS)
}

/// Remove a domain.
async fn cmd_remove(
    config_path: &Path,
    app: &str,
    domain_name: &str,
    json_output: bool,
) -> Result<u8> {
    let cfg = load_config(config_path)?;
    let normalized = domain::validate_domain_name(domain_name)?;

    let conf_path = cfg.nginx.live_dir.join(format!("{}.conf", normalized));
    if !conf_path.exists() {
        let msg = format!("config not found for domain {}", normalized);
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "error": msg }))?
            );
        } else {
            eprintln!("error: {}", msg);
        }
        return Ok(EXIT_ERROR);
    }

    tokio::fs::remove_file(&conf_path)
        .await
        .with_context(|| format!("failed to remove config: {}", conf_path.display()))?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": "remove",
                "app": app,
                "domain": normalized,
            }))?
        );
    } else {
        println!("removed config for domain {} (app: {})", normalized, app);
    }

    Ok(EXIT_SUCCESS)
}

/// Bring a domain up: stage -> test -> swap -> reload.
async fn cmd_up(config_path: &Path, app: &str, domain_name: &str, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;
    let normalized = domain::validate_domain_name(domain_name)?;

    // Verify cert exists
    let cert_result = cert_validator::validate_certs(&cfg.nginx.ssl_base_dir, &normalized);
    if !cert_result.is_valid() {
        if let cert_validator::CertValidation::Invalid(reason) = cert_result {
            let msg = format!("cannot bring up {}: {}", normalized, reason);
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "error": msg }))?
                );
            } else {
                eprintln!("error: {}", msg);
            }
            return Ok(EXIT_ERROR);
        }
    }

    // Read current live configs
    let (live_names, live_configs) = differ::read_live_configs(&cfg.nginx.live_dir)?;

    // Build a domain info for this domain
    let domain_info = domain::DomainInfo {
        no: 0,
        name: normalized.clone(),
        status: domain::DomainStatus::InUse,
        app: app.to_string(),
    };

    // Create a diff with this domain added
    let mut to_add = vec![domain_info.clone()];
    let mut unchanged = Vec::new();

    // Keep existing domains unchanged
    for name in &live_names {
        if name != &normalized {
            if let Some(content) = live_configs.get(name) {
                let (no, status, existing_app) = parse_config_header(content, name);
                unchanged.push(domain::DomainInfo {
                    no,
                    name: name.clone(),
                    status,
                    app: existing_app,
                });
            }
        }
    }

    // If domain already exists in live, treat as update
    if live_names.contains(&normalized) {
        to_add.clear();
    }

    let diff = differ::DiffResult {
        to_add,
        to_update: if live_names.contains(&normalized) {
            vec![domain_info]
        } else {
            vec![]
        },
        unchanged,
        ..Default::default()
    };

    match stager::stage_and_swap(&diff, &live_configs, &cfg.nginx).await? {
        stager::StageOutcome::Success {
            generation,
            domain_count,
        } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "up",
                        "app": app,
                        "domain": normalized,
                        "generation": generation,
                        "domain_count": domain_count,
                    }))?
                );
            } else {
                println!(
                    "domain {} is up (gen={}, total={})",
                    normalized, generation, domain_count
                );
            }
            Ok(EXIT_SUCCESS)
        }
        stager::StageOutcome::NoChanges => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "up",
                        "domain": normalized,
                        "status": "no_changes",
                    }))?
                );
            } else {
                println!("domain {} — no changes needed", normalized);
            }
            Ok(EXIT_SUCCESS)
        }
        stager::StageOutcome::TestFailed { error } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "up",
                        "domain": normalized,
                        "status": "test_failed",
                        "error": error,
                    }))?
                );
            } else {
                eprintln!("nginx config test failed:\n{}", error);
            }
            Ok(EXIT_NGINX_TEST_FAILURE)
        }
    }
}

/// Bring a domain down: remove config -> test -> swap -> reload.
async fn cmd_down(
    config_path: &Path,
    app: &str,
    domain_name: &str,
    json_output: bool,
) -> Result<u8> {
    let cfg = load_config(config_path)?;
    let normalized = domain::validate_domain_name(domain_name)?;

    // Read current live configs
    let (live_names, live_configs) = differ::read_live_configs(&cfg.nginx.live_dir)?;

    if !live_names.contains(&normalized) {
        let msg = format!("domain {} is not currently live", normalized);
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "error": msg }))?
            );
        } else {
            eprintln!("error: {}", msg);
        }
        return Ok(EXIT_ERROR);
    }

    // Build diff with this domain removed
    let mut unchanged = Vec::new();
    for name in &live_names {
        if name != &normalized {
            if let Some(content) = live_configs.get(name) {
                let (no, status, existing_app) = parse_config_header(content, name);
                unchanged.push(domain::DomainInfo {
                    no,
                    name: name.clone(),
                    status,
                    app: existing_app,
                });
            }
        }
    }

    let diff = differ::DiffResult {
        to_remove: vec![normalized.clone()],
        unchanged,
        ..Default::default()
    };

    match stager::stage_and_swap(&diff, &live_configs, &cfg.nginx).await? {
        stager::StageOutcome::Success {
            generation,
            domain_count,
        } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "down",
                        "app": app,
                        "domain": normalized,
                        "generation": generation,
                        "domain_count": domain_count,
                    }))?
                );
            } else {
                println!(
                    "domain {} is down (gen={}, remaining={})",
                    normalized, generation, domain_count
                );
            }
            Ok(EXIT_SUCCESS)
        }
        stager::StageOutcome::NoChanges => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "down",
                        "domain": normalized,
                        "status": "no_changes",
                    }))?
                );
            } else {
                println!("domain {} — no changes needed", normalized);
            }
            Ok(EXIT_SUCCESS)
        }
        stager::StageOutcome::TestFailed { error } => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "down",
                        "domain": normalized,
                        "status": "test_failed",
                        "error": error,
                    }))?
                );
            } else {
                eprintln!("nginx config test failed:\n{}", error);
            }
            Ok(EXIT_NGINX_TEST_FAILURE)
        }
    }
}

/// Full reconciliation from a desired-state JSON file.
///
/// JSON format:
/// ```json
/// [
///   { "no": 1, "name": "example.com", "status": 3, "app": "myapp" },
///   { "no": 2, "name": "bo.example.com", "status": 3, "app": "bo" }
/// ]
/// ```
async fn cmd_sync(config_path: &Path, desired_path: &Path, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;

    // Read desired state
    let desired_json = tokio::fs::read_to_string(desired_path)
        .await
        .with_context(|| {
            format!(
                "failed to read desired state file: {}",
                desired_path.display()
            )
        })?;

    let raw_records: Vec<DesiredDomainRecord> = serde_json::from_str(&desired_json)
        .with_context(|| "failed to parse desired state JSON")?;

    // Convert to DomainInfo
    let mut desired: Vec<domain::DomainInfo> = Vec::new();
    for record in &raw_records {
        let status = match domain::DomainStatus::from_i32(record.status) {
            Some(s) => s,
            None => {
                tracing::warn!(no = record.no, name = %record.name, status = record.status,
                    "skipping domain with unknown status");
                continue;
            }
        };
        if !status.should_have_config() {
            continue;
        }
        match domain::DomainInfo::new(record.no, &record.name, status, &record.app) {
            Ok(info) => desired.push(info),
            Err(e) => {
                tracing::warn!(no = record.no, name = %record.name, error = %e,
                    "skipping domain with invalid name");
            }
        }
    }

    // ★ STEP 1 — ensure certs (no-op if [acme] / [dns_provider] unset).
    // An empty desired set is a valid reconciliation target. Upstream callers
    // own fetch-failure handling and skip invoking sync when desired state is
    // unavailable.
    // Per-domain failures are reported in `ensure_report.failed`; only fatal
    // setup issues (missing acme.sh, CF token, account register) bubble up.
    let mut ensure_report = if let (Some(acme), Some(dns)) = (&cfg.acme, &cfg.dns_provider) {
        cert_issuer::ensure_certs_for_desired(&desired, &cfg.nginx, acme, dns).await?
    } else {
        cert_issuer::EnsureCertReport::default()
    };
    // Capture the cert-only-reload signal before merge_acme drains the
    // issued/renewed vecs into `diff`.
    let material_change = ensure_report.had_material_change();
    let (issued_count, renewed_count) = (ensure_report.issued.len(), ensure_report.renewed.len());

    // ★ STEP 2 — Read live state and compute diff.
    // NOTE: `desired` is NOT mutated for ACME failures. cert_validator inside
    // compute_diff provides defense-in-depth (failed → skipped_no_cert with
    // existing live config preserved as `unchanged`).
    let (live_names, live_configs) = differ::read_live_configs(&cfg.nginx.live_dir)?;
    let mut diff = differ::compute_diff(
        &desired,
        &live_names,
        &live_configs,
        &cfg.nginx,
        &cfg.safety,
    )?;

    // ★ STEP 3 — Move ACME outcomes into diff for reporting (no clones).
    diff.merge_acme(&mut ensure_report);

    // Human-readable preamble
    if !json_output {
        if !diff.to_add.is_empty() {
            println!(
                "adding: {}",
                diff.to_add
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !diff.to_update.is_empty() {
            println!(
                "updating: {}",
                diff.to_update
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !diff.to_remove.is_empty() {
            println!("removing: {}", diff.to_remove.join(", "));
        }
        if !diff.deferred_removals.is_empty() {
            println!("deferred removals: {}", diff.deferred_removals.join(", "));
        }
        if !diff.skipped_no_cert.is_empty() {
            println!(
                "skipped (no cert): {}",
                diff.skipped_no_cert
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if !diff.issued.is_empty() {
            println!("issued: {}", diff.issued.join(", "));
        }
        if !diff.renewed.is_empty() {
            println!("renewed: {}", diff.renewed.join(", "));
        }
        if !diff.acme_failed.is_empty() {
            for f in &diff.acme_failed {
                println!("acme failed [{}]: {}", f.name, f.reason);
            }
        }
    }

    // ★ STEP 4 — Stage & swap (skipped when no config changes).
    let stage_outcome = if diff.has_changes() {
        stager::stage_and_swap(&diff, &live_configs, &cfg.nginx).await?
    } else {
        stager::StageOutcome::NoChanges
    };

    // ★ STEP 5 — Reload decision matrix.
    //
    // High-level decisions only — see STEP 6 below for the full
    // status × exit-code cross-product (which adds reload-result branches
    // and a defensive arm for unreachable combinations).
    //
    //   diff.has_changes | stage_outcome  | material_change | action
    //   ─────────────────┼────────────────┼─────────────────┼──────────────────────
    //         true       | Success        |       *         | (already reloaded)
    //         true       | TestFailed     |       true      | explicit reload
    //         true       | TestFailed     |       false     | no reload
    //         false      | NoChanges      |       true      | explicit reload
    //         false      | NoChanges      |       false     | no-op
    let needs_cert_reload = match &stage_outcome {
        stager::StageOutcome::Success { .. } => false,
        stager::StageOutcome::NoChanges => material_change,
        stager::StageOutcome::TestFailed { .. } => material_change,
    };

    let cert_reload_result = if needs_cert_reload {
        tracing::info!(
            issued = issued_count,
            renewed = renewed_count,
            stage_outcome = ?stage_outcome,
            "cert material changed — forcing nginx reload"
        );
        Some(stager::reload_nginx(&cfg.nginx.bin).await)
    } else {
        None
    };

    // Invariant — needs_cert_reload and cert_reload_result.is_some() are
    // derived from the same source. If a future refactor decouples them
    // (e.g. adding a config flag that gates the reload), the defensive arm
    // in STEP 6 would silently flag a healthy run as `cert_reload_failed`.
    // Catch the drift here, where the cause is local and obvious.
    debug_assert_eq!(
        needs_cert_reload,
        cert_reload_result.is_some(),
        "needs_cert_reload must align with cert_reload_result.is_some() — \
         see STEP 6 reload matrix"
    );

    // ★ STEP 6 — Status + exit code matrix (see SPEC §2.5.1).
    let (status_str, exit_code, cert_reload_err) =
        match (&stage_outcome, material_change, &cert_reload_result) {
            (stager::StageOutcome::Success { .. }, _, _) => ("success", EXIT_SUCCESS, None),
            (stager::StageOutcome::NoChanges, false, _) => ("no_changes", EXIT_SUCCESS, None),
            (stager::StageOutcome::NoChanges, true, Some(Ok(_))) => {
                ("cert_only_reloaded", EXIT_SUCCESS, None)
            }
            (stager::StageOutcome::NoChanges, true, Some(Err(e))) => {
                ("cert_reload_failed", EXIT_ERROR, Some(format!("{:#}", e)))
            }
            (stager::StageOutcome::TestFailed { .. }, false, _) => {
                ("test_failed", EXIT_NGINX_TEST_FAILURE, None)
            }
            (stager::StageOutcome::TestFailed { .. }, true, Some(Ok(_))) => {
                ("test_failed_cert_reloaded", EXIT_NGINX_TEST_FAILURE, None)
            }
            (stager::StageOutcome::TestFailed { .. }, true, Some(Err(e))) => (
                "test_failed_cert_reload_failed",
                EXIT_NGINX_TEST_FAILURE,
                Some(format!("{:#}", e)),
            ),
            // Defensive: needs_cert_reload aligns with material_change, so the
            // (NoChanges|TestFailed, true, None) cells above always have Some(_).
            // This is kept so the match is exhaustive without a panicking arm.
            (stager::StageOutcome::NoChanges, true, None)
            | (stager::StageOutcome::TestFailed { .. }, true, None) => (
                "cert_reload_failed",
                EXIT_ERROR,
                Some(
                    "internal: needs_cert_reload was true but reload was not attempted".to_string(),
                ),
            ),
        };

    let stage_error = match &stage_outcome {
        stager::StageOutcome::TestFailed { error } => Some(error.clone()),
        _ => None,
    };
    let (gen_opt, dom_count_opt) = match &stage_outcome {
        stager::StageOutcome::Success {
            generation,
            domain_count,
        } => (Some(*generation), Some(*domain_count)),
        _ => (None, None),
    };

    if json_output {
        let mut payload = json!({
            "action": "sync",
            "status": status_str,
            "added": diff.to_add.len(),
            "updated": diff.to_update.len(),
            "removed": diff.to_remove.len(),
            "deferred_removals": diff.deferred_removals.len(),
            "skipped_no_cert": diff.skipped_no_cert.len(),
            "issued": diff.issued,
            "renewed": diff.renewed,
            "acme_failed": diff.acme_failed.iter().map(|f| json!({
                "name": f.name, "reason": f.reason,
            })).collect::<Vec<_>>(),
        });
        if let serde_json::Value::Object(map) = &mut payload {
            if let Some(g) = gen_opt {
                map.insert("generation".to_string(), json!(g));
            }
            if let Some(c) = dom_count_opt {
                map.insert("domain_count".to_string(), json!(c));
            }
            if let Some(e) = &stage_error {
                map.insert("error".to_string(), json!(e));
            }
            if let Some(e) = &cert_reload_err {
                map.insert("cert_reload_error".to_string(), json!(e));
            }
        }
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        match (gen_opt, dom_count_opt) {
            (Some(g), Some(c)) => println!("sync {} (gen={}, total={})", status_str, g, c),
            _ => println!("sync {}", status_str),
        }
        if let Some(e) = &stage_error {
            eprintln!("nginx config test failed:\n{}", e);
        }
        if let Some(e) = &cert_reload_err {
            eprintln!("nginx reload after cert renewal failed:\n{}", e);
        }
    }

    Ok(exit_code)
}

/// JSON record for desired domain state (sync command input).
#[derive(Debug, serde::Deserialize)]
struct DesiredDomainRecord {
    no: i64,
    name: String,
    status: i32,
    #[serde(default)]
    app: String,
}

/// Run nginx -t.
async fn cmd_test(config_path: &Path, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;

    match stager::run_nginx_test_default(&cfg.nginx.bin).await {
        Ok(()) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "test",
                        "status": "ok",
                    }))?
                );
            } else {
                println!("nginx config test passed");
            }
            Ok(EXIT_SUCCESS)
        }
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "test",
                        "status": "failed",
                        "error": error,
                    }))?
                );
            } else {
                eprintln!("nginx config test failed:\n{}", error);
            }
            Ok(EXIT_NGINX_TEST_FAILURE)
        }
    }
}

/// Rollback to previous generation.
async fn cmd_rollback(config_path: &Path, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;

    if !cfg.nginx.prev_dir.exists() {
        let msg = "no previous generation available for rollback";
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "error": msg }))?
            );
        } else {
            eprintln!("error: {}", msg);
        }
        return Ok(EXIT_ERROR);
    }

    stager::rollback(&cfg.nginx.live_dir, &cfg.nginx.prev_dir).await?;

    // Reload nginx with restored config
    stager::reload_nginx(&cfg.nginx.bin).await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "action": "rollback",
                "status": "success",
            }))?
        );
    } else {
        println!("rollback complete — previous config restored and nginx reloaded");
    }

    Ok(EXIT_SUCCESS)
}

/// Run health check.
async fn cmd_health(config_path: &Path, json_output: bool) -> Result<u8> {
    let cfg = load_config(config_path)?;

    let status = health::check_health(&cfg.health).await;

    match &status {
        health::HealthStatus::Healthy => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "health",
                        "status": "healthy",
                        "url": cfg.health.url,
                    }))?
                );
            } else {
                println!("health check passed: {}", cfg.health.url);
            }
            Ok(EXIT_SUCCESS)
        }
        health::HealthStatus::Disabled => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "health",
                        "status": "disabled",
                    }))?
                );
            } else {
                println!("health check is disabled");
            }
            Ok(EXIT_SUCCESS)
        }
        health::HealthStatus::Unhealthy(reason) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "health",
                        "status": "unhealthy",
                        "reason": reason,
                        "url": cfg.health.url,
                    }))?
                );
            } else {
                eprintln!("health check FAILED: {}", reason);
            }
            Ok(EXIT_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_accepts_config_after_subcommand() {
        let cli = Cli::try_parse_from([
            "nginx-domain-cli",
            "sync",
            "--config",
            "/tmp/nginx-domain-cli/config.toml",
            "--desired",
            "/tmp/nginx-domain-cli/desired.json",
            "--json",
        ])
        .expect("sync should accept --config after the subcommand");

        assert_eq!(
            cli.config,
            PathBuf::from("/tmp/nginx-domain-cli/config.toml")
        );
        assert!(cli.json);
        match cli.command {
            Commands::Sync { desired } => {
                assert_eq!(desired, PathBuf::from("/tmp/nginx-domain-cli/desired.json"));
            }
            other => panic!("expected sync command, got {other:?}"),
        }
    }
}
