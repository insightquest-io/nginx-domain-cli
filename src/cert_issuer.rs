//! ACME certificate issuance and renewal via `acme.sh` shell-out.
//!
//! ## Approach
//!
//! This module is the **only** caller of `acme.sh` in the project. It is
//! invoked from `cmd_sync` *before* `compute_diff`, so the diff can rely on
//! freshly-issued certs without reaching back into ACME from the differ.
//!
//! For every desired domain we:
//!
//! 1. Acquire a non-blocking exclusive flock at
//!    `{acme.lock_dir}/{domain}.acme.lock`. Held → `Failed { reason }` and
//!    we move on; the next sync cycle retries naturally.
//! 2. Inspect `{ssl_base_dir}/{domain}/{fullchain,key}.pem`. Missing /
//!    incomplete / malformed / past-renewal-window → need to (re)issue.
//!    Pair mismatch (cert pubkey ≠ key pubkey) is treated as malformed.
//! 3. Issue via `acme.sh --issue --dns dns_cf -d <d> --home <h> --server <s>`
//!    (acme.sh is itself idempotent — re-runs become renewals).
//! 4. Install via `acme.sh --install-cert -d <d> --home <h>
//!    --key-file <ssl_dir>/<d>/key.pem.new
//!    --fullchain-file <ssl_dir>/<d>/fullchain.pem.new`. Then:
//!    - `set_permissions` 0644/0600 (bypasses umask filtering).
//!    - `fsync` both files.
//!    - `rename` `.new` → live (per-file atomic on the same FS).
//!    - `fsync` the parent directory (POSIX rename durability).
//!
//! Per-domain failures are isolated: they're collected into
//! `EnsureCertReport.failed` and the function continues with the next
//! domain. The desired list is *never* mutated — `cert_validator` provides
//! defense-in-depth in `compute_diff`.
//!
//! ## acme.sh boundary
//!
//! We never read from `<acme_sh_home>/<domain>/` directly. `--install-cert`
//! is the only acme.sh-supported boundary for getting cert material out of
//! its tree. We pass our own `.new` paths so acme.sh writes directly into
//! ndc-owned temp files. `--reloadcmd` is intentionally **not** used —
//! nginx reload is owned by the caller (`cmd_sync`).
//!
//! ## acme.sh cron must be disabled (deployment precondition)
//!
//! acme.sh must be **installed** with `--nocron`
//! (`curl https://get.acme.sh | sh -s ... --nocron`). This module is the
//! single renewal actor; an external cron from acme.sh would race our
//! atomic-install and trigger a double-issue. Nothing here verifies the
//! flag was passed at install time — treat as a deployment precondition
//! enforced by ops, not by code.

use crate::config::{AcmeConfig, DnsProviderConfig, NginxSection};
use crate::domain::DomainInfo;
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Per-domain outcome from `ensure_cert`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOutcome {
    /// Cert existed, valid, far from expiry. acme.sh was not invoked.
    Existing,
    /// Cert was missing/incomplete/malformed and was freshly issued.
    Issued,
    /// Cert existed but within the renewal window; reissued.
    Renewed,
    /// Lock contention, acme.sh failure, install failure, etc.
    Failed { reason: String },
}

/// Aggregated report from `ensure_certs_for_desired`.
///
/// `had_material_change()` is the signal `cmd_sync` uses to decide whether
/// a nginx reload must be forced even when the config diff is empty
/// (cert-only renewal path).
#[derive(Debug, Clone, Default)]
pub struct EnsureCertReport {
    /// Domains with a still-valid existing cert (no acme.sh invocation).
    pub existing: Vec<String>,
    /// Domains that received a freshly-issued cert.
    pub issued: Vec<String>,
    /// Domains whose cert was renewed (within window or post-expiry).
    pub renewed: Vec<String>,
    /// `(domain, reason)` pairs for per-domain failures.
    pub failed: Vec<(String, String)>,
}

impl EnsureCertReport {
    /// True when at least one cert file changed on disk this cycle.
    /// Drives the cert-only reload branch in `cmd_sync`.
    ///
    /// Only `issued` and `renewed` count — `existing` (no acme.sh call)
    /// and `failed` (no successful install) leave on-disk state unchanged
    /// and therefore do not require a reload.
    pub fn had_material_change(&self) -> bool {
        !self.issued.is_empty() || !self.renewed.is_empty()
    }
}

/// State of an existing cert pair on disk, per `inspect_existing_cert`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CertState {
    /// Neither file exists.
    Missing,
    /// Only one of `fullchain.pem` / `key.pem` exists.
    Incomplete { reason: String },
    /// Files exist but are unparseable, expired-format, or pair-mismatched.
    Malformed { reason: String },
    /// Both files exist, parseable, paired correctly. `not_after` is the
    /// X.509 `notAfter` timestamp from `openssl x509 -enddate`.
    Valid { not_after: DateTime<Utc> },
}

/// Issue or renew certs for every desired domain. Per-domain failures are
/// captured in `EnsureCertReport.failed`; they do **not** abort the loop.
///
/// Errors only on fatal setup issues that prevent processing any domain:
/// - `acme_sh_home` cannot be resolved (HOME unset and config absent)
/// - CF token cannot be sourced (neither `dns.api_token` nor `CF_Token` env)
/// - `acme.sh` binary cannot be located
/// - Account registration fails (network/auth)
pub async fn ensure_certs_for_desired(
    domains: &[DomainInfo],
    nginx: &NginxSection,
    acme: &AcmeConfig,
    dns: &DnsProviderConfig,
) -> Result<EnsureCertReport> {
    if domains.is_empty() {
        tracing::debug!("no desired domains; skipping ACME certificate ensure");
        return Ok(EnsureCertReport::default());
    }

    let ctx = AcmeCtx::resolve(nginx, acme, dns)?;

    fs::create_dir_all(&acme.lock_dir).with_context(|| {
        format!(
            "failed to create acme lock directory: {}",
            acme.lock_dir.display()
        )
    })?;

    // Per spec D9: register every entry, no cache. acme.sh handles
    // "already registered" idempotently.
    register_account(&ctx).context("acme.sh account registration failed")?;

    let mut report = EnsureCertReport::default();
    for d in domains {
        let outcome = ensure_cert_inner(&d.name, &ctx).await;
        match outcome {
            CertOutcome::Existing => {
                tracing::debug!(domain = %d.name, "cert valid; no acme.sh invocation");
                report.existing.push(d.name.clone());
            }
            CertOutcome::Issued => {
                tracing::info!(domain = %d.name, "cert freshly issued via ACME");
                report.issued.push(d.name.clone());
            }
            CertOutcome::Renewed => {
                tracing::info!(domain = %d.name, "cert renewed via ACME");
                report.renewed.push(d.name.clone());
            }
            CertOutcome::Failed { reason } => {
                tracing::warn!(domain = %d.name, reason = %reason, "ACME cert ensure failed");
                report.failed.push((d.name.clone(), reason));
            }
        }
    }

    Ok(report)
}

/// Single-domain entry point exposed for testing. Performs the same
/// account registration as `ensure_certs_for_desired` so it is
/// API-self-sufficient.
pub async fn ensure_cert(
    domain: &str,
    nginx: &NginxSection,
    acme: &AcmeConfig,
    dns: &DnsProviderConfig,
) -> Result<CertOutcome> {
    let ctx = AcmeCtx::resolve(nginx, acme, dns)?;
    fs::create_dir_all(&acme.lock_dir).ok(); // best-effort; lock acquire will retry
    register_account(&ctx).context("acme.sh account registration failed")?;
    Ok(ensure_cert_inner(domain, &ctx).await)
}

/// Resolved per-invocation context — owns the borrowed config refs plus
/// the runtime-resolved `acme_sh_home` and `cf_token`. Constructed once
/// at the top of `ensure_certs_for_desired` and passed into every
/// per-domain call so the entry signatures stay narrow.
struct AcmeCtx<'a> {
    nginx: &'a NginxSection,
    acme: &'a AcmeConfig,
    bin: PathBuf,
    home: PathBuf,
    cf_token: String,
}

impl<'a> AcmeCtx<'a> {
    fn resolve(
        nginx: &'a NginxSection,
        acme: &'a AcmeConfig,
        dns: &'a DnsProviderConfig,
    ) -> Result<Self> {
        let home = acme
            .resolved_acme_sh_home()
            .context("failed to resolve acme.sh home")?;

        let cf_token = match &dns.api_token {
            Some(t) if !t.is_empty() => t.clone(),
            _ => std::env::var("CF_Token").map_err(|_| {
                anyhow!(
                    "Cloudflare API token not configured: set [dns_provider].api_token \
                     in config OR export CF_Token env var"
                )
            })?,
        };

        let bin = resolved_acme_bin(acme);
        if !acme_bin_exists(&bin) {
            bail!(
                "acme.sh binary not found at {} (override via CERT_ISSUER_ACME_BIN env)",
                bin.display()
            );
        }

        Ok(Self {
            nginx,
            acme,
            bin,
            home,
            cf_token,
        })
    }
}

async fn ensure_cert_inner(domain: &str, ctx: &AcmeCtx<'_>) -> CertOutcome {
    let lock_path = ctx.acme.lock_dir.join(format!("{}.acme.lock", domain));
    let _lock_guard = match acquire_domain_lock(&lock_path) {
        Ok(g) => g,
        Err(LockAcquireErrorPub {
            kind: LockAcquireKind::Held,
            ..
        }) => {
            return CertOutcome::Failed {
                reason: format!("lock held: {}", lock_path.display()),
            };
        }
        Err(LockAcquireErrorPub { message, .. }) => {
            return CertOutcome::Failed {
                reason: format!("lock acquire failed: {}", message),
            };
        }
    };

    let cert_dir = ctx.nginx.ssl_base_dir.join(domain);
    let was_renewal = match inspect_existing_cert(&cert_dir) {
        CertState::Missing => false,
        CertState::Incomplete { reason } => {
            // Almost always indicates a partial-install crash; warn so
            // operators see it without raising RUST_LOG to debug.
            tracing::warn!(domain = %domain, reason = %reason, "cert incomplete; reissuing");
            false
        }
        CertState::Malformed { reason } => {
            tracing::warn!(domain = %domain, reason = %reason, "cert malformed; reissuing");
            false
        }
        CertState::Valid { not_after } => {
            if needs_renewal(not_after, ctx.acme.renewal_window_days) {
                true
            } else {
                return CertOutcome::Existing;
            }
        }
    };

    if let Err(e) = invoke_acme_sh_issue(domain, ctx) {
        return CertOutcome::Failed {
            reason: format!("acme.sh --issue failed: {:#}", e),
        };
    }

    if let Err(e) = atomic_install(&ctx.bin, &ctx.home, &ctx.nginx.ssl_base_dir, domain) {
        return CertOutcome::Failed {
            reason: format!("atomic install failed: {:#}", e),
        };
    }

    if was_renewal {
        CertOutcome::Renewed
    } else {
        CertOutcome::Issued
    }
}

// --------------------------------------------------------------------------
// Lock handling
// --------------------------------------------------------------------------

/// Wraps an `fs2` advisory file lock. The OS releases it on `Drop` (file
/// close), so callers just keep this guard alive for the critical section.
pub struct DomainLockGuard {
    file: File,
}

impl Drop for DomainLockGuard {
    fn drop(&mut self) {
        // Drop cannot return errors. Log so an unlock failure is visible —
        // even though the kernel will release the lock when `self.file`'s
        // descriptor closes immediately after this call.
        if let Err(e) = FileExt::unlock(&self.file) {
            tracing::warn!(error = %e, "DomainLockGuard: explicit unlock failed");
        }
    }
}

/// Open `lock_path` and acquire a non-blocking exclusive advisory lock.
///
/// Public only so unit tests can exercise the contention semantics.
pub fn acquire_domain_lock(lock_path: &Path) -> Result<DomainLockGuard, LockAcquireErrorPub> {
    if let Some(parent) = lock_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| LockAcquireErrorPub {
                kind: LockAcquireKind::Io,
                message: format!(
                    "failed to create lock parent dir {}: {}",
                    parent.display(),
                    e
                ),
            })?;
        }
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| LockAcquireErrorPub {
            kind: LockAcquireKind::Io,
            message: format!("open {}: {}", lock_path.display(), e),
        })?;

    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => Ok(DomainLockGuard { file }),
        Err(e) => {
            // fs2 returns WouldBlock for held locks; everything else is io
            let kind = if e.kind() == std::io::ErrorKind::WouldBlock {
                LockAcquireKind::Held
            } else {
                LockAcquireKind::Io
            };
            Err(LockAcquireErrorPub {
                kind,
                message: format!("try_lock_exclusive {}: {}", lock_path.display(), e),
            })
        }
    }
}

/// Public lock-acquisition error variants (testable).
#[derive(Debug)]
pub struct LockAcquireErrorPub {
    pub kind: LockAcquireKind,
    pub message: String,
}

/// Distinguishes contention from real I/O errors.
#[derive(Debug, PartialEq, Eq)]
pub enum LockAcquireKind {
    /// Lock currently held by another process.
    Held,
    /// Filesystem error opening or locking the file.
    Io,
}

// --------------------------------------------------------------------------
// Cert inspection
// --------------------------------------------------------------------------

fn inspect_existing_cert(cert_dir: &Path) -> CertState {
    let fullchain = cert_dir.join("fullchain.pem");
    let key = cert_dir.join("key.pem");

    // Existence classification first — the "X missing" reason strings are
    // what operators see in logs and what tests pin against.
    let fc_exists = fullchain.is_file();
    let key_exists = key.is_file();
    if !fc_exists && !key_exists {
        return CertState::Missing;
    }
    if !fc_exists {
        return CertState::Incomplete {
            reason: "fullchain.pem missing (key present)".to_string(),
        };
    }
    if !key_exists {
        return CertState::Incomplete {
            reason: "key.pem missing (fullchain present)".to_string(),
        };
    }

    // Both files present — delegate cheap PEM header/footer validation to
    // cert_validator (the same routine compute_diff uses for defense-in-
    // depth) so empty / corrupted PEM gets caught before we spawn openssl.
    if let crate::cert_validator::CertValidation::Invalid(reason) =
        crate::cert_validator::validate_cert_files(&fullchain, &key)
    {
        return CertState::Malformed { reason };
    }

    // Single openssl spawn yields both the enddate AND the cert pubkey,
    // halving subprocess count per valid-cert domain on the hot path.
    let (not_after, cert_pub) = match read_enddate_and_pubkey(&fullchain) {
        Ok(pair) => pair,
        Err(e) => {
            return CertState::Malformed {
                reason: format!("openssl x509 enddate+pubkey failed: {}", e),
            };
        }
    };

    if let Err(e) = verify_cert_key_pair(&cert_pub, &key) {
        return CertState::Malformed {
            reason: format!("cert/key pair mismatch: {}", e),
        };
    }

    CertState::Valid { not_after }
}

/// Single openssl invocation that returns both `notAfter` and the cert's
/// PEM-encoded public key. openssl's `-enddate -pubkey` flag combination
/// emits the enddate line followed by the pubkey PEM block on stdout.
fn read_enddate_and_pubkey(fullchain: &Path) -> Result<(DateTime<Utc>, Vec<u8>)> {
    let output = Command::new("openssl")
        .args(["x509", "-noout", "-enddate", "-pubkey", "-in"])
        .arg(fullchain)
        .output()
        .context("failed to spawn openssl x509")?;
    if !output.status.success() {
        bail!(
            "openssl x509 exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Output format: "notAfter=...\n-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    let stdout = String::from_utf8(output.stdout).context("openssl x509 output not UTF-8")?;
    let (enddate_line, pubkey_pem) = stdout
        .split_once("-----BEGIN PUBLIC KEY-----")
        .ok_or_else(|| anyhow!("openssl x509 output missing PUBLIC KEY block: {:?}", stdout))?;
    let not_after = parse_not_after(enddate_line)?;
    let pubkey_bytes = format!("-----BEGIN PUBLIC KEY-----{}", pubkey_pem).into_bytes();
    Ok((not_after, pubkey_bytes))
}

/// Parse openssl's `notAfter=Apr 15 12:00:00 2026 GMT` line into a UTC time.
pub fn parse_not_after(s: &str) -> Result<DateTime<Utc>> {
    let stripped = s
        .trim()
        .strip_prefix("notAfter=")
        .ok_or_else(|| anyhow!("unexpected openssl output: {:?}", s))?;
    let ndt = chrono::NaiveDateTime::parse_from_str(stripped, "%b %e %H:%M:%S %Y GMT")
        .map_err(|e| anyhow!("failed to parse enddate {:?}: {}", stripped, e))?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
}

/// True when `not_after` is within `window_days` of "now".
pub fn needs_renewal(not_after: DateTime<Utc>, window_days: u32) -> bool {
    not_after < Utc::now() + chrono::Duration::days(window_days as i64)
}

/// Verify that the public key embedded in the cert matches the public key
/// derived from `key.pem`. Works for both RSA and EC keys because
/// `openssl pkey -pubout` derives the public component from any private
/// key algorithm. The cert pubkey comes pre-extracted from the merged
/// `read_enddate_and_pubkey` call so we only spawn openssl once for the
/// key file.
fn verify_cert_key_pair(cert_pub: &[u8], key: &Path) -> Result<()> {
    let key_pub = Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(key)
        .output()
        .context("openssl pkey -pubout spawn")?;
    if !key_pub.status.success() {
        bail!(
            "openssl pkey -pubout failed: {}",
            String::from_utf8_lossy(&key_pub.stderr)
        );
    }

    let cert_pem = normalize_pem(cert_pub);
    let key_pem = normalize_pem(&key_pub.stdout);
    if cert_pem != key_pem {
        bail!(
            "cert pubkey ({} bytes) != key pubkey ({} bytes)",
            cert_pem.len(),
            key_pem.len()
        );
    }
    Ok(())
}

fn normalize_pem(bytes: &[u8]) -> Vec<u8> {
    // Strip all ASCII whitespace so trailing newline / line-ending differences
    // don't cause spurious mismatches between `openssl` invocations.
    bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

// --------------------------------------------------------------------------
// acme.sh invocation
// --------------------------------------------------------------------------

fn resolved_acme_bin(acme: &AcmeConfig) -> PathBuf {
    if let Ok(override_bin) = std::env::var("CERT_ISSUER_ACME_BIN") {
        if !override_bin.is_empty() {
            return PathBuf::from(override_bin);
        }
    }
    acme.acme_bin.clone()
}

fn acme_bin_exists(bin: &Path) -> bool {
    if bin.is_file() {
        return true;
    }
    // PATH lookup — only meaningful when bin is a bare name.
    if bin.components().count() == 1 {
        if let Ok(path) = std::env::var("PATH") {
            for dir in path.split(':') {
                if Path::new(dir).join(bin).is_file() {
                    return true;
                }
            }
        }
    }
    false
}

fn server_arg(acme: &AcmeConfig) -> String {
    if acme.staging {
        "letsencrypt_test".to_string()
    } else {
        acme.directory_url.clone()
    }
}

fn register_account(ctx: &AcmeCtx<'_>) -> Result<()> {
    let mut cmd = Command::new(&ctx.bin);
    cmd.arg("--register-account")
        .arg("-m")
        .arg(&ctx.acme.email)
        .arg("--home")
        .arg(&ctx.home)
        .arg("--server")
        .arg(server_arg(ctx.acme))
        .env("CF_Token", &ctx.cf_token);
    let output = cmd
        .output()
        .context("failed to spawn acme.sh --register-account")?;
    if !output.status.success() {
        bail!(
            "acme.sh --register-account exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn invoke_acme_sh_issue(domain: &str, ctx: &AcmeCtx<'_>) -> Result<()> {
    let mut cmd = Command::new(&ctx.bin);
    cmd.arg("--issue")
        .arg("--dns")
        .arg("dns_cf")
        .arg("-d")
        .arg(domain)
        .arg("--home")
        .arg(&ctx.home)
        .arg("--server")
        .arg(server_arg(ctx.acme))
        .env("CF_Token", &ctx.cf_token);

    let output = cmd
        .output()
        .with_context(|| format!("failed to spawn {} --issue", ctx.bin.display()))?;

    if !output.status.success() {
        // Exit code 2 = "skipped, cert already valid" in acme.sh, which is
        // benign during renewal sweeps. Treat as success but preserve the
        // stderr in the trace log so operators can see what acme.sh said
        // (e.g. "Skip, Next renewal time is …").
        //
        // Known limitation: when ndc's local renewal_window_days is more
        // aggressive than acme.sh's `renewBeforeExpiry`, the caller will
        // still proceed to atomic_install (copying the *same* bytes from
        // acme.sh's cache to live paths) and report Issued/Renewed,
        // forcing an unnecessary nginx reload. Plumbing the exit-2 signal
        // back to ensure_cert_inner so it can return Existing without
        // re-installing is tracked as a follow-up — see PR #7 review.
        if output.status.code() == Some(2) {
            tracing::debug!(
                domain = %domain,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "acme.sh --issue returned 2 (cert already valid)"
            );
            return Ok(());
        }
        bail!(
            "acme.sh --issue (-d {}) exited with {}: {}",
            domain,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

// --------------------------------------------------------------------------
// Atomic install
// --------------------------------------------------------------------------

/// Copy cert material from acme.sh's tree into ndc-owned temp paths via
/// `--install-cert`, then rename atomically into the live paths. Public so
/// unit tests can exercise the rename + permissions semantics with mocked
/// inputs.
///
/// **External-actor hazard.** Between the two `rename` calls (fullchain
/// then key), a microsecond window exists in which the live directory has
/// `(new fullchain, old key)`. The cert/key pair will fail TLS handshakes
/// during that window. The per-domain advisory flock acquired by the
/// caller serializes *cert writers* but does **not** serialize *nginx
/// reloads*. The deployment must guarantee that no other actor (acme.sh
/// cron, logrotate postrotate, systemd `Reload=`, manual `nginx -s reload`)
/// triggers a reload while this function is running. See module-level
/// docs and SPEC §2.3 D13.
pub fn atomic_install(
    acme_bin: &Path,
    acme_sh_home: &Path,
    ssl_base: &Path,
    domain: &str,
) -> Result<()> {
    let dst_dir = ssl_base.join(domain);
    fs::create_dir_all(&dst_dir).with_context(|| {
        format!(
            "failed to create cert destination dir: {}",
            dst_dir.display()
        )
    })?;

    let tmp_fullchain = dst_dir.join("fullchain.pem.new");
    let tmp_key = dst_dir.join("key.pem.new");

    // Ask acme.sh to install directly into our temp paths. This is the
    // supported boundary — we never read from <acme_sh_home>/<domain>/.
    // Use `.output()` rather than `.status()` so install-cert stderr is
    // captured and surfaced in the bail message (otherwise it leaks to
    // the parent's inherited stderr where the caller can't see it).
    let output = Command::new(acme_bin)
        .arg("--install-cert")
        .arg("-d")
        .arg(domain)
        .arg("--home")
        .arg(acme_sh_home)
        .arg("--key-file")
        .arg(&tmp_key)
        .arg("--fullchain-file")
        .arg(&tmp_fullchain)
        .output()
        .context("failed to spawn acme.sh --install-cert")?;
    if !output.status.success() {
        bail!(
            "acme.sh --install-cert exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    // Force exact perms via syscall (bypasses umask, unlike OpenOptions::mode).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_fullchain, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("set_permissions {}", tmp_fullchain.display()))?;
        fs::set_permissions(&tmp_key, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set_permissions {}", tmp_key.display()))?;
    }

    // fsync both files so the data the child process wrote is durable
    // before we rename. POSIX `fsync(fd)` is per-inode regardless of the
    // fd's read/write mode, so opening read-only here is sufficient. We
    // split open vs sync_all into two `?` steps so a context message
    // points at the actual failing operation.
    let f = File::open(&tmp_fullchain)
        .with_context(|| format!("open for fsync: {}", tmp_fullchain.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync: {}", tmp_fullchain.display()))?;
    let f =
        File::open(&tmp_key).with_context(|| format!("open for fsync: {}", tmp_key.display()))?;
    f.sync_all()
        .with_context(|| format!("fsync: {}", tmp_key.display()))?;

    let live_fullchain = dst_dir.join("fullchain.pem");
    let live_key = dst_dir.join("key.pem");

    // Per-file rename is atomic on the same FS. See function-level doc
    // for the (cert.new, key.old) intermediate-state hazard.
    fs::rename(&tmp_fullchain, &live_fullchain).with_context(|| {
        format!(
            "rename {} -> {}",
            tmp_fullchain.display(),
            live_fullchain.display()
        )
    })?;
    fs::rename(&tmp_key, &live_key)
        .with_context(|| format!("rename {} -> {}", tmp_key.display(), live_key.display()))?;

    // POSIX requires fsyncing the parent dir for rename durability.
    let dir = File::open(&dst_dir)
        .with_context(|| format!("open parent for fsync: {}", dst_dir.display()))?;
    dir.sync_all()
        .with_context(|| format!("fsync parent: {}", dst_dir.display()))?;

    // Always fsync ssl_base for first-issue durability. On the renew path
    // dst_dir already existed and this is a no-op cost; on the first-issue
    // path it ensures the new domain subdirectory entry survives a
    // crash + reboot. One fsync per cycle is cheap; the unconditional
    // form is simpler than tracking dst_was_new.
    let parent = File::open(ssl_base)
        .with_context(|| format!("open ssl_base for fsync: {}", ssl_base.display()))?;
    parent
        .sync_all()
        .with_context(|| format!("fsync ssl_base: {}", ssl_base.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dst_dir, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("set_permissions {}", dst_dir.display()))?;
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate process-global env vars
    /// (`CERT_ISSUER_ACME_BIN`). Cargo runs unit tests in parallel by
    /// default; without this mutex any future test that *reads* the env
    /// would race with `resolved_acme_bin_env_override` below.
    static ENV_MUTATION_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parse_not_after_basic() {
        let s = "notAfter=Apr 15 12:00:00 2026 GMT\n";
        let dt = parse_not_after(s).unwrap();
        assert_eq!(dt.to_rfc3339(), "2026-04-15T12:00:00+00:00");
    }

    #[test]
    fn parse_not_after_single_digit_day() {
        // openssl uses %e (space-padded day) — must accept "Jan  5"
        let s = "notAfter=Jan  5 00:00:00 2027 GMT";
        let dt = parse_not_after(s).unwrap();
        assert_eq!(dt.to_rfc3339(), "2027-01-05T00:00:00+00:00");
    }

    #[test]
    fn parse_not_after_rejects_garbage() {
        assert!(parse_not_after("garbage").is_err());
        assert!(parse_not_after("notAfter=not a date").is_err());
    }

    #[test]
    fn needs_renewal_window_boundary() {
        let now = Utc::now();
        // 31 days away with 30-day window → no renewal
        assert!(!needs_renewal(now + chrono::Duration::days(31), 30));
        // 29 days away with 30-day window → renew
        assert!(needs_renewal(now + chrono::Duration::days(29), 30));
        // expired → renew
        assert!(needs_renewal(now - chrono::Duration::hours(1), 30));
    }

    #[test]
    fn lock_acquire_release_reacquire() {
        // Behavioral check: acquire → drop → reacquire must succeed.
        // This proves the unlock path works without depending on
        // platform-specific same-process contention semantics (fs2 uses
        // BSD `flock` on macOS — per-fd; on Linux — `flock` syscall, also
        // per-fd in practice — so two file handles in the same process
        // *should* see contention, but POSIX advisory `fcntl` locks are
        // per-process and would not. We sidestep the ambiguity here and
        // verify cross-process contention separately in
        // `lock_held_by_subprocess_returns_held` below).
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("a.example.com.acme.lock");

        let g1 = acquire_domain_lock(&lock).expect("first lock should succeed");
        drop(g1);
        let g2 = acquire_domain_lock(&lock).expect("reacquire after drop should succeed");
        drop(g2);
    }

    /// Cross-process contention test — the only reliable way to assert
    /// `LockAcquireKind::Held`. Spawns a python3 helper that holds the
    /// lock via `fcntl.flock`, then verifies the parent's
    /// `acquire_domain_lock` returns `Held`.
    ///
    /// Skipped (returns early) when python3 is not on PATH.
    #[test]
    fn lock_held_by_subprocess_returns_held() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        if Command::new("python3")
            .arg("-c")
            .arg("import fcntl, sys; sys.exit(0)")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            eprintln!("skipping: python3 with fcntl unavailable");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("contended.acme.lock");

        let script = r#"
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o644)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except (BlockingIOError, OSError) as e:
    print(f"FAILED:{e}", flush=True)
    sys.exit(1)
print("LOCKED", flush=True)
# Hold the lock until parent kills us or 10s elapse.
time.sleep(10)
"#;
        let mut child = Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(&lock_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3 lock holder");

        // Wait for "LOCKED" handshake so we know the child actually holds
        // the lock before we attempt to acquire. The python helper has a
        // 10s sleep cap; if it fails to ever report LOCKED, read_line
        // returns Ok(0) (EOF on child exit) and we abort the test.
        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let acquired = loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break false,
                Ok(_) if line.trim() == "LOCKED" => break true,
                Ok(_) => continue,
                Err(_) => break false,
            }
        };

        if !acquired {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "python3 helper failed to report LOCKED handshake: {:?}",
                line
            );
        }

        // Now attempt to acquire from this process — must report Held.
        let result = acquire_domain_lock(&lock_path);

        // Clean up child before asserting so a failed assertion doesn't
        // leak a 10-second-sleeping subprocess.
        let _ = child.kill();
        let _ = child.wait();

        match result {
            Ok(_g) => panic!("expected Held; subprocess holds the lock"),
            Err(e) => assert_eq!(
                e.kind,
                LockAcquireKind::Held,
                "expected Held, got {:?} ({})",
                e.kind,
                e.message
            ),
        }
    }

    #[test]
    fn lock_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested").join("deep");
        let lock = nested.join("d.acme.lock");
        // Parent doesn't exist yet — function must create it.
        let _g = acquire_domain_lock(&lock).expect("acquire should create parent");
        assert!(nested.is_dir());
        assert!(lock.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn set_permissions_bypasses_umask() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("k.pem.new");
        fs::write(&f, b"secret").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        let mode = fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "expected 0600 after set_permissions, got {:o}",
            mode
        );
    }

    #[test]
    fn ensure_report_had_material_change() {
        let mut r = EnsureCertReport::default();
        assert!(!r.had_material_change());
        r.existing.push("a.com".to_string());
        assert!(!r.had_material_change(), "existing should not count");
        r.failed.push(("b.com".into(), "lock held".into()));
        assert!(!r.had_material_change(), "failed should not count");
        r.issued.push("c.com".to_string());
        assert!(r.had_material_change());
        r.issued.clear();
        r.renewed.push("d.com".to_string());
        assert!(r.had_material_change());
    }

    #[test]
    fn inspect_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            inspect_existing_cert(&dir.path().join("nope.com")),
            CertState::Missing
        );
    }

    #[test]
    fn inspect_incomplete_only_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_dir = dir.path().join("a.com");
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join("key.pem"), "x").unwrap();
        match inspect_existing_cert(&cert_dir) {
            CertState::Incomplete { reason } => {
                assert!(reason.contains("fullchain.pem missing"), "{}", reason);
            }
            other => panic!("expected Incomplete, got {:?}", other),
        }
    }

    #[test]
    fn resolved_acme_bin_env_override() {
        // Hold ENV_MUTATION_LOCK for the full critical section so the
        // process-global CERT_ISSUER_ACME_BIN is observed atomically by
        // any concurrent reader.
        let _guard = ENV_MUTATION_LOCK.lock().unwrap();

        let acme = AcmeConfig {
            email: "x@y".into(),
            directory_url: "https://acme/x".into(),
            staging: false,
            renewal_window_days: 30,
            acme_sh_home: None,
            acme_bin: PathBuf::from("acme.sh"),
            lock_dir: PathBuf::from("/tmp"),
        };
        std::env::set_var("CERT_ISSUER_ACME_BIN", "/opt/mock/acme.sh");
        assert_eq!(resolved_acme_bin(&acme), PathBuf::from("/opt/mock/acme.sh"));
        std::env::remove_var("CERT_ISSUER_ACME_BIN");
        assert_eq!(resolved_acme_bin(&acme), PathBuf::from("acme.sh"));
    }

    #[test]
    fn server_arg_staging_vs_prod() {
        let mut acme = AcmeConfig {
            email: "x@y".into(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            staging: false,
            renewal_window_days: 30,
            acme_sh_home: None,
            acme_bin: PathBuf::from("acme.sh"),
            lock_dir: PathBuf::from("/tmp"),
        };
        assert_eq!(
            server_arg(&acme),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        acme.staging = true;
        assert_eq!(server_arg(&acme), "letsencrypt_test");
    }
}
