//! Integration tests for the ACME cert-issuer module.
//!
//! These tests use a mock `acme.sh` shell script (provided per-test as
//! `acme.acme_bin`) so we don't depend on network access, real Cloudflare
//! credentials, or `acme.sh` being installed on the test host. The mock
//! forwards `--install-cert` to a self-signed `openssl req` invocation that
//! materializes cert/key files at the requested paths.
//!
//! Coverage map vs SPEC §4 Verification Checklist:
//! - V1  issue_new_domain — lib-level (mock acme.sh)
//! - V2  skip_valid_cert — lib-level (mock invocation count)
//! - V3  renew_near_expiry — lib-level (5-day cert pre-seed)
//! - V4  cf_token_invalid_isolated — lib-level (mock fails for one domain,
//!   others succeed)
//! - V5  missing_acme_bin — lib-level (point at /nonexistent)
//! - V6  lock_contention_nonblocking — covered in unit tests
//!   (`acquire_domain_lock`)
//! - V7  unit — `parse_not_after`, `needs_renewal`, perms — unit tests
//! - V8a empty_desired_acme_noop — covered by V0 and sync_empty_desired tests
//! - V9  partial_install_recovery_stale — lib-level
//! - V9a partial_install_mismatched_pair — lib-level
//! - V10 legacy_mode_no_regression — config-level: no [acme] →
//!   ensure_certs_for_desired never called

#![cfg(unix)]

use nginx_domain_cli::cert_issuer::{ensure_certs_for_desired, CertOutcome, EnsureCertReport};
use nginx_domain_cli::config::{AcmeConfig, DnsProviderConfig, NginxSection};
use nginx_domain_cli::domain::{DomainInfo, DomainStatus};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// --------------------------------------------------------------------------
// Test fixtures
// --------------------------------------------------------------------------

struct AcmeFixture {
    _tmp: tempfile::TempDir,
    ssl_base: PathBuf,
    lock_dir: PathBuf,
    acme_sh_home: PathBuf,
    mock_bin: PathBuf,
    mock_log: PathBuf,
}

fn setup_fixture() -> AcmeFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let ssl_base = root.join("ssl");
    let lock_dir = root.join("locks");
    let acme_sh_home = root.join("acme_home");
    let mock_log = root.join("mock.log");
    fs::create_dir_all(&ssl_base).unwrap();
    fs::create_dir_all(&lock_dir).unwrap();
    fs::create_dir_all(&acme_sh_home).unwrap();

    let mock_bin = root.join("mock_acme.sh");
    write_mock_script(&mock_bin, &mock_log, &[]);

    AcmeFixture {
        _tmp: tmp,
        ssl_base,
        lock_dir,
        acme_sh_home,
        mock_bin,
        mock_log,
    }
}

/// Write a mock `acme.sh`. `fail_domains` is a list of domain names for
/// which `--issue` should exit non-zero (simulating CF token / rate-limit
/// failures isolated to those domains).
fn write_mock_script(path: &Path, log: &Path, fail_domains: &[&str]) {
    let fail_match = if fail_domains.is_empty() {
        "false".to_string()
    } else {
        fail_domains
            .iter()
            .map(|d| format!("[ \"$dom\" = \"{}\" ] && return 0", d))
            .collect::<Vec<_>>()
            .join(" || ")
            + " ; return 1"
    };
    let script = format!(
        r#"#!/bin/bash
set -e
LOG="{log}"
echo "$@" >> "$LOG"

is_failing_domain() {{
  local dom="$1"
  {fail_match}
}}

case "$1" in
  --register-account)
    exit 0
    ;;
  --issue)
    # Extract -d <domain>
    DOM=""
    args=("$@")
    i=0
    while [ $i -lt ${{#args[@]}} ]; do
      if [ "${{args[$i]}}" = "-d" ]; then
        next=$((i+1))
        DOM="${{args[$next]}}"
        break
      fi
      i=$((i+1))
    done
    if is_failing_domain "$DOM"; then
      echo "mock: simulated CF token failure for $DOM" >&2
      exit 1
    fi
    exit 0
    ;;
  --install-cert)
    KEYFILE=""
    FCFILE=""
    DOM=""
    args=("$@")
    i=0
    while [ $i -lt ${{#args[@]}} ]; do
      a="${{args[$i]}}"
      next=$((i+1))
      case "$a" in
        --key-file) KEYFILE="${{args[$next]}}"; i=$((i+2)) ;;
        --fullchain-file) FCFILE="${{args[$next]}}"; i=$((i+2)) ;;
        -d) DOM="${{args[$next]}}"; i=$((i+2)) ;;
        *) i=$((i+1)) ;;
      esac
    done
    [ -z "$KEYFILE" ] && {{ echo "mock: --key-file missing" >&2; exit 1; }}
    [ -z "$FCFILE" ] && {{ echo "mock: --fullchain-file missing" >&2; exit 1; }}
    # Generate a fresh self-signed cert pair valid for 365 days.
    openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
      -keyout "$KEYFILE" -out "$FCFILE" \
      -subj "/CN=$DOM" -batch 2>/dev/null
    exit 0
    ;;
esac
echo "mock: unhandled args $@" >&2
exit 1
"#,
        log = log.display(),
        fail_match = fail_match,
    );
    // Unlink first so a re-write produces a fresh inode. On Linux,
    // overwriting a file that was recently `execve`d (or is still in
    // the kernel's exec cache) can fail subsequent spawns with ETXTBSY
    // ("Text file busy"). V4 re-invokes this helper to inject
    // fail_domains after setup_fixture's initial write — the unlink
    // sidesteps that race entirely.
    let _ = fs::remove_file(path);
    fs::write(path, script).expect("write mock");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn read_mock_log(log: &Path) -> Vec<String> {
    fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|s| s.to_string())
        .collect()
}

fn make_acme(fix: &AcmeFixture) -> AcmeConfig {
    AcmeConfig {
        email: "ops@example.com".into(),
        directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
        staging: true,
        renewal_window_days: 30,
        acme_sh_home: Some(fix.acme_sh_home.clone()),
        acme_bin: fix.mock_bin.clone(),
        lock_dir: fix.lock_dir.clone(),
    }
}

fn make_dns() -> DnsProviderConfig {
    DnsProviderConfig {
        provider: "cloudflare".into(),
        api_token: Some("test_dummy_cf_token".into()),
    }
}

fn make_nginx(fix: &AcmeFixture) -> NginxSection {
    NginxSection {
        ssl_base_dir: fix.ssl_base.clone(),
        ..Default::default()
    }
}

fn domain(name: &str) -> DomainInfo {
    DomainInfo {
        no: 1,
        name: name.to_string(),
        status: DomainStatus::InUse,
        app: "test".to_string(),
    }
}

/// Pre-seed a cert/key pair via openssl with the given validity (in days).
/// Used to set up V2 (long-lived) and V3 (near-expiry) starting state.
fn seed_cert(ssl_base: &Path, name: &str, days: u32) {
    let dir = ssl_base.join(name);
    fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("fullchain.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-days",
            &days.to_string(),
            "-nodes",
            "-batch",
            "-subj",
            &format!("/CN={}", name),
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .expect("openssl req");
    assert!(
        status.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

/// Pre-seed cert from one keypair and key from a *different* keypair —
/// the pubkey-mismatch case exercised by V9a.
fn seed_mismatched_pair(ssl_base: &Path, name: &str) {
    let dir = ssl_base.join(name);
    fs::create_dir_all(&dir).unwrap();
    let tmp = tempfile::tempdir().unwrap();

    // Pair 1
    let cert1 = tmp.path().join("c1.pem");
    let key1 = tmp.path().join("k1.pem");
    Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-days", "365", "-nodes", "-batch", "-subj",
        ])
        .arg(format!("/CN={}", name))
        .arg("-keyout")
        .arg(&key1)
        .arg("-out")
        .arg(&cert1)
        .output()
        .unwrap();

    // Pair 2
    let key2 = tmp.path().join("k2.pem");
    let cert2 = tmp.path().join("c2.pem");
    Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-days", "365", "-nodes", "-batch", "-subj",
        ])
        .arg(format!("/CN={}", name))
        .arg("-keyout")
        .arg(&key2)
        .arg("-out")
        .arg(&cert2)
        .output()
        .unwrap();

    fs::copy(&cert1, dir.join("fullchain.pem")).unwrap();
    fs::copy(&key2, dir.join("key.pem")).unwrap();
}

fn assert_files_present(ssl_base: &Path, name: &str) {
    let dir = ssl_base.join(name);
    assert!(
        dir.join("fullchain.pem").is_file(),
        "fullchain.pem missing for {}",
        name
    );
    assert!(
        dir.join("key.pem").is_file(),
        "key.pem missing for {}",
        name
    );
}

fn assert_perms(ssl_base: &Path, name: &str) {
    let dir = ssl_base.join(name);
    let fc_mode = fs::metadata(dir.join("fullchain.pem"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let key_mode = fs::metadata(dir.join("key.pem"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(fc_mode, 0o644, "fullchain perms");
    assert_eq!(key_mode, 0o600, "key perms");
}

fn require_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// --------------------------------------------------------------------------
// V0 — empty desired is ACME no-op
// --------------------------------------------------------------------------

#[tokio::test]
async fn v0_empty_desired_is_acme_noop() {
    let fix = setup_fixture();
    let mut acme = make_acme(&fix);
    acme.acme_bin = PathBuf::from("/definitely/does/not/exist/acme.sh");
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let report = ensure_certs_for_desired(&[], &nginx, &acme, &dns)
        .await
        .expect("empty desired should not require ACME setup");

    assert!(report.existing.is_empty());
    assert!(report.issued.is_empty());
    assert!(report.renewed.is_empty());
    assert!(report.failed.is_empty());
    assert!(!report.had_material_change());
}

// --------------------------------------------------------------------------
// V1 — issue new domain
// --------------------------------------------------------------------------

#[tokio::test]
async fn v1_issue_new_domain() {
    if !require_openssl() {
        eprintln!("skipping: openssl not available");
        return;
    }
    let fix = setup_fixture();
    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let domains = vec![domain("v1.example.com")];
    let report = ensure_certs_for_desired(&domains, &nginx, &acme, &dns)
        .await
        .expect("ensure ok");

    assert_eq!(report.issued, vec!["v1.example.com".to_string()]);
    assert!(report.renewed.is_empty());
    assert!(report.failed.is_empty());
    assert!(report.had_material_change());
    assert_files_present(&fix.ssl_base, "v1.example.com");
    assert_perms(&fix.ssl_base, "v1.example.com");
}

// --------------------------------------------------------------------------
// V2 — skip valid cert (mock NOT invoked for issue/install)
// --------------------------------------------------------------------------

#[tokio::test]
async fn v2_skip_valid_cert() {
    if !require_openssl() {
        return;
    }
    let fix = setup_fixture();
    seed_cert(&fix.ssl_base, "v2.example.com", 365);
    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let domains = vec![domain("v2.example.com")];
    let report = ensure_certs_for_desired(&domains, &nginx, &acme, &dns)
        .await
        .expect("ensure ok");

    assert_eq!(report.existing, vec!["v2.example.com".to_string()]);
    assert!(report.issued.is_empty());
    assert!(report.renewed.is_empty());
    assert!(!report.had_material_change());

    // Mock should have been called for --register-account ONLY.
    let log = read_mock_log(&fix.mock_log);
    let issue_calls = log.iter().filter(|l| l.starts_with("--issue ")).count();
    let install_calls = log
        .iter()
        .filter(|l| l.starts_with("--install-cert "))
        .count();
    assert_eq!(issue_calls, 0, "issue should not be called");
    assert_eq!(install_calls, 0, "install should not be called");
}

// --------------------------------------------------------------------------
// V3 — renew near expiry
// --------------------------------------------------------------------------

#[tokio::test]
async fn v3_renew_near_expiry() {
    if !require_openssl() {
        return;
    }
    let fix = setup_fixture();
    seed_cert(&fix.ssl_base, "v3.example.com", 5); // 5 days < 30-day window
    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let domains = vec![domain("v3.example.com")];
    let report = ensure_certs_for_desired(&domains, &nginx, &acme, &dns)
        .await
        .expect("ensure ok");

    assert_eq!(report.renewed, vec!["v3.example.com".to_string()]);
    assert!(report.issued.is_empty());
    assert!(report.had_material_change());
    assert_files_present(&fix.ssl_base, "v3.example.com");
}

// --------------------------------------------------------------------------
// V4 — CF token failure isolated to one domain
// --------------------------------------------------------------------------

#[tokio::test]
async fn v4_cf_token_invalid_isolated() {
    if !require_openssl() {
        return;
    }
    let fix = setup_fixture();
    // Re-write mock to fail for "bad.example.com" only.
    write_mock_script(&fix.mock_bin, &fix.mock_log, &["bad.example.com"]);

    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let domains = vec![domain("good.example.com"), domain("bad.example.com")];
    let report = ensure_certs_for_desired(&domains, &nginx, &acme, &dns)
        .await
        .expect("ensure ok (overall)");

    assert!(
        report.issued.contains(&"good.example.com".to_string()),
        "good.example.com should be issued, got issued={:?}",
        report.issued
    );
    assert_eq!(report.failed.len(), 1, "one failure expected");
    assert_eq!(report.failed[0].0, "bad.example.com");
    assert!(
        report.failed[0].1.contains("acme.sh --issue failed"),
        "reason should mention acme.sh failure: {}",
        report.failed[0].1
    );
    assert!(report.had_material_change());
    assert_files_present(&fix.ssl_base, "good.example.com");
}

// --------------------------------------------------------------------------
// V5 — missing acme.sh binary
// --------------------------------------------------------------------------

#[tokio::test]
async fn v5_missing_acme_bin() {
    let fix = setup_fixture();
    let mut acme = make_acme(&fix);
    acme.acme_bin = PathBuf::from("/definitely/does/not/exist/acme.sh");
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let result = ensure_certs_for_desired(&[domain("v5.example.com")], &nginx, &acme, &dns).await;
    let err = result.expect_err("should fail when acme.sh is missing");
    let msg = format!("{:#}", err);
    assert!(msg.contains("acme.sh binary not found"), "msg: {}", msg);
}

// --------------------------------------------------------------------------
// V9 — partial install recovery (stale .new file)
// --------------------------------------------------------------------------

#[tokio::test]
async fn v9_partial_install_recovery_stale_new() {
    if !require_openssl() {
        return;
    }
    let fix = setup_fixture();
    // Pre-seed: dst dir exists with a stale fullchain.pem.new from a prior crash.
    let dst = fix.ssl_base.join("v9.example.com");
    fs::create_dir_all(&dst).unwrap();
    let mut f = fs::File::create(dst.join("fullchain.pem.new")).unwrap();
    writeln!(f, "stale leftover").unwrap();
    drop(f);

    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let report = ensure_certs_for_desired(&[domain("v9.example.com")], &nginx, &acme, &dns)
        .await
        .expect("ensure ok");
    assert_eq!(report.issued, vec!["v9.example.com".to_string()]);
    // Stale .new should have been overwritten by --install-cert and renamed.
    assert!(!dst.join("fullchain.pem.new").exists());
    assert!(dst.join("fullchain.pem").is_file());
    assert!(dst.join("key.pem").is_file());
}

// --------------------------------------------------------------------------
// V9a — partial install: mismatched pair triggers reissue
// --------------------------------------------------------------------------

#[tokio::test]
async fn v9a_partial_install_recovery_mismatched_pair() {
    if !require_openssl() {
        return;
    }
    let fix = setup_fixture();
    seed_mismatched_pair(&fix.ssl_base, "v9a.example.com");

    let acme = make_acme(&fix);
    let dns = make_dns();
    let nginx = make_nginx(&fix);

    let report = ensure_certs_for_desired(&[domain("v9a.example.com")], &nginx, &acme, &dns)
        .await
        .expect("ensure ok");

    // Mismatch was detected → treated as Malformed → reissued (not Existing).
    assert_eq!(report.issued, vec!["v9a.example.com".to_string()]);
    assert!(report.existing.is_empty());
    assert_files_present(&fix.ssl_base, "v9a.example.com");
}

// --------------------------------------------------------------------------
// V10 — legacy mode (no [acme]) — covered indirectly: ensure_certs_for_desired
// is only invoked when both [acme] and [dns_provider] are configured. We
// verify the default-empty report shape so cmd_sync's branches behave.
// --------------------------------------------------------------------------

#[test]
fn v10_legacy_mode_default_report_is_inert() {
    let r = EnsureCertReport::default();
    assert!(r.existing.is_empty());
    assert!(r.issued.is_empty());
    assert!(r.renewed.is_empty());
    assert!(r.failed.is_empty());
    assert!(!r.had_material_change());
}

// --------------------------------------------------------------------------
// Spot check: outcome typing
// --------------------------------------------------------------------------

#[test]
fn cert_outcome_pattern_matches() {
    let o = CertOutcome::Failed { reason: "x".into() };
    assert!(matches!(o, CertOutcome::Failed { .. }));
}
