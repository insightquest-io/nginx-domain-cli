#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

struct SyncRun {
    _tmp: tempfile::TempDir,
    live_dir: PathBuf,
    nginx_log: PathBuf,
    acme_log: Option<PathBuf>,
    output: Output,
}

fn run_empty_desired_sync() -> SyncRun {
    run_empty_desired_sync_with(&SyncScenario::default())
}

struct SyncScenario {
    live_domains: Vec<&'static str>,
    max_removals_per_cycle: usize,
    include_acme: bool,
}

impl Default for SyncScenario {
    fn default() -> Self {
        Self {
            live_domains: vec!["a.com", "b.com"],
            max_removals_per_cycle: 10,
            include_acme: false,
        }
    }
}

fn run_empty_desired_sync_with(scenario: &SyncScenario) -> SyncRun {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let live_dir = root.join("live");
    let staging_dir = root.join("staging");
    let prev_dir = root.join("prev");
    let ssl_dir = root.join("ssl");
    let temp_dir = root.join("tmp");
    let nginx_conf = root.join("nginx.conf");
    let nginx_log = root.join("nginx.log");
    let nginx_bin = root.join("mock-nginx.sh");
    let config_path = root.join("config.toml");
    let desired_path = root.join("desired.json");
    let acme_log = root.join("acme.log");
    let acme_bin = root.join("mock-acme.sh");
    let acme_home = root.join("acme-home");
    let acme_locks = root.join("acme-locks");

    fs::create_dir_all(&live_dir).unwrap();
    fs::create_dir_all(&ssl_dir).unwrap();
    fs::create_dir_all(&temp_dir).unwrap();
    fs::create_dir_all(&acme_home).unwrap();
    fs::create_dir_all(&acme_locks).unwrap();
    for domain in &scenario.live_domains {
        fs::write(
            live_dir.join(format!("{domain}.conf")),
            format!("# Managed by domain-agent\n{domain} config\n"),
        )
        .unwrap();
    }
    fs::write(
        &nginx_conf,
        format!(
            "events {{}}\nhttp {{ include {}/*.conf; }}\n",
            live_dir.display()
        ),
    )
    .unwrap();
    fs::write(&desired_path, "[]\n").unwrap();

    let mock_nginx = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "{log}"
if [ "$1" = "-t" ]; then
  exit 0
fi
if [ "$1" = "-s" ] && [ "$2" = "reload" ]; then
  exit 0
fi
exit 1
"#,
        log = nginx_log.display(),
    );
    fs::write(&nginx_bin, mock_nginx).unwrap();
    fs::set_permissions(&nginx_bin, fs::Permissions::from_mode(0o755)).unwrap();

    let acme_section = if scenario.include_acme {
        let mock_acme = format!(
            r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
exit 1
"#,
            log = acme_log.display(),
        );
        fs::write(&acme_bin, mock_acme).unwrap();
        fs::set_permissions(&acme_bin, fs::Permissions::from_mode(0o755)).unwrap();
        format!(
            r#"
[acme]
email = "ops@example.com"
staging = true
acme_sh_home = "{acme_home}"
acme_bin = "{acme_bin}"
lock_dir = "{acme_locks}"

[dns_provider]
provider = "cloudflare"
api_token = "test_dummy_cf_token"
"#,
            acme_home = acme_home.display(),
            acme_bin = acme_bin.display(),
            acme_locks = acme_locks.display(),
        )
    } else {
        String::new()
    };

    let config = format!(
        r#"[nginx]
bin = "{nginx_bin}"
live_dir = "{live_dir}"
staging_dir = "{staging_dir}"
prev_dir = "{prev_dir}"
ssl_base_dir = "{ssl_dir}"
nginx_conf = "{nginx_conf}"
temp_dir = "{temp_dir}"

[safety]
min_expected_domains = 1
max_removals_per_cycle = {max_removals_per_cycle}
{acme_section}
"#,
        nginx_bin = nginx_bin.display(),
        live_dir = live_dir.display(),
        staging_dir = staging_dir.display(),
        prev_dir = prev_dir.display(),
        ssl_dir = ssl_dir.display(),
        nginx_conf = nginx_conf.display(),
        temp_dir = temp_dir.display(),
        max_removals_per_cycle = scenario.max_removals_per_cycle,
        acme_section = acme_section,
    );
    fs::write(&config_path, config).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nginx-domain-cli"))
        .arg("--config")
        .arg(&config_path)
        .arg("--json")
        .arg("sync")
        .arg("--desired")
        .arg(&desired_path)
        .output()
        .expect("run nginx-domain-cli sync");

    SyncRun {
        _tmp: tmp,
        live_dir,
        nginx_log,
        acme_log: scenario.include_acme.then_some(acme_log),
        output,
    }
}

#[test]
fn sync_empty_desired_removes_all_live_vhosts() {
    let run = run_empty_desired_sync();

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    assert!(!run.live_dir.join("a.com.conf").exists());
    assert!(!run.live_dir.join("b.com.conf").exists());
}

#[test]
fn sync_empty_desired_triggers_nginx_reload() {
    let run = run_empty_desired_sync();

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let log = fs::read_to_string(&run.nginx_log).unwrap();
    assert!(log.lines().any(|line| line == "-s reload"));
}

#[test]
fn sync_empty_desired_returns_status_success() {
    let run = run_empty_desired_sync();

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    let payload: Value = serde_json::from_slice(&run.output.stdout).unwrap();
    assert_eq!(payload["action"], "sync");
    assert_eq!(payload["status"], "success");
    assert_eq!(payload["removed"], 2);
    assert_eq!(payload["domain_count"], 0);
}

#[test]
fn sync_empty_desired_skips_acme_when_configured() {
    let scenario = SyncScenario {
        include_acme: true,
        ..Default::default()
    };
    let run = run_empty_desired_sync_with(&scenario);

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    assert!(!run.live_dir.join("a.com.conf").exists());
    assert!(!run.live_dir.join("b.com.conf").exists());
    assert!(
        !run.acme_log.unwrap().exists(),
        "empty desired sync should not invoke acme.sh"
    );
}

#[test]
fn sync_empty_desired_respects_max_removals_per_cycle() {
    let scenario = SyncScenario {
        live_domains: vec!["a.com", "b.com", "c.com"],
        max_removals_per_cycle: 2,
        include_acme: false,
    };
    let run = run_empty_desired_sync_with(&scenario);

    assert!(
        run.output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.output.stderr)
    );
    assert!(!run.live_dir.join("a.com.conf").exists());
    assert!(!run.live_dir.join("b.com.conf").exists());
    assert!(run.live_dir.join("c.com.conf").exists());

    let payload: Value = serde_json::from_slice(&run.output.stdout).unwrap();
    assert_eq!(payload["status"], "success");
    assert_eq!(payload["removed"], 2);
    assert_eq!(payload["deferred_removals"], 1);
    assert_eq!(payload["domain_count"], 1);
}
