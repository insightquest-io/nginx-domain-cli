//! Build script: embed the git commit short hash into the binary so
//! `nginx-domain-cli --version` reports `<name> <pkg>+<short7>` (SemVer
//! build metadata). The hash is sourced with priority:
//!
//!   1. `GIT_COMMIT_HASH` env var (preferred path; CI sets this from
//!      `${{ github.event.pull_request.head.sha || github.sha }}` so PR
//!      builds embed the actual branch HEAD instead of the synthesized
//!      merge commit).
//!   2. `git rev-parse HEAD` against the discovered `.git` directory
//!      (works for local `cargo build` from a checkout).
//!   3. `"unknown"` — only when running outside CI without a checkout
//!      (e.g. `cargo install` from a registry tarball). When `CI=true`
//!      we panic instead of silently shipping `+unknown` builds.
//!
//! The resulting hash is truncated to 7 chars at this consumer side so
//! the format contract holds regardless of upstream length (`github.sha`
//! is 40 chars; `git rev-parse HEAD` is also 40).
//!
//! Two `cargo:rustc-env=` lines are emitted:
//!   - `GIT_COMMIT_HASH` — the 7-char hash on its own.
//!   - `FULL_VERSION` — `<CARGO_PKG_VERSION>+<hash>`, consumed by
//!     `clap::Parser`'s `version = env!(...)`.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GIT_COMMIT_HASH");

    let pkg_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");

    let raw = env::var("GIT_COMMIT_HASH")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        });

    let raw = match raw {
        Some(h) => h,
        None => {
            // Fail fast in CI so a build that lost the hash never ships.
            // Local dev outside any git checkout (e.g. extracted tarball)
            // still gets a usable `+unknown` binary.
            if env::var("CI").is_ok() {
                panic!(
                    "GIT_COMMIT_HASH env var not provided and `git rev-parse HEAD` failed. \
                     Set GIT_COMMIT_HASH (e.g. ${{{{ github.sha }}}}) in CI or build from a git checkout."
                );
            }
            "unknown".to_string()
        }
    };

    // Enforce the short7 contract at the consumer side regardless of the
    // upstream length (env injection commonly carries the full 40-char SHA).
    let hash: String = raw.chars().take(7).collect();

    if let Some(git_dir) = find_git_dir() {
        // Track the active ref so a new commit invalidates the build.
        let head = git_dir.join("HEAD");
        if head.exists() {
            println!("cargo:rerun-if-changed={}", head.display());
            if let Ok(contents) = fs::read_to_string(&head) {
                if let Some(rest) = contents.trim().strip_prefix("ref: ") {
                    println!("cargo:rerun-if-changed={}", git_dir.join(rest).display());
                }
            }
        }
        // After `git gc`, refs migrate from loose files into packed-refs;
        // tracking only the loose path would silently freeze the embedded
        // hash on a subsequent `cargo build` after gc.
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join("packed-refs").display()
        );
    }

    println!("cargo:rustc-env=GIT_COMMIT_HASH={hash}");
    println!("cargo:rustc-env=FULL_VERSION={pkg_version}+{hash}");
}

/// Walk up from `CARGO_MANIFEST_DIR` looking for a `.git` entry.
///
/// Resolves both layouts:
///   - directory (`.git/`) — standard repo.
///   - file (`.git` containing `gitdir: <path>`) — git worktree or submodule.
///
/// Walking up handles cargo workspace members where `.git` lives in the
/// workspace root rather than the package directory.
fn find_git_dir() -> Option<PathBuf> {
    let mut dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    loop {
        let candidate = dir.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            let contents = fs::read_to_string(&candidate).ok()?;
            let rest = contents.trim().strip_prefix("gitdir: ")?;
            let resolved = PathBuf::from(rest);
            return Some(if resolved.is_absolute() {
                resolved
            } else {
                dir.join(resolved)
            });
        }
        if !dir.pop() {
            return None;
        }
    }
}
