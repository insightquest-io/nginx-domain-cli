# nginx-domain-cli

CLI tool for managing nginx domain configurations with generation-based staging, atomic swap, and rollback.

## Usage

```bash
# List all managed domains
nginx-domain-cli list

# List domains for a specific app
nginx-domain-cli list myapp

# Show nginx status and config validity
nginx-domain-cli status

# Add a domain with SSL certs
nginx-domain-cli add myapp example.com \
  --cert /path/to/fullchain.pem \
  --key /path/to/key.pem \
  --proxy-conf /etc/nginx/myapp-proxy.conf

# Remove a domain
nginx-domain-cli remove myapp example.com

# Bring a domain up (stage -> test -> swap -> reload)
nginx-domain-cli up myapp example.com

# Bring a domain down (remove -> test -> swap -> reload)
nginx-domain-cli down myapp example.com

# Full reconciliation from desired state
nginx-domain-cli sync --desired domains.json

# Test nginx config
nginx-domain-cli test

# Rollback to previous generation
nginx-domain-cli rollback

# Health check
nginx-domain-cli health

# JSON output (all commands)
nginx-domain-cli --json list
```

## Configuration

Copy `config.example.toml` to `/etc/nginx-domain-cli/config.toml` and adjust paths.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | nginx -t failure |

`sync` JSON output additionally exposes a `status` field:

| status | exit |
|--------|------|
| `success` | 0 |
| `no_changes` | 0 |
| `cert_only_reloaded` | 0 |
| `cert_reload_failed` | 1 |
| `test_failed` | 2 |
| `test_failed_cert_reloaded` | 2 |
| `test_failed_cert_reload_failed` | 2 |

## ACME / Let's Encrypt — automatic cert issuance

When `[acme]` and `[dns_provider]` are both set in `config.toml`, `sync`
will issue and renew certificates for every desired domain *before*
computing the diff. The diff then sees the freshly-installed certs and
deploys nginx configs in the same cycle.

Only Cloudflare DNS-01 is currently supported.

### Prerequisites

1. **`acme.sh` installed with `--nocron`** — this is the single most
   important rule. `nginx-domain-cli` is the only renewal actor; an
   external cron from `acme.sh` would race our atomic-install path.

   ```bash
   curl https://get.acme.sh | sh -s email=ops@example.com --nocron
   ```

2. **`openssl`** — used for cert expiry parsing (`x509 -enddate`) and
   pubkey-based cert/key pair verification.

3. **Cloudflare API token** with the minimal scopes:
   - `Zone:Read`
   - `Zone.DNS:Edit`
   - **Include**: only the zone(s) hosting your domains
   - Optional: TTL and IP filter

   Profile → API Tokens → Create Token → Custom Token.

### Configuration

```toml
[acme]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
staging = false                    # true = LE staging (avoid prod rate limits)
renewal_window_days = 30
acme_sh_home = "/var/lib/nginx-domain-cli/.acme.sh"  # absolute path required
acme_bin = "/usr/local/bin/acme.sh"                   # default: PATH lookup
lock_dir = "/var/lock/nginx-domain-cli"

[dns_provider]
provider = "cloudflare"
# Either set api_token here, or export CF_Token in the environment.
# api_token = "..."
```

Both `[acme]` and `[dns_provider]` must be present together, or both
omitted (legacy mode where certs are pre-materialized by another actor).
Only `provider = "cloudflare"` is supported.

### How it works

On every `sync`:

1. **Account register** — `acme.sh --register-account` is called once
   per sync invocation. `acme.sh` is idempotent here.
2. **Per-domain loop** — for each desired domain, serially:
   - Acquire a non-blocking advisory file lock at
     `{lock_dir}/{domain}.acme.lock`. Held → reported as `acme_failed`
     (other domains continue) and retried next cycle.
   - Inspect the on-disk cert at `{ssl_base_dir}/{domain}/`. Parse
     `notAfter` via `openssl`. Verify the cert's pubkey matches the
     pubkey derived from `key.pem` (works for RSA and EC) — mismatch
     forces reissue.
   - Within `renewal_window_days` of expiry (or missing/malformed) →
     `acme.sh --issue --dns dns_cf -d <d> --home <home> --server <srv>`
     followed by `acme.sh --install-cert -d <d> --home <home>
     --key-file <ssl>/<d>/key.pem.new --fullchain-file
     <ssl>/<d>/fullchain.pem.new`. We then `chmod` (0644 / 0600),
     `fsync`, atomically rename to the live filenames, and `fsync`
     the parent directory.
3. **Diff + reload** — `compute_diff` runs over the (now valid) certs.
   If the diff has config changes, the existing stage-and-swap path
   handles reload. If it has *only* cert renewals (no config change),
   `nginx -s reload` is forced explicitly so the renewed cert is
   loaded into nginx's memory.

An empty desired state is valid and reconciles by removing all managed
live configs subject to `safety.max_removals_per_cycle`. Callers that
fetch desired state from an API are responsible for skipping `sync` when
the fetch fails. If the removal cap defers some configs, JSON output
includes `deferred_removals` and `domain_count` remains above zero; repeat
`sync` to continue draining in capped batches.

### Failure isolation

A per-domain ACME failure (CF token reject, rate limit, lock
contention) is reported in the JSON output's `acme_failed` array. The
domain keeps any existing valid cert and live config — the config
diffing path will preserve it via the `cert_validator` defense-in-depth
check. Other domains are unaffected.

### Logs

`RUST_LOG=info` is recommended for production. Per-domain outcomes
(`Existing` / `Issued` / `Renewed` / `Failed`) appear at INFO/DEBUG.

### Troubleshooting

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `acme.sh binary not found` | `acme.sh` missing or PATH wrong | install `acme.sh --nocron`, set `acme.acme_bin` to absolute path |
| `acme.sh --register-account exited with ...` | network or LE outage | check connectivity; try `acme.staging = true` |
| `acme.sh --issue` 403 | bad CF API token or zone scope | regenerate token with `Zone:Read + Zone.DNS:Edit` |
| `acme.sh --issue` rate limit | too many issues from prod LE | set `acme.staging = true` until validated |
| `lock held: ...` | concurrent sync invocation | wait for next cycle; safe to retry |
| `cert/key pair mismatch` | partial install crash window | next sync will reissue automatically |
| `cert_reload_failed` | `nginx -s reload` fails | check `nginx -t` and inspect nginx error log; certs are already on disk |

## Building

```bash
cargo build --release
```

## Cross-compile for Linux (musl)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```
