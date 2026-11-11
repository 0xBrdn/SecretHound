# SecretHound

![Rust](https://img.shields.io/badge/Rust-Built_for_Performance-B7410E?style=flat-square&logo=rust&logoColor=white)
![Arch](https://img.shields.io/badge/Arch-ARM64%20%7C%20x86__64-00599C?style=flat-square)
![Type](https://img.shields.io/badge/Type-DevSecOps_CLI-10B981?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-0.3.0-2563EB?style=flat-square)

An ultra-fast, multi-threaded static secrets scanner and pre-commit hook designed for DevSecOps pipelines.

SecretHound prevents hardcoded credentials from being committed to version control. It acts as a strict "shift-left" security gate that runs locally on the developer's machine with minimal overhead.

## Core Features

* **High Performance** – Work-stealing multi-threading (`rayon`) scans thousands of files in milliseconds (optimised for Apple Silicon / ARM64).
* **Git-Aware Traversal** – Natively respects `.gitignore`, `.ignore` and common binary extensions.
* **Allowlist / Baseline** – Support for `.secrethoundignore` to suppress known false positives (paths or exact secrets).
* **Safe Reporting** – Secrets are dynamically obfuscated before being printed.
* **CI/CD Ready** – Native JSON and **SARIF 2.1.0** output for GitHub Code Scanning, Azure DevOps, etc.
* **Zero-Friction Hook** – One-command installation of a `pre-commit` hook that blocks dirty commits.
* **Standalone Binary** – Compiles to a single executable with no runtime dependencies.

## Installation

```bash
git clone https://github.com/0xBrdn/secrethound.git
cd secrethound
cargo build --release
```

```bash
# Optional: install globally
sudo mv target/release/secrethound /usr/local/bin/
```

## Usage

### Manual Scan

```bash
secrethound scan /path/to/repository
```

**Text output (default):**

```
▸  SecretHound · scanning /path/to/repository

┌──────────────────┬──────┬───────────────────┬──────────────────────┐
│ File             │ Line │ Type              │ Secret (Obfuscated)  │
├──────────────────┼──────┼───────────────────┼──────────────────────┤
│ src/config.yml   │ 12   │ aws-access-key-id │ AKIA************CDEF │
│ tests/auth.py    │ 45   │ github-pat        │ ghp_************xyz1 │
└──────────────────┴──────┴───────────────────┴──────────────────────┘

⚠ 2 secret(s) detected. Review carefully before committing.
```

### JSON output (CI pipelines)

```bash
secrethound scan . --format json
```

### SARIF output (GitHub Code Scanning / SAST)

```bash
secrethound scan . --format sarif > results.sarif
```

The generated SARIF is compatible with GitHub Advanced Security, Azure DevOps, and most SARIF consumers.

### Pre-Commit Hook

```bash
secrethound install-hook
```

Subsequent `git commit` will automatically run a full scan. Secrets → exit code 1 → commit blocked.

### Allowlist (`.secrethoundignore`)

```
# Ignore entire directories or files
docs/examples/
test/fixtures/known-secrets.txt

# Accept a known false-positive secret (exact match)
ignore AKIAIOSFODNN7EXAMPLE
ignore ghp_exampletokenfortestingonly1234567890ab
```

## Exit Codes

| Code | Meaning                          |
|------|----------------------------------|
| 0    | No secrets found                 |
| 1    | Secrets detected (blocks commit) |
| 2    | Internal error (e.g. JSON fail)  |

## Supported Detection Rules (v0.3.0)

| Rule                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `aws-access-key-id`   | AWS Access Key ID (`AKIA...`)                    |
| `aws-secret-access-key` | AWS Secret Access Key                          |
| `github-pat`          | GitHub Personal Access Token (`ghp_...`)         |
| `github-oauth`        | GitHub OAuth Token (`gho_...`)                   |
| `github-app-token`    | GitHub App Token (`ghu_` / `ghs_`)               |
| `private-key`         | RSA / OpenSSH / EC / DSA private key headers     |
| `slack-token`         | Slack Token (`xox[baprs]-...`)                   |
| `slack-webhook`       | Slack Incoming Webhook URL                       |
| `stripe-api-key`      | Stripe API Key (`sk_live_` / `pk_live_` / test)  |
| `google-api-key`      | Google API Key (`AIza...`)                       |
| `twilio-api-key`      | Twilio API Key (`SK...`)                         |
| `jwt-token`           | JSON Web Token (JWT)                             |
| `generic-api-key`     | Generic `api_key` / `secret` / `token` assignment|
| `url-password`        | Credentials embedded inside a URL                |

All patterns are compiled once via `std::sync::OnceLock`.

## Architecture Notes

* Files are read line-by-line (`BufReader`) – memory efficient.
* Extremely long lines (> 10 kB) are skipped.
* Binary and media extensions are filtered before any I/O.
* Non-UTF-8 files are safely skipped.
* Progress bar is sent to stderr so that `--format json|sarif` keeps stdout pure.

## Uninstall the Hook

```bash
rm .git/hooks/pre-commit
# or edit the file and remove the SecretHound block
```

## Changelog (highlights)

### v0.3.0
- Added 9 new detection rules (Slack, Stripe, Google, Twilio, JWT, GitHub OAuth/App, generic API key)
- Added SARIF 2.1.0 export (`--format sarif`)
- Expanded unit tests

### v0.2.0
- Allowlist via `.secrethoundignore`
- JSON output (`--format json`)
- Unit tests for rules & obfuscation

### v0.1.0
- Initial release: scan + pre-commit hook + progress bar + table output

## License

MIT License – Copyright (c) 2026 0xBrdn

See [LICENSE](LICENSE) for the full text.
