# SecretHound

![Rust](https://img.shields.io/badge/Rust-Built_for_Performance-B7410E?style=flat-square&logo=rust&logoColor=white)
![Arch](https://img.shields.io/badge/Arch-ARM64%20%7C%20x86__64-00599C?style=flat-square)
![Type](https://img.shields.io/badge/Type-DevSecOps_CLI-10B981?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

An ultra-fast, multi-threaded static secrets scanner and pre-commit hook designed for DevSecOps pipelines.

SecretHound prevents hardcoded credentials (AWS keys, GitHub tokens, private keys, etc.) from being committed to version control. It acts as a strict "shift-left" security gate that runs locally on the developer's machine with minimal overhead.

## Core Features

* **High Performance** – Work-stealing multi-threading (`rayon`) scans thousands of files in milliseconds (optimised for Apple Silicon / ARM64).
* **Git-Aware Traversal** – Natively respects `.gitignore`, `.ignore` and common binary extensions. Never wastes time on `node_modules`, `target`, etc.
* **Allowlist / Baseline** – Support for `.secrethoundignore` to suppress known false positives (paths or exact secrets).
* **Safe Reporting** – Secrets are dynamically obfuscated before being printed (prevents the scanner itself from leaking credentials into CI logs).
* **CI/CD Ready** – Native JSON output (`--format json`) for easy integration with any pipeline.
* **Zero-Friction Hook** – One-command installation of a `pre-commit` hook that blocks dirty commits.
* **Standalone Binary** – Compiles to a single executable with no runtime dependencies.

## Installation

```bash
git clone https://github.com/0xBrdn/secrethound.git
cd secrethound
cargo build --release
```

The optimised binary is available at `target/release/secrethound`.

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

**JSON output (for CI):**

```bash
secrethound scan . --format json
```

```json
{
  "tool": "secrethound",
  "version": "0.2.0",
  "findings_count": 2,
  "findings": [
    {
      "file": "src/config.yml",
      "line": 12,
      "rule": "aws-access-key-id",
      "secret_obfuscated": "AKIA************CDEF"
    }
  ]
}
```

### Pre-Commit Hook

```bash
secrethound install-hook
```

This command:

1. Locates the `.git/hooks/` directory
2. Creates or safely appends to `pre-commit`
3. Writes the absolute path of the current binary
4. Sets executable permissions (`chmod +x`)

Subsequent `git commit` will automatically run a full scan. Secrets → exit code 1 → commit blocked.

### Allowlist (`.secrethoundignore`)

Place a `.secrethoundignore` file at the root of the repository:

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

## Supported Detection Rules

| Rule                    | Pattern / Description                          |
|-------------------------|------------------------------------------------|
| `aws-access-key-id`     | `AKIA...` (16 chars after prefix)              |
| `aws-secret-access-key` | Classic 40-char AWS secret                     |
| `github-pat`            | `ghp_...`                                      |
| `private-key`           | `-----BEGIN (RSA\|OPENSSH\|EC\|DSA) PRIVATE KEY-----` |
| `url-password`          | Credentials embedded in URLs                   |

All patterns are compiled once via `std::sync::OnceLock`.

## Architecture Notes

* Files are read line-by-line (`BufReader`) – memory efficient.
* Extremely long lines (> 10 kB) are skipped (minified / generated code).
* Binary and media extensions are filtered before any I/O.
* Non-UTF-8 files are safely skipped without crashing worker threads.
* Progress bar is sent to stderr so that `--format json` keeps stdout pure.

## Uninstall the Hook

```bash
rm .git/hooks/pre-commit
# or edit the file and remove the SecretHound block
```

## License

MIT License – Copyright (c) 2026 0xBrdn

See [LICENSE](LICENSE) for the full text.
