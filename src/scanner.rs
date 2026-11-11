//! Parallel file scanner for SecretHound
//! Author: 0xBrdn

use crate::rules::{get_rules, SecretRule};
use ignore::WalkBuilder;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A single secret finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Absolute or relative path of the file
    pub file: PathBuf,
    /// 1-based line number
    pub line: usize,
    /// Rule name that matched
    pub rule_name: &'static str,
    /// Partially obfuscated secret (e.g. AKIA********1234)
    pub secret_obfuscated: String,
    /// Original secret (kept internal / for allowlist matching, not serialized by default)
    #[serde(skip)]
    pub secret_raw: String,
}

/// Allowlist loaded from `.secrethoundignore`.
#[derive(Debug, Default)]
pub struct Allowlist {
    /// Path prefixes / exact paths to skip entirely
    pub ignored_paths: Vec<String>,
    /// Exact secrets (raw) that are accepted as false positives
    pub allowed_secrets: HashSet<String>,
}

impl Allowlist {
    /// Load `.secrethoundignore` from the given root directory.
    /// Format:
    ///   # comment
    ///   path/to/ignore          → skip this path (prefix match)
    ///   ignore SECRET_VALUE     → allow this exact secret
    pub fn load(root: &Path) -> Self {
        let path = root.join(".secrethoundignore");
        let mut allowlist = Allowlist::default();

        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => return allowlist,
        };

        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(secret) = line.strip_prefix("ignore ") {
                let secret = secret.trim();
                if !secret.is_empty() {
                    allowlist.allowed_secrets.insert(secret.to_string());
                }
            } else {
                // Treat as path/prefix to ignore
                allowlist.ignored_paths.push(line.to_string());
            }
        }

        allowlist
    }

    fn is_path_ignored(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.ignored_paths.iter().any(|p| path_str.contains(p))
    }

    fn is_secret_allowed(&self, secret: &str) -> bool {
        self.allowed_secrets.contains(secret)
    }
}

/// Obfuscate a secret: keep first 4 and last 4 characters, mask the middle.
pub fn obfuscate(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();

    if len <= 8 {
        if len == 0 {
            return String::new();
        }
        return format!("{}{}", chars[0], "*".repeat(len.saturating_sub(1)));
    }

    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
    let mask_len = len - 8;
    format!("{}{}{}", prefix, "*".repeat(mask_len), suffix)
}

/// Returns true if the path looks like a binary we should skip.
fn is_likely_binary(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_lowercase();
        matches!(
            ext.as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "ico" | "bmp"
                | "pdf" | "zip" | "gz" | "tar" | "bz2" | "7z" | "rar"
                | "exe" | "dll" | "so" | "dylib" | "bin" | "o" | "a"
                | "class" | "jar" | "war" | "pyc" | "pyo" | "wasm"
                | "mp3" | "mp4" | "avi" | "mkv" | "mov" | "woff" | "woff2"
                | "ttf" | "otf" | "eot"
        )
    } else {
        false
    }
}

/// Scan a single file for secrets. Returns findings or empty vec on error / binary.
fn scan_file(path: &Path, rules: &[SecretRule], allowlist: &Allowlist) -> Vec<Finding> {
    if is_likely_binary(path) || allowlist.is_path_ignored(path) {
        return Vec::new();
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut findings = Vec::new();

    for (idx, line_result) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = match line_result {
            Ok(l) => l,
            Err(_) => return findings, // non-UTF-8 → stop this file
        };

        if line.len() > 10_000 {
            continue;
        }

        for rule in rules {
            for cap in rule.regex.captures_iter(&line) {
                let secret = if let Some(m) = cap.get(1) {
                    m.as_str()
                } else if let Some(m) = cap.get(0) {
                    m.as_str()
                } else {
                    continue;
                };

                if secret.is_empty() || allowlist.is_secret_allowed(secret) {
                    continue;
                }

                findings.push(Finding {
                    file: path.to_path_buf(),
                    line: line_no,
                    rule_name: rule.name,
                    secret_obfuscated: obfuscate(secret),
                    secret_raw: secret.to_string(),
                });
            }
        }
    }

    findings
}

/// Walk `root` with the `ignore` crate then scan in parallel with a live progress bar.
/// Progress is written to stderr so that `--format json` can keep stdout clean.
pub fn scan(root: &Path, quiet: bool) -> Vec<Finding> {
    let rules = get_rules();
    let allowlist = Allowlist::load(root);

    // Collect candidate files (respects .gitignore / .ignore)
    let mut paths: Vec<PathBuf> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            paths.push(entry.into_path());
        }
    }

    let total = paths.len() as u64;

    let pb = if quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta}) {msg}",
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏  ")
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb.set_message("scanning…");
        pb
    };

    // Massive parallel scan (Rayon work-stealing – optimised for M4 Pro)
    let findings: Vec<Finding> = paths
        .into_par_iter()
        .flat_map(|path| {
            let result = scan_file(&path, rules, &allowlist);
            pb.inc(1);
            result
        })
        .collect();

    if !quiet {
        pb.finish_and_clear();
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscate_long_secret() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let obf = obfuscate(secret);
        assert!(obf.starts_with("AKIA"));
        assert!(obf.ends_with("MPLE"));
        assert!(obf.contains('*'));
        assert_eq!(obf.len(), secret.len());
    }

    #[test]
    fn obfuscate_short_secret() {
        let secret = "short";
        let obf = obfuscate(secret);
        assert_eq!(obf, "s****");
    }

    #[test]
    fn obfuscate_empty() {
        assert_eq!(obfuscate(""), "");
    }

    #[test]
    fn allowlist_path_and_secret() {
        let mut al = Allowlist::default();
        al.ignored_paths.push("fixtures/".to_string());
        al.allowed_secrets.insert("AKIAIOSFODNN7EXAMPLE".to_string());

        assert!(al.is_path_ignored(Path::new("src/fixtures/test.txt")));
        assert!(al.is_secret_allowed("AKIAIOSFODNN7EXAMPLE"));
        assert!(!al.is_secret_allowed("AKIAOTHERKEY123456"));
    }
}
