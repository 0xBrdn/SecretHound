//! Parallel file scanner for SecretHound
//! Author: 0xBrdn

use crate::rules::{get_rules, SecretRule};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

/// A single secret finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Absolute or relative path of the file
    pub file: PathBuf,
    /// 1-based line number
    pub line: usize,
    /// Rule name that matched
    pub rule_name: &'static str,
    /// Partially obfuscated secret (e.g. AKIA********1234)
    pub secret_obfuscated: String,
}

/// Obfuscate a secret: keep first 4 and last 4 characters, mask the middle.
fn obfuscate(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();

    if len <= 8 {
        // Too short: mask everything except first char
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
    // Quick extension-based filter (common binaries / media)
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
fn scan_file(path: &Path, rules: &[SecretRule]) -> Vec<Finding> {
    if is_likely_binary(path) {
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
            Err(_) => {
                // Non-UTF-8 line → treat whole file as binary-ish and stop
                return findings;
            }
        };

        // Skip extremely long lines (likely minified / generated)
        if line.len() > 10_000 {
            continue;
        }

        for rule in rules {
            for cap in rule.regex.captures_iter(&line) {
                // Prefer the first capture group if present, otherwise the whole match
                let secret = if let Some(m) = cap.get(1) {
                    m.as_str()
                } else if let Some(m) = cap.get(0) {
                    m.as_str()
                } else {
                    continue;
                };

                if secret.is_empty() {
                    continue;
                }

                findings.push(Finding {
                    file: path.to_path_buf(),
                    line: line_no,
                    rule_name: rule.name,
                    secret_obfuscated: obfuscate(secret),
                });
            }
        }
    }

    findings
}

/// Walk `root` with the `ignore` crate (respects .gitignore) then scan in parallel.
pub fn scan(root: &Path) -> Vec<Finding> {
    let rules = get_rules();

    // Collect candidate files (respecting .gitignore / .ignore / hidden, etc.)
    let mut paths: Vec<PathBuf> = Vec::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)          // still respect gitignore rules for hidden dirs if configured
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

    // Massive parallel scan (Rayon work-stealing – great on M4 Pro)
    paths
        .into_par_iter()
        .flat_map(|path| scan_file(&path, rules))
        .collect()
}
