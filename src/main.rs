//! SecretHound - Ultra-fast static secrets scanner
//! Author: 0xBrdn

mod rules;
mod scanner;

use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{self, Command};

#[derive(Parser)]
#[command(name = "secrethound")]
#[command(author = "0xBrdn")]
#[command(version = "0.3.0")]
#[command(about = "Ultra-fast static secrets scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// Human-readable table (default)
    Text,
    /// Structured JSON for CI/CD
    Json,
    /// SARIF 2.1.0 for GitHub Code Scanning / SAST tools
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a path for secrets
    Scan {
        /// Path to scan (file or directory)
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Install the pre-commit git hook
    InstallHook,
}

// ── JSON report ──────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonReport {
    tool: &'static str,
    version: &'static str,
    findings_count: usize,
    findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
struct JsonFinding {
    file: String,
    line: usize,
    rule: &'static str,
    secret_obfuscated: String,
}

// ── SARIF 2.1.0 (minimal but valid subset) ───────────────────────────────────

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    information_uri: &'static str,
    version: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    default_configuration: SarifDefaultConfig,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifDefaultConfig {
    level: &'static str,
}

#[derive(Serialize)]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    start_line: usize,
}

fn print_findings_table(findings: &[scanner::Finding]) {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("File")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Line")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Type")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
            Cell::new("Secret (Obfuscated)")
                .add_attribute(Attribute::Bold)
                .fg(Color::Cyan),
        ]);

    for f in findings {
        table.add_row(vec![
            Cell::new(f.file.display().to_string()),
            Cell::new(f.line.to_string()),
            Cell::new(f.rule_name).fg(Color::Yellow),
            Cell::new(&f.secret_obfuscated).fg(Color::DarkGrey),
        ]);
    }

    println!();
    println!("{}", table);
    println!();
    println!(
        "{} {} secret(s) detected. Review carefully before committing.",
        "⚠".red().bold(),
        findings.len().to_string().red().bold()
    );
}

fn emit_json(findings: &[scanner::Finding]) {
    let report = JsonReport {
        tool: "secrethound",
        version: "0.3.0",
        findings_count: findings.len(),
        findings: findings
            .iter()
            .map(|f| JsonFinding {
                file: f.file.display().to_string(),
                line: f.line,
                rule: f.rule_name,
                secret_obfuscated: f.secret_obfuscated.clone(),
            })
            .collect(),
    };

    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Failed to serialize JSON report: {}", e);
            process::exit(2);
        }
    }
}

fn emit_sarif(findings: &[scanner::Finding]) {
    // Collect unique rule ids present in the findings
    let mut rule_ids: Vec<&str> = findings.iter().map(|f| f.rule_name).collect();
    rule_ids.sort_unstable();
    rule_ids.dedup();

    let rules: Vec<SarifRule> = rule_ids
        .iter()
        .map(|id| SarifRule {
            id: id.to_string(),
            short_description: SarifMessage {
                text: format!("Secret detected by rule '{}'", id),
            },
            full_description: SarifMessage {
                text: format!(
                    "SecretHound rule '{}' matched a potential credential or secret.",
                    id
                ),
            },
            default_configuration: SarifDefaultConfig { level: "error" },
        })
        .collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| SarifResult {
            rule_id: f.rule_name.to_string(),
            level: "error",
            message: SarifMessage {
                text: format!(
                    "Potential secret ({}) found: {}",
                    f.rule_name, f.secret_obfuscated
                ),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file.display().to_string(),
                    },
                    region: SarifRegion {
                        start_line: f.line,
                    },
                },
            }],
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "SecretHound",
                    information_uri: "https://github.com/0xBrdn/secrethound",
                    version: "0.3.0",
                    rules,
                },
            },
            results,
        }],
    };

    match serde_json::to_string_pretty(&log) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Failed to serialize SARIF report: {}", e);
            process::exit(2);
        }
    }
}

/// Resolve the .git directory (works from any subdirectory of a repo).
fn find_git_dir() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .map_err(|e| format!("Failed to run git: {}. Is git installed?", e))?;

    if !output.status.success() {
        return Err(
            "Not inside a Git repository.\n  → Run this command from the root (or any subfolder) of a git repo.".to_string(),
        );
    }

    let git_dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let path = PathBuf::from(git_dir);

    if path.is_relative() {
        let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
        Ok(cwd.join(path))
    } else {
        Ok(path)
    }
}

/// Install (or update) the pre-commit hook that runs SecretHound.
fn install_hook() -> Result<(), String> {
    let git_dir = find_git_dir()?;
    let hooks_dir = git_dir.join("hooks");
    let hook_path = hooks_dir.join("pre-commit");

    fs::create_dir_all(&hooks_dir).map_err(|e| format!("Cannot create hooks dir: {}", e))?;

    let exe = std::env::current_exe()
        .map_err(|e| format!("Cannot resolve current executable: {}", e))?;
    let exe_str = exe.to_string_lossy();

    let hook_content = format!(
        r#"#!/bin/sh
# SecretHound pre-commit hook – blocks commits containing secrets
# Generated by: secrethound install-hook
# Author: 0xBrdn

set -e

echo "SecretHound · pre-commit scan…"
"{exe_str}" scan .

"#
    );

    if hook_path.exists() {
        let existing = fs::read_to_string(&hook_path).unwrap_or_default();
        if existing.contains("SecretHound pre-commit hook") {
            println!(
                "{}  SecretHound pre-commit hook is already installed.",
                "✔".green().bold()
            );
            println!("    Location: {}", hook_path.display());
            return Ok(());
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(&hook_path)
            .map_err(|e| format!("Cannot open existing hook: {}", e))?;

        writeln!(file).map_err(|e| e.to_string())?;
        writeln!(file, "# --- SecretHound (appended) ---").map_err(|e| e.to_string())?;
        write!(file, "{}", hook_content).map_err(|e| e.to_string())?;

        println!(
            "{}  Appended SecretHound to existing pre-commit hook.",
            "✔".green().bold()
        );
    } else {
        fs::write(&hook_path, hook_content)
            .map_err(|e| format!("Cannot write hook file: {}", e))?;
        println!("{}  Created new pre-commit hook.", "✔".green().bold());
    }

    let mut perms = fs::metadata(&hook_path)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms).map_err(|e| e.to_string())?;

    println!("    Location : {}", hook_path.display());
    println!("    Binary   : {}", exe_str);
    println!();
    println!(
        "{}  The hook will now run automatically on every `git commit`.",
        "ℹ".cyan()
    );
    println!("    If secrets are detected, the commit will be blocked (exit code 1).");
    println!();

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, format } => {
            let quiet = matches!(format, OutputFormat::Json | OutputFormat::Sarif);

            if !quiet {
                println!();
                println!(
                    "{}  SecretHound · scanning {}",
                    "▸".cyan().bold(),
                    path.display().to_string().bold()
                );
                println!();
            }

            let findings = scanner::scan(&path, quiet);

            match format {
                OutputFormat::Json => {
                    emit_json(&findings);
                    process::exit(if findings.is_empty() { 0 } else { 1 });
                }
                OutputFormat::Sarif => {
                    emit_sarif(&findings);
                    process::exit(if findings.is_empty() { 0 } else { 1 });
                }
                OutputFormat::Text => {
                    if findings.is_empty() {
                        println!(
                            "{}  No secrets found. Repository looks clean.",
                            "✔".green().bold()
                        );
                        println!();
                        process::exit(0);
                    } else {
                        print_findings_table(&findings);
                        process::exit(1);
                    }
                }
            }
        }
        Commands::InstallHook => {
            println!();
            match install_hook() {
                Ok(()) => {}
                Err(msg) => {
                    eprintln!("{}  {}", "✖".red().bold(), msg.red());
                    eprintln!();
                    process::exit(1);
                }
            }
        }
    }
}
