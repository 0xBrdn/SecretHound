//! SecretHound - Ultra-fast static secrets scanner
//! Author: 0xBrdn

mod rules;
mod scanner;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "secrethound")]
#[command(author = "0xBrdn")]
#[command(version = "0.1.0")]
#[command(about = "Ultra-fast static secrets scanner", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a path for secrets
    Scan {
        /// Path to scan (file or directory)
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
    /// Install the pre-commit git hook
    InstallHook,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            println!(
                "{} Scanning path: {}",
                "[DEBUG]".yellow().bold(),
                path.display().to_string().cyan()
            );

            let findings = scanner::scan(&path);

            println!(
                "{} Found {} potential secret(s)",
                "[DEBUG]".yellow().bold(),
                findings.len().to_string().green()
            );

            for f in &findings {
                println!(
                    "  {} {}:{}  [{}]  {}",
                    "→".red(),
                    f.file.display(),
                    f.line,
                    f.rule_name.yellow(),
                    f.secret_obfuscated.bright_black()
                );
            }
        }
        Commands::InstallHook => {
            println!(
                "{} Installing git pre-commit hook...",
                "[DEBUG]".yellow().bold()
            );
        }
    }
}
