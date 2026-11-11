//! SecretHound - Ultra-fast static secrets scanner
//! Author: 0xBrdn

mod rules;

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

    // Rules are compiled once via OnceLock
    let rules = rules::get_rules();

    match cli.command {
        Commands::Scan { path } => {
            println!(
                "{} Scanning path: {} ({} rules loaded)",
                "[DEBUG]".yellow().bold(),
                path.display().to_string().cyan(),
                rules.len().to_string().green()
            );
        }
        Commands::InstallHook => {
            println!(
                "{} Installing git pre-commit hook...",
                "[DEBUG]".yellow().bold()
            );
        }
    }
}
