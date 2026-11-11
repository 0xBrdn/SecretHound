//! SecretHound - Ultra-fast static secrets scanner
//! Author: 0xBrdn

mod rules;
mod scanner;

use clap::{Parser, Subcommand};
use colored::Colorize;
use comfy_table::presets::UTF8_ROUNDED;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};
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

fn print_findings_table(findings: &[scanner::Finding]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_ROUNDED)
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path } => {
            println!();
            println!(
                "{}  SecretHound · scanning {}",
                "▸".cyan().bold(),
                path.display().to_string().bold()
            );
            println!();

            let findings = scanner::scan(&path);

            if findings.is_empty() {
                println!(
                    "{}  No secrets found. Repository looks clean.",
                    "✔".green().bold()
                );
                println!();
            } else {
                print_findings_table(&findings);
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
