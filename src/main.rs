use clap::Parser;
use sentrix::config_loader;
use sentrix::report::Report;
use sentrix::{diff, run, ScanOptions};

#[derive(Parser)]
#[command(
    name = "sentrix",
    version,
    about = "Lightweight heuristic malware triage scanner"
)]
pub struct Cli {
    /// Run a quick scan (skip recently modified files check)
    #[arg(short, long)]
    pub quick: bool,

    /// Write report to a file instead of stdout
    #[arg(short, long)]
    pub out: Option<String>,

    /// Output report as JSON instead of plain text
    #[arg(long)]
    pub json: bool,

    /// Compare scan results against a previous JSON report
    #[arg(long, value_name = "FILE")]
    pub diff: Option<String>,

    /// Path to TOML configuration file with custom detection patterns
    #[arg(short, long)]
    pub config: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Load user config if provided
    let user_config = match &cli.config {
        Some(path) => {
            let config_path = std::path::Path::new(path);
            match config_loader::load_config(config_path) {
                Ok(config) => {
                    eprintln!("loaded config from {}", path);
                    Some(config)
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    let opts = ScanOptions {
        quick: cli.quick,
        user_config,
    };
    let report = run(&opts);

    if let Some(prev_path) = &cli.diff {
        let previous = match load_previous_report(prev_path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {}", e);
                std::process::exit(1);
            }
        };
        let result = diff::compute(&previous, &report);
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&result).unwrap_or_default()
            );
        } else {
            print!("{}", result.to_text());
        }
        std::process::exit(if result.new_findings.is_empty() { 0 } else { 2 });
    }

    if let Some(path) = &cli.out {
        let content = if cli.json {
            report.to_json()
        } else {
            report.join()
        };
        if let Err(e) = std::fs::write(path, content) {
            eprintln!("error: could not write report to {}: {}", path, e);
            std::process::exit(1);
        }
        eprintln!(
            "report written to {} ({} findings)",
            path,
            report.findings()
        );
    } else if cli.json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.join());
    }

    if report.findings() > 0 {
        std::process::exit(2);
    }
}

fn load_previous_report(path: &str) -> Result<Report, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read previous report {}: {}", path, e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("could not parse previous report {}: {}", path, e))
}
