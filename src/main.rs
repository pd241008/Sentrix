use clap::Parser;
use sentrix::config_loader;
use sentrix::{run, ScanOptions};

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

    if let Some(path) = &cli.out {
        if let Err(e) = std::fs::write(path, report.join()) {
            eprintln!("error: could not write report to {}: {}", path, e);
            std::process::exit(1);
        }
        eprintln!("report written to {} ({} findings)", path, report.findings);
    } else {
        print!("{}", report.join());
    }

    if report.findings > 0 {
        std::process::exit(2);
    }
}
