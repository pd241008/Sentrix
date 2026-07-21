use clap::Parser;
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
}

fn main() {
    let cli = Cli::parse();

    let opts = ScanOptions { quick: cli.quick };
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
