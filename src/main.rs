use clap::Parser;

#[derive(Parser)]
#[command(name = "sentrix", version, about = "Lightweight heuristic malware triage scanner")]
pub struct Cli {
    /// Run a quick scan (skip recently modified files check)
    #[arg(short, long)]
    pub quick: bool,

    /// Write report to a file instead of stdout
    #[arg(short, long)]
    pub out: Option<String>,
}

fn main() {
    let _cli = Cli::parse();
    println!("sentrix — skeleton");
}
