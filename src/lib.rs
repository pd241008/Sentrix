pub mod config;
pub mod platform;
pub mod report;
pub mod scanner;

use report::Report;

pub struct ScanOptions {
    pub quick: bool,
}

pub fn run(opts: &ScanOptions) -> Report {
    let mut report = Report::new();

    scanner::processes::run(&mut report);
    scanner::persistence::run(&mut report);

    if !opts.quick {
        let dirs: Vec<String> = config::suspicious_dirs()
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        scanner::recent_files::run(&dirs, config::RECENT_FILE_DAYS, &mut report);
    }

    report
}
