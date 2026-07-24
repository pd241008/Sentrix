pub mod config;
pub mod config_loader;
pub mod platform;
pub mod report;
pub mod scanner;

use config_loader::UserConfig;
use report::Report;

pub struct ScanOptions {
    pub quick: bool,
    pub user_config: Option<UserConfig>,
}

pub fn run(opts: &ScanOptions) -> Report {
    let mut report = Report::new();

    scanner::processes::run(&mut report, opts.user_config.as_ref());
    scanner::persistence::run(&mut report, opts.user_config.as_ref());

    if !opts.quick {
        let dirs: Vec<String> = config::suspicious_dirs()
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let days = opts
            .user_config
            .as_ref()
            .and_then(|c| c.recent_file_days)
            .unwrap_or(config::RECENT_FILE_DAYS);
        scanner::recent_files::run(&dirs, days, &mut report);
    }

    report
}
