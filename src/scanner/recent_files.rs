use crate::report::Report;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(dirs: &[String], days: u64, report: &mut Report) {
    report.section(&format!("Recently modified files (last {} days)", days));
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(days * 86400))
        .unwrap_or(UNIX_EPOCH);

    for d in dirs {
        let dir = Path::new(d);
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        if let Ok(modified) = meta.modified() {
                            if modified > cutoff {
                                report.log(format!("Recently modified: {}", path.display()));
                            }
                        }
                    }
                }
            }
        }
    }
}
