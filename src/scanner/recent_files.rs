use crate::report::Report;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum recursion depth when walking scan directories. Prevents runaway
/// traversals through deeply nested (or adversarially constructed) trees.
const MAX_SCAN_DEPTH: usize = 4;

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
        scan_dir(dir, cutoff, 0, report);
    }
}

fn scan_dir(dir: &Path, cutoff: SystemTime, depth: usize, report: &mut Report) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            // Skip symlinks entirely: a planted link could point the walk at
            // arbitrary locations (e.g. re-scan /etc recursively).
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_file() {
                if let Ok(modified) = meta.modified() {
                    if modified > cutoff {
                        report.log(format!("Recently modified: {}", path.display()));
                    }
                }
            } else if meta.is_dir() {
                scan_dir(&path, cutoff, depth + 1, report);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_finds_files_in_subdirectories() {
        let tmp = std::env::temp_dir().join("sentrix_recursive_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let nested = tmp.join("level1").join("level2");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("deep.txt"), "x").unwrap();

        let mut report = Report::new();
        run(&[tmp.to_string_lossy().to_string()], 1, &mut report);

        let out = report.join();
        assert!(
            out.contains("deep.txt"),
            "nested file should be reported, got: {}",
            out
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_depth_cap_stops_walking() {
        // Build a chain deeper than MAX_SCAN_DEPTH; the innermost file must
        // not be reported.
        let tmp = std::env::temp_dir().join("sentrix_depth_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut cur = tmp.clone();
        for i in 0..MAX_SCAN_DEPTH + 2 {
            cur = cur.join(format!("d{}", i));
        }
        std::fs::create_dir_all(&cur).unwrap();
        std::fs::write(cur.join("too_deep.txt"), "x").unwrap();

        let mut report = Report::new();
        run(&[tmp.to_string_lossy().to_string()], 1, &mut report);

        let out = report.join();
        assert!(
            !out.contains("too_deep.txt"),
            "file beyond depth cap must not be reported"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
