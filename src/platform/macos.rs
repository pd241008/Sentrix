use crate::config::{launch_agent_dirs, path_is_suspicious, suspicious_dirs, SUSPICIOUS_PLIST_PATTERNS};
use crate::report::Report;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn check_processes(report: &mut Report) {
    report.section("Suspicious process locations");
    let sus_dirs = suspicious_dirs();

    let output = Command::new("ps")
        .args(["-axo", "pid,comm"])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if let Some((pid, comm)) = line.split_once(' ') {
                let comm = comm.trim();
                if path_is_suspicious(comm, &sus_dirs) {
                    report.flag(format!(
                        "PID {} running from suspicious location: {}",
                        pid, comm
                    ));
                }
            }
        }
    } else {
        report.log("(i) Could not run ps to enumerate processes.");
    }
}

pub fn check_persistence(report: &mut Report) {
    report.section("Persistence (LaunchAgents / LaunchDaemons)");

    for d in launch_agent_dirs() {
        let dir = Path::new(&d);
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "plist").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path) {
                        report.log(format!("LaunchAgent/Daemon: {}", path.display()));
                        let lower = content.to_lowercase();
                        if SUSPICIOUS_PLIST_PATTERNS
                            .iter()
                            .any(|pat| lower.contains(pat))
                        {
                            report.flag(format!(
                                "Suspicious plist (download/exec pattern): {}",
                                path.display()
                            ));
                        }
                    }
                }
            }
        }
    }

    crate::scanner::recent_files::run(
        &[
            "/Library/LaunchAgents".to_string(),
            "/Library/LaunchDaemons".to_string(),
        ],
        3,
        report,
    );
}
