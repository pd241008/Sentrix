use crate::config::{
    launch_agent_dirs, path_is_suspicious, suspicious_dirs, SUSPICIOUS_CRON_PATTERNS,
    SUSPICIOUS_LAUNCHCTL_OUTPUT, SUSPICIOUS_PLIST_PATTERNS,
};
use crate::report::Report;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn check_processes(report: &mut Report) {
    report.section("Suspicious process locations");
    let sus_dirs = suspicious_dirs();

    // Use pid,args for full executable paths (not just command name)
    let output = Command::new("ps").args(["-axo", "pid,args"]).output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if let Some((pid, args)) = line.split_once(' ') {
                let args = args.trim();
                // Extract the executable path (first token before any flags)
                let exe = args.split_whitespace().next().unwrap_or(args);
                if path_is_suspicious(exe, &sus_dirs) {
                    report.flag(format!(
                        "PID {} running from suspicious location: {}",
                        pid, exe
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

    // Collect on-disk plist paths
    let mut on_disk_plists: HashSet<String> = HashSet::new();

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
                        let path_str = path.display().to_string();
                        on_disk_plists.insert(path_str.clone());
                        report.log(format!("LaunchAgent/Daemon: {}", path_str));
                        let lower = content.to_lowercase();
                        if SUSPICIOUS_PLIST_PATTERNS
                            .iter()
                            .any(|pat| lower.contains(pat))
                        {
                            report.flag(format!(
                                "Suspicious plist (download/exec pattern): {}",
                                path_str
                            ));
                        }
                    }
                }
            }
        }
    }

    // Cross-reference with launchctl list
    report.section("Launchctl cross-reference");
    let output = Command::new("launchctl").args(["list"]).output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // launchctl list output: PID Status Label
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let label = parts[2];
            // Check for suspicious patterns in the label
            let lower = label.to_lowercase();
            if SUSPICIOUS_LAUNCHCTL_OUTPUT
                .iter()
                .any(|pat| lower.contains(&pat.to_lowercase()))
            {
                report.flag(format!(
                    "Suspicious launchctl label: {} (PID: {})",
                    label, parts[0]
                ));
            }
        }
    } else {
        report.log("(i) Could not run launchctl list.");
    }

    // Per-user crontab check
    report.section("Persistence (crontab)");
    let home = std::env::var("HOME").unwrap_or_default();
    if !home.is_empty() {
        let output = Command::new("crontab").args(["-l"]).output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                report.log(format!("crontab ({}): {}", home, trimmed));
                let lower = trimmed.to_lowercase();
                if SUSPICIOUS_CRON_PATTERNS
                    .iter()
                    .any(|pat| lower.contains(pat))
                {
                    report.flag(format!("Suspicious crontab entry: {}", trimmed));
                }
            }
        }
    }

    // Check /etc/crontab and /etc/cron.d for system-level cron
    if let Ok(content) = fs::read_to_string("/etc/crontab") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            report.log(format!("cron (/etc/crontab): {}", trimmed));
        }
    }
    if let Ok(entries) = fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    report.log(format!("cron ({}): {}", entry.path().display(), trimmed));
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
