use crate::config::{path_is_suspicious, suspicious_dirs, PERSISTENCE_SCAN_DIRS, SHELL_RC_FILES};
use crate::config_loader::UserConfig;
use crate::report::Report;
use std::fs;
use std::path::Path;

pub fn check_processes(report: &mut Report, _user_config: Option<&UserConfig>) {
    report.section("Suspicious process locations");
    let sus_dirs = suspicious_dirs();
    let proc_dir = Path::new("/proc");

    let entries = match fs::read_dir(proc_dir) {
        Ok(e) => e,
        Err(_) => {
            report.log("(i) Could not read /proc.");
            return;
        }
    };

    for entry in entries.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();
        if !fname_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid = fname_str.to_string();
        let exe_link = entry.path().join("exe");
        let exe_str = fs::read_link(&exe_link)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if exe_str.is_empty() {
            continue;
        }
        if path_is_suspicious(&exe_str, &sus_dirs) {
            report.flag(format!(
                "PID {} running from suspicious location: {}",
                pid, exe_str
            ));
        }
        if exe_str.contains("(deleted)") {
            report.flag(format!(
                "PID {} is executing a deleted binary: {} — common dropper/rootkit trick",
                pid, exe_str
            ));
        }
    }
}

pub fn check_persistence(report: &mut Report, user_config: Option<&UserConfig>) {
    report.section("Persistence (cron / systemd / shell rc)");

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

    let shell_rc_files: Vec<String> = user_config
        .and_then(|c| c.linux.as_ref())
        .and_then(|c| c.shell_rc_files.clone())
        .unwrap_or_else(|| SHELL_RC_FILES.iter().map(|s| s.to_string()).collect());

    let home = std::env::var("HOME").unwrap_or_default();
    for rc_name in &shell_rc_files {
        let rc = format!("{}/{}", home, rc_name);
        if let Ok(content) = fs::read_to_string(&rc) {
            let lower = content.to_lowercase();
            let dl_exec = (lower.contains("curl") || lower.contains("wget"))
                && (lower.contains("| bash") || lower.contains("| sh"));
            if dl_exec || lower.contains("base64 -d") || lower.contains("/dev/tcp/") {
                report.flag(format!(
                    "Suspicious download-and-execute / reverse-shell pattern in {}",
                    rc
                ));
            }
        }
    }

    let scan_dirs: Vec<String> = user_config
        .and_then(|c| c.linux.as_ref())
        .and_then(|c| c.persistence_scan_dirs.clone())
        .unwrap_or_else(|| PERSISTENCE_SCAN_DIRS.iter().map(|s| s.to_string()).collect());

    crate::scanner::recent_files::run(&scan_dirs, 3, report);
}
