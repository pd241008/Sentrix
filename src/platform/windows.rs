use crate::config::{
    suspicious_dirs, PERSISTENCE_REGISTRY_RUN_PATHS, SUSPICIOUS_AUTORUN_PATTERNS,
    SUSPICIOUS_TASK_ACTIONS,
};
use crate::report::Report;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

pub fn check_processes(report: &mut Report) {
    report.section("Suspicious process locations");
    let sus_dirs = suspicious_dirs();

    // Try wmic first for full executable paths
    let output = Command::new("wmic")
        .args([
            "process",
            "get",
            "Name,ExecutablePath,ProcessId",
            "/format:csv",
        ])
        .output();

    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // CSV format: Node,ExecutablePath,Name,ProcessId
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 4 {
                continue;
            }
            let exe_path = fields[1].trim();
            let name = fields[2].trim();
            let pid = fields[3].trim();

            if exe_path.is_empty() || exe_path == "ExecutablePath" {
                continue;
            }

            for d in &sus_dirs {
                if let Some(dstr) = d.to_str() {
                    if exe_path.to_lowercase().contains(&dstr.to_lowercase()) {
                        report.flag(format!(
                            "PID {} ({}) running from suspicious location: {}",
                            pid, name, exe_path
                        ));
                    }
                }
            }
        }
    } else {
        // Fallback to tasklist if wmic is unavailable
        report.log("(i) wmic unavailable, falling back to tasklist.");
        let output = Command::new("tasklist").args(["/v", "/fo", "csv"]).output();
        if let Ok(out) = output {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split("\",\"").collect();
                if fields.is_empty() {
                    continue;
                }
                let name = fields[0].trim_matches('"');
                for d in &sus_dirs {
                    if let Some(dstr) = d.to_str() {
                        if line.to_lowercase().contains(&dstr.to_lowercase()) {
                            report.flag(format!(
                                "Process line references suspicious path: {} ({})",
                                name, line
                            ));
                        }
                    }
                }
            }
        } else {
            report.log("(i) Could not run tasklist to enumerate processes.");
        }
    }
}

pub fn check_persistence(report: &mut Report) {
    report.section("Persistence (Registry Run keys)");
    let hives: [(&RegKey, &str); 2] = [
        (&RegKey::predef(HKEY_CURRENT_USER), "HKCU"),
        (&RegKey::predef(HKEY_LOCAL_MACHINE), "HKLM"),
    ];

    for (hive, hive_name) in &hives {
        for rp in PERSISTENCE_REGISTRY_RUN_PATHS {
            if let Ok(key) = hive.open_subkey(rp) {
                for (name, value) in key.enum_values().flatten() {
                    let val_str = format!("{:?}", value);
                    report.log(format!("{}\\{}: {} = {}", hive_name, rp, name, val_str));
                    let lower = val_str.to_lowercase();
                    if SUSPICIOUS_AUTORUN_PATTERNS
                        .iter()
                        .any(|pat| lower.contains(pat))
                    {
                        report.flag(format!(
                            "Suspicious autorun entry in {}\\{}: {} = {}",
                            hive_name, rp, name, val_str
                        ));
                    }
                }
            }
        }
    }

    report.section("Persistence (Scheduled Tasks)");
    let output = Command::new("schtasks")
        .args(["/query", "/fo", "list", "/v"])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let mut current_task = String::new();
        let mut current_action = String::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("TaskName:") {
                current_task = val.trim().to_string();
            }
            if let Some(val) = line.strip_prefix("Task To Run:") {
                current_action = val.trim().to_string();
                let lower = current_action.to_lowercase();
                if SUSPICIOUS_TASK_ACTIONS
                    .iter()
                    .any(|pat| lower.contains(&pat.to_lowercase()))
                {
                    report.flag(format!(
                        "Suspicious scheduled task action: {} -> {}",
                        current_task, current_action
                    ));
                } else {
                    report.log(format!(
                        "Scheduled task: {} -> {}",
                        current_task, current_action
                    ));
                }
            }
        }
    } else {
        report.log("(i) Could not run schtasks to enumerate scheduled tasks.");
    }

    crate::scanner::recent_files::run(
        &[
            "C:\\Windows\\System32\\Tasks".to_string(),
            "C:\\Users\\Public".to_string(),
        ],
        3,
        report,
    );
}
