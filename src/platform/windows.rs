use crate::config::{
    suspicious_dirs, PERSISTENCE_REGISTRY_RUN_PATHS, SUSPICIOUS_AUTORUN_PATTERNS,
    SUSPICIOUS_POWERSHELL_PATTERNS, SUSPICIOUS_SERVICE_PATTERNS, SUSPICIOUS_TASK_ACTIONS,
    WMI_EVENT_CONSUMER_PATTERNS,
};
use crate::config_loader::UserConfig;
use crate::report::Report;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

pub fn check_processes(report: &mut Report, _user_config: Option<&UserConfig>) {
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

pub fn check_persistence(report: &mut Report, user_config: Option<&UserConfig>) {
    let autorun_patterns: Vec<String> = user_config
        .and_then(|c| c.windows.as_ref())
        .and_then(|c| c.suspicious_autorun_patterns.clone())
        .unwrap_or_else(|| SUSPICIOUS_AUTORUN_PATTERNS.iter().map(|s| s.to_string()).collect());

    let task_patterns: Vec<String> = user_config
        .and_then(|c| c.windows.as_ref())
        .and_then(|c| c.suspicious_task_actions.clone())
        .unwrap_or_else(|| SUSPICIOUS_TASK_ACTIONS.iter().map(|s| s.to_string()).collect());

    let powershell_patterns: Vec<String> = user_config
        .and_then(|c| c.windows.as_ref())
        .and_then(|c| c.suspicious_powershell_patterns.clone())
        .unwrap_or_else(|| {
            SUSPICIOUS_POWERSHELL_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });

    let service_patterns: Vec<String> = user_config
        .and_then(|c| c.windows.as_ref())
        .and_then(|c| c.suspicious_service_patterns.clone())
        .unwrap_or_else(|| SUSPICIOUS_SERVICE_PATTERNS.iter().map(|s| s.to_string()).collect());

    let wmi_patterns: Vec<String> = user_config
        .and_then(|c| c.windows.as_ref())
        .and_then(|c| c.wmi_event_consumer_patterns.clone())
        .unwrap_or_else(|| {
            WMI_EVENT_CONSUMER_PATTERNS
                .iter()
                .map(|s| s.to_string())
                .collect()
        });

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
                    if autorun_patterns
                        .iter()
                        .any(|pat| lower.contains(&pat.to_lowercase()))
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
                if task_patterns
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

    // Startup folder check
    report.section("Persistence (Startup folder)");
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    if !appdata.is_empty() {
        let startup_dir = std::path::Path::new(&appdata)
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if let Ok(entries) = std::fs::read_dir(&startup_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    report.log(format!("Startup item: {}", path.display()));
                }
            }
        }
    }

    // WMI event subscription check
    report.section("Persistence (WMI event subscriptions)");
    let output = Command::new("wmic")
        .args([
            "/namespace:\\\\root\\subscription",
            "path",
            "__EventConsumer",
            "get",
            "CommandLineTemplate",
            "/format:csv",
        ])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || line.contains("CommandLineTemplate") {
                continue;
            }
            let lower = line.to_lowercase();
            if wmi_patterns
                .iter()
                .any(|pat| lower.contains(&pat.to_lowercase()))
            {
                report.flag(format!("Suspicious WMI event consumer command: {}", line));
            } else {
                report.log(format!("WMI event consumer: {}", line));
            }
        }
    } else {
        report.log("(i) Could not query WMI event consumers.");
    }

    // Services check
    report.section("Persistence (Services)");
    let output = Command::new("wmic")
        .args(["service", "get", "Name,PathName,StartMode", "/format:csv"])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() || line.contains("PathName") {
                continue;
            }
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 3 {
                continue;
            }
            let name = fields[1].trim();
            let path_name = fields[2].trim();
            if path_name.is_empty() {
                continue;
            }
            let lower = path_name.to_lowercase();
            if service_patterns
                .iter()
                .any(|pat| lower.contains(&pat.to_lowercase()))
            {
                report.flag(format!(
                    "Suspicious service path: {} -> {}",
                    name, path_name
                ));
            } else {
                report.log(format!("Service: {} -> {}", name, path_name));
            }
        }
    } else {
        report.log("(i) Could not query WMI services.");
    }

    // PowerShell script block logging check
    report.section("Persistence (PowerShell script block logging)");
    let ps_script = "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 50 2>$null | ForEach-Object { $_.Properties[2].Value }";
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_script])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let mut suspicious_count = 0;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_lowercase();
            if powershell_patterns
                .iter()
                .any(|pat| lower.contains(&pat.to_lowercase()))
            {
                suspicious_count += 1;
                if suspicious_count <= 5 {
                    report.flag(format!(
                        "Suspicious PowerShell script block: {}",
                        &trimmed[..trimmed.len().min(200)]
                    ));
                }
            }
        }
        if suspicious_count > 5 {
            report.flag(format!(
                "... and {} more suspicious PowerShell script blocks",
                suspicious_count - 5
            ));
        } else if suspicious_count == 0 {
            report.log("(i) No suspicious PowerShell script blocks detected in recent events.");
        }
    } else {
        report.log("(i) Could not query PowerShell script block logging events.");
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
