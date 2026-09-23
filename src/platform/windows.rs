use crate::config::{
    suspicious_dirs, PERSISTENCE_REGISTRY_RUN_PATHS, RECENT_FILE_DAYS, SUSPICIOUS_AUTORUN_PATTERNS,
    SUSPICIOUS_POWERSHELL_PATTERNS, SUSPICIOUS_SERVICE_PATTERNS, SUSPICIOUS_TASK_ACTIONS,
    WMI_EVENT_CONSUMER_PATTERNS,
};
use crate::config_loader::UserConfig;
use crate::platform::win_helpers::{decode_output, CsvTable};
use crate::report::Report;
use std::process::Command;
use winreg::enums::*;
use winreg::RegKey;

/// Run an external command and return its decoded stdout, or `None` if the
/// program could not be launched (missing, blocked, ...).
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .map(|out| decode_output(&out.stdout))
}

/// Run a PowerShell command; returns decoded stdout or `None`.
fn run_ps(ps_script: &str) -> Option<String> {
    run_capture(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", ps_script],
    )
}

/// Run `wmic` and fall back to an equivalent PowerShell CIM query when wmic
/// is unavailable (deprecated/removed on recent Windows 11 builds).
fn run_wmic_or_ps(wmic_args: &[&str], ps_script: &str) -> Option<String> {
    if let Some(text) = run_capture("wmic", wmic_args) {
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    run_ps(ps_script)
}

/// Extract a full executable path from a tasklist `/v` row, which shows
/// only the image name — resolve it against the Path environment variable.
fn resolve_image_name(name: &str) -> String {
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    String::new()
}

pub fn check_processes(report: &mut Report, _user_config: Option<&UserConfig>) {
    report.section("Suspicious process locations");
    let sus_dirs = suspicious_dirs();

    // Prefer wmic for full executable paths; fall back to PowerShell CIM
    // (Get-CimInstance) on builds where wmic is deprecated/removed, then to
    // tasklist as a last resort.
    let text = run_wmic_or_ps(
        &[
            "process",
            "get",
            "Name,ExecutablePath,ProcessId",
            "/format:csv",
        ],
        "Get-CimInstance Win32_Process | Where-Object ExecutablePath | \
         Select-Object ExecutablePath,Name,ProcessId | ConvertTo-Csv -NoTypeInformation",
    );

    if let Some(text) = text {
        let table = CsvTable::parse(&text);
        let mut matched = 0usize;
        for row in &table.rows {
            let Some(exe_path) = table.get(row, "executablepath") else {
                continue;
            };
            if exe_path.is_empty() {
                continue;
            }
            let name = table.get(row, "name").unwrap_or("unknown");
            let pid = table.get(row, "processid").unwrap_or("?");

            if sus_dirs
                .iter()
                .filter_map(|d| d.to_str())
                .any(|d| exe_path.to_lowercase().contains(&d.to_lowercase()))
            {
                report.flag(format!(
                    "PID {} ({}) running from suspicious location: {}",
                    pid, name, exe_path
                ));
                matched += 1;
            }
        }
        if matched == 0 {
            report.log("(i) No processes running from suspicious locations.");
        }
    } else {
        // Last-resort fallback: tasklist has no ExecutablePath column, so we
        // scan for suspicious path fragments and resolve image names via PATH.
        report.log("(i) wmic/CIM unavailable, falling back to tasklist.");
        if let Some(text) = run_capture("tasklist", &["/v", "/fo", "csv"]) {
            let mut matched = 0usize;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let fields = crate::platform::win_helpers::parse_csv_line(line);
                let name = fields.first().map(|s| s.trim()).unwrap_or("unknown");
                let sus_hit = sus_dirs
                    .iter()
                    .filter_map(|d| d.to_str())
                    .find(|d| line.to_lowercase().contains(&d.to_lowercase()));
                if let Some(d) = sus_hit {
                    let resolved = resolve_image_name(name);
                    if resolved.is_empty() {
                        report.flag(format!(
                            "Process image name references suspicious dir ({}): {}",
                            d, name
                        ));
                    } else {
                        report.flag(format!(
                            "Process running from suspicious location: {} ({})",
                            resolved, name
                        ));
                    }
                    matched += 1;
                }
            }
            if matched == 0 {
                report.log("(i) No processes matched suspicious locations via tasklist.");
            }
        } else {
            report.log("(i) Could not run tasklist to enumerate processes.");
        }
    }
}

pub fn check_persistence(report: &mut Report, user_config: Option<&UserConfig>) {
    let win_cfg = user_config.and_then(|c| c.windows.as_ref());

    let autorun_patterns = win_cfg
        .and_then(|c| c.suspicious_autorun_patterns.clone())
        .unwrap_or_else(|| strings(SUSPICIOUS_AUTORUN_PATTERNS));
    let task_patterns = win_cfg
        .and_then(|c| c.suspicious_task_actions.clone())
        .unwrap_or_else(|| strings(SUSPICIOUS_TASK_ACTIONS));
    let powershell_patterns = win_cfg
        .and_then(|c| c.suspicious_powershell_patterns.clone())
        .unwrap_or_else(|| strings(SUSPICIOUS_POWERSHELL_PATTERNS));
    let service_patterns = win_cfg
        .and_then(|c| c.suspicious_service_patterns.clone())
        .unwrap_or_else(|| strings(SUSPICIOUS_SERVICE_PATTERNS));
    let wmi_patterns = win_cfg
        .and_then(|c| c.wmi_event_consumer_patterns.clone())
        .unwrap_or_else(|| strings(WMI_EVENT_CONSUMER_PATTERNS));

    // Registry Run keys (winreg crate — no external process needed).
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

    // Scheduled tasks: wmic is not useful here; schtasks first, PowerShell
    // Get-ScheduledTask fallback (works on builds where schtasks output
    // formatting is localized or the tool is restricted).
    report.section("Persistence (Scheduled Tasks)");
    let mut tasks_logged = false;
    if let Some(text) = run_capture("schtasks", &["/query", "/fo", "list", "/v"]) {
        let mut current_task = String::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("TaskName:") {
                current_task = val.trim().to_string();
            }
            if let Some(val) = line.strip_prefix("Task To Run:") {
                let current_action = val.trim().to_string();
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
                tasks_logged = true;
            }
        }
    }
    if !tasks_logged {
        // PowerShell fallback: same heuristic on task actions.
        let ps = "Get-ScheduledTask | ForEach-Object { $t = $_; \
                  $_.Actions | ForEach-Object { \
                  '{0}\\{1}|{2}' -f $t.TaskPath, $t.TaskName, $_.Execute } }";
        if let Some(text) = run_ps(ps) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let (task, action) = match line.split_once('|') {
                    Some((t, a)) => (t, a),
                    None => continue,
                };
                let lower = action.to_lowercase();
                if task_patterns
                    .iter()
                    .any(|pat| lower.contains(&pat.to_lowercase()))
                {
                    report.flag(format!(
                        "Suspicious scheduled task action: {} -> {}",
                        task, action
                    ));
                } else {
                    report.log(format!("Scheduled task: {} -> {}", task, action));
                }
                tasks_logged = true;
            }
        }
    }
    if !tasks_logged {
        report.log(
            "(i) Could not enumerate scheduled tasks (schtasks and PowerShell both unavailable).",
        );
    }

    // Startup folder check.
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
    } else {
        report.log("(i) APPDATA not set; skipping startup folder scan.");
    }

    // WMI event subscriptions: wmic first, PowerShell CIM fallback.
    report.section("Persistence (WMI event subscriptions)");
    let wmi_text = run_wmic_or_ps(
        &[
            "/namespace:\\\\root\\subscription",
            "path",
            "__EventConsumer",
            "get",
            "CommandLineTemplate",
            "/format:csv",
        ],
        "Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | \
         Where-Object CommandLineTemplate | Select-Object -ExpandProperty CommandLineTemplate",
    );
    if let Some(text) = wmi_text {
        let mut any = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.to_lowercase().contains("commandlinetemplate") {
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
            any = true;
        }
        if !any {
            report.log("(i) No WMI event consumers found.");
        }
    } else {
        report.log("(i) Could not query WMI event consumers.");
    }

    // Services: wmic first, PowerShell Get-CimInstance fallback.
    report.section("Persistence (Services)");
    let svc_text = run_wmic_or_ps(
        &["service", "get", "Name,PathName,StartMode", "/format:csv"],
        "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode | \
         ConvertTo-Csv -NoTypeInformation",
    );
    if let Some(text) = svc_text {
        let table = CsvTable::parse(&text);
        let mut any = false;
        for row in &table.rows {
            let Some(path_name) = table.get(row, "pathname") else {
                continue;
            };
            if path_name.is_empty() {
                continue;
            }
            let name = table.get(row, "name").unwrap_or("unknown");
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
            any = true;
        }
        if !any {
            report.log("(i) No services returned path information.");
        }
    } else {
        report.log("(i) Could not enumerate services (wmic and PowerShell both unavailable).");
    }

    // PowerShell script block logging check.
    report.section("Persistence (PowerShell script block logging)");
    let ps_script = "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object { $_.Properties[2].Value }";
    if let Some(text) = run_ps(ps_script) {
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
                    let cut = trimmed
                        .char_indices()
                        .nth(200)
                        .map(|(i, _)| i)
                        .unwrap_or(trimmed.len());
                    report.flag(format!(
                        "Suspicious PowerShell script block: {}",
                        &trimmed[..cut]
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
        user_config
            .and_then(|c| c.recent_file_days)
            .unwrap_or(RECENT_FILE_DAYS),
        report,
    );
}

fn strings(consts: &[&str]) -> Vec<String> {
    consts.iter().map(|s| s.to_string()).collect()
}
