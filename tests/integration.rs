use sentrix::config;
use sentrix::config_loader::load_config;
use sentrix::report::Report;
use sentrix::scanner::recent_files;
use std::fs;
use std::io::Write;

// ===== Report tests =====

#[test]
fn test_report_new_has_timestamp() {
    let report = Report::new();
    assert_eq!(report.findings, 0);
    assert!(!report.lines.is_empty());
    assert!(report.lines[0].starts_with("epoch:"));
}

#[test]
fn test_report_section_and_log() {
    let mut report = Report::new();
    report.section("Test Section");
    report.log("a log line");
    report.log("another log line");

    let output = report.join();
    assert!(output.contains("== Test Section =="));
    assert!(output.contains("a log line"));
    assert!(output.contains("another log line"));
    assert_eq!(report.findings, 0);
}

#[test]
fn test_report_flag_increments_findings() {
    let mut report = Report::new();
    report.flag("suspicious thing 1");
    report.flag("suspicious thing 2");
    assert_eq!(report.findings, 2);

    let output = report.join();
    assert!(output.contains("[!] suspicious thing 1"));
    assert!(output.contains("[!] suspicious thing 2"));
}

#[test]
fn test_report_to_json() {
    let mut report = Report::new();
    report.section("JSON Test");
    report.flag("bad thing");

    let json = report.to_json();
    assert!(json.contains("\"findings\": 1"));
    assert!(json.contains("\"lines\""));
    assert!(json.contains("== JSON Test =="));
    assert!(json.contains("[!] bad thing"));
}

// ===== Config tests =====

#[test]
fn test_suspicious_dirs_not_empty() {
    let dirs = config::suspicious_dirs();
    assert!(!dirs.is_empty(), "suspicious_dirs() should not be empty");
}

#[test]
fn test_recent_file_days_default() {
    assert_eq!(config::RECENT_FILE_DAYS, 3);
}

#[test]
fn test_load_config_with_valid_toml() {
    let tmp = std::env::temp_dir().join("sentrix_integration_config.toml");
    let mut f = fs::File::create(&tmp).unwrap();
    write!(
        f,
        r#"
recent_file_days = 7

[windows]
suspicious_autorun_patterns = ["powershell -enc", "mshta"]
suspicious_task_actions = ["powershell", "cmd /c"]

[macos]
suspicious_plist_patterns = ["curl", "wget"]

[linux]
shell_rc_files = [".bashrc"]
persistence_scan_dirs = ["/etc"]
"#
    )
    .unwrap();

    let config = load_config(&tmp).unwrap();
    assert_eq!(config.recent_file_days, Some(7));
    let win = config.windows.unwrap();
    assert_eq!(
        win.suspicious_autorun_patterns,
        Some(vec!["powershell -enc".to_string(), "mshta".to_string()])
    );
    assert_eq!(
        win.suspicious_task_actions,
        Some(vec!["powershell".to_string(), "cmd /c".to_string()])
    );
    let macos = config.macos.unwrap();
    assert_eq!(
        macos.suspicious_plist_patterns,
        Some(vec!["curl".to_string(), "wget".to_string()])
    );
    let linux = config.linux.unwrap();
    assert_eq!(linux.shell_rc_files, Some(vec![".bashrc".to_string()]));
    assert_eq!(linux.persistence_scan_dirs, Some(vec!["/etc".to_string()]));

    let _ = fs::remove_file(&tmp);
}

#[test]
fn test_load_config_malformed_toml() {
    let tmp = std::env::temp_dir().join("sentrix_integration_bad.toml");
    fs::write(&tmp, "recent_file_days = not_a_number\n").unwrap();

    let result = load_config(&tmp);
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("Failed to parse config file"));

    let _ = fs::remove_file(&tmp);
}

// ===== Scanner tests =====

#[test]
fn test_recent_files_scanner_counts_recent() {
    let tmp_dir = std::env::temp_dir().join("sentrix_test_recent");
    let _ = fs::create_dir_all(&tmp_dir);

    let recent_file = tmp_dir.join("recent.txt");
    let mut f = fs::File::create(&recent_file).unwrap();
    write!(f, "recent content").unwrap();

    let mut report = Report::new();
    recent_files::run(&[tmp_dir.to_string_lossy().to_string()], 1, &mut report);

    let output = report.join();
    assert!(output.contains("recent.txt"));

    let _ = fs::remove_file(&recent_file);
    let _ = fs::remove_dir(&tmp_dir);
}

// ===== Pattern tests =====

#[cfg(target_os = "windows")]
#[test]
fn test_windows_patterns_non_empty() {
    assert!(!config::SUSPICIOUS_AUTORUN_PATTERNS.is_empty());
    assert!(!config::SUSPICIOUS_TASK_ACTIONS.is_empty());
    assert!(!config::SUSPICIOUS_POWERSHELL_PATTERNS.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_patterns_non_empty() {
    assert!(!config::SUSPICIOUS_PLIST_PATTERNS.is_empty());
    assert!(!config::SUSPICIOUS_CRON_PATTERNS.is_empty());
    assert!(!config::SUSPICIOUS_LAUNCHCTL_OUTPUT.is_empty());
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[test]
fn test_linux_patterns_non_empty() {
    assert!(!config::SHELL_RC_FILES.is_empty());
    assert!(!config::PERSISTENCE_SCAN_DIRS.is_empty());
}

// ===== Config overrides flow =====

#[test]
fn test_config_overrides_are_preserved() {
    let tmp = std::env::temp_dir().join("sentrix_integration_overrides.toml");
    let mut f = fs::File::create(&tmp).unwrap();
    write!(
        f,
        r#"
[windows]
suspicious_autorun_patterns = ["custom-pattern"]

[linux]
persistence_scan_dirs = ["/custom/path"]
"#
    )
    .unwrap();

    let config = load_config(&tmp).unwrap();
    let win = config.windows.unwrap();
    assert_eq!(
        win.suspicious_autorun_patterns,
        Some(vec!["custom-pattern".to_string()])
    );
    let linux = config.linux.unwrap();
    assert_eq!(
        linux.persistence_scan_dirs,
        Some(vec!["/custom/path".to_string()])
    );

    let _ = fs::remove_file(&tmp);
}
