use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserConfig {
    pub recent_file_days: Option<u64>,
    pub windows: Option<PlatformConfig>,
    pub macos: Option<PlatformConfig>,
    pub linux: Option<PlatformConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PlatformConfig {
    pub suspicious_autorun_patterns: Option<Vec<String>>,
    pub suspicious_task_actions: Option<Vec<String>>,
    pub suspicious_powershell_patterns: Option<Vec<String>>,
    pub suspicious_service_patterns: Option<Vec<String>>,
    pub wmi_event_consumer_patterns: Option<Vec<String>>,
    pub suspicious_plist_patterns: Option<Vec<String>>,
    pub suspicious_cron_patterns: Option<Vec<String>>,
    pub suspicious_launchctl_output: Option<Vec<String>>,
    pub shell_rc_files: Option<Vec<String>>,
    pub persistence_scan_dirs: Option<Vec<String>>,
}

pub fn load_config(path: &Path) -> Result<UserConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Could not read config file {}: {}", path.display(), e))?;

    toml::from_str(&content).map_err(|e| format!("Failed to parse config file: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_valid_config() {
        let tmp = std::env::temp_dir().join("sentrix_test_config.toml");
        let mut f = std::fs::File::create(&tmp).unwrap();
        write!(
            f,
            r#"
recent_file_days = 5

[windows]
suspicious_autorun_patterns = ["powershell -enc", "mshta"]

[linux]
shell_rc_files = [".bashrc", ".zshrc"]
persistence_scan_dirs = ["/etc", "/usr/local/bin"]
"#
        )
        .unwrap();

        let config = load_config(&tmp).unwrap();
        assert_eq!(config.recent_file_days, Some(5));
        assert!(config.windows.is_some());
        let win = config.windows.unwrap();
        assert_eq!(
            win.suspicious_autorun_patterns,
            Some(vec!["powershell -enc".to_string(), "mshta".to_string()])
        );
        let linux = config.linux.unwrap();
        assert_eq!(
            linux.shell_rc_files,
            Some(vec![".bashrc".to_string(), ".zshrc".to_string()])
        );
        assert_eq!(
            linux.persistence_scan_dirs,
            Some(vec!["/etc".to_string(), "/usr/local/bin".to_string()])
        );

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_load_empty_config() {
        let tmp = std::env::temp_dir().join("sentrix_test_empty.toml");
        std::fs::write(&tmp, "").unwrap();

        let config = load_config(&tmp).unwrap();
        assert_eq!(config.recent_file_days, None);
        assert!(config.windows.is_none());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_load_invalid_config() {
        let tmp = std::env::temp_dir().join("sentrix_test_invalid.toml");
        std::fs::write(&tmp, "this is not valid toml {{{").unwrap();

        let result = load_config(&tmp);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&tmp);
    }
}
