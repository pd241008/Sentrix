use std::collections::HashMap;
use std::path::Path;

/// User-configurable settings loaded from TOML config file
#[derive(Debug, Clone, Default)]
pub struct UserConfig {
    pub recent_file_days: Option<u64>,
    pub windows: Option<PlatformConfig>,
    pub macos: Option<PlatformConfig>,
    pub linux: Option<PlatformConfig>,
}

#[derive(Debug, Clone, Default)]
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

/// Simple TOML parser for Sentrix config files.
/// Supports only the subset needed for config: strings, integers, and arrays of strings.
pub fn load_config(path: &Path) -> Result<UserConfig, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Could not read config file {}: {}", path.display(), e))?;

    let mut current_section = String::new();
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut root: HashMap<String, String> = HashMap::new();

    for (_line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            current_section = line[1..line.len() - 1].trim().to_string();
            sections
                .entry(current_section.clone())
                .or_insert_with(HashMap::new);
            continue;
        }

        // Key = Value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();

            if current_section.is_empty() {
                root.insert(key, value);
            } else {
                if let Some(section) = sections.get_mut(&current_section) {
                    section.insert(key, value);
                }
            }
        }
    }

    // Parse root settings
    let mut config = UserConfig::default();
    if let Some(days) = root.get("recent_file_days") {
        if let Ok(d) = days.parse::<u64>() {
            config.recent_file_days = Some(d);
        }
    }

    // Parse platform configs
    config.windows = parse_platform_config(&sections, "windows");
    config.macos = parse_platform_config(&sections, "macos");
    config.linux = parse_platform_config(&sections, "linux");

    Ok(config)
}

fn parse_platform_config(
    sections: &HashMap<String, HashMap<String, String>>,
    platform: &str,
) -> Option<PlatformConfig> {
    let section = sections.get(platform)?;

    let mut config = PlatformConfig::default();

    config.suspicious_autorun_patterns = parse_string_array(section, "suspicious_autorun_patterns");
    config.suspicious_task_actions = parse_string_array(section, "suspicious_task_actions");
    config.suspicious_powershell_patterns =
        parse_string_array(section, "suspicious_powershell_patterns");
    config.suspicious_service_patterns = parse_string_array(section, "suspicious_service_patterns");
    config.wmi_event_consumer_patterns =
        parse_string_array(section, "wmi_event_consumer_patterns");
    config.suspicious_plist_patterns = parse_string_array(section, "suspicious_plist_patterns");
    config.suspicious_cron_patterns = parse_string_array(section, "suspicious_cron_patterns");
    config.suspicious_launchctl_output = parse_string_array(section, "suspicious_launchctl_output");
    config.shell_rc_files = parse_string_array(section, "shell_rc_files");
    config.persistence_scan_dirs = parse_string_array(section, "persistence_scan_dirs");

    Some(config)
}

fn parse_string_array(section: &HashMap<String, String>, key: &str) -> Option<Vec<String>> {
    let value = section.get(key)?;
    parse_array_value(value)
}

/// Parse a TOML-style array: ["item1", "item2", "item3"]
fn parse_array_value(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return None;
    }

    let inner = &value[1..value.len() - 1];
    let items: Vec<String> = inner
        .split(',')
        .map(|s| {
            let s = s.trim();
            // Remove quotes
            let s = s.trim_start_matches('"').trim_end_matches('"');
            let s = s.trim_start_matches('\'').trim_end_matches('\'');
            s.to_string()
        })
        .filter(|s| !s.is_empty())
        .collect();

    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_array_value() {
        assert_eq!(
            parse_array_value(r#"["powershell", "cmd /c", "mshta"]"#),
            Some(vec![
                "powershell".to_string(),
                "cmd /c".to_string(),
                "mshta".to_string()
            ])
        );
    }

    #[test]
    fn test_parse_array_value_empty() {
        assert_eq!(parse_array_value("[]"), Some(vec![]));
    }

    #[test]
    fn test_parse_array_value_single() {
        assert_eq!(
            parse_array_value(r#"["powershell"]"#),
            Some(vec!["powershell".to_string()])
        );
    }
}
