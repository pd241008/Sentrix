use std::path::PathBuf;

pub const RECENT_FILE_DAYS: u64 = 3;

#[cfg(target_os = "windows")]
pub fn suspicious_dirs() -> Vec<PathBuf> {
    let mut v = vec![
        PathBuf::from("C:\\Windows\\Temp"),
        PathBuf::from("C:\\Users\\Public"),
    ];
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        v.push(PathBuf::from(local).join("Temp"));
    }
    v
}

#[cfg(target_os = "macos")]
pub fn suspicious_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/Users/Shared"),
    ]
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn suspicious_dirs() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/dev/shm"),
        PathBuf::from("/var/tmp"),
    ]
}

pub fn path_is_suspicious(exe_str: &str, sus_dirs: &[PathBuf]) -> bool {
    let exe_path = std::path::Path::new(exe_str);
    sus_dirs.iter().any(|d| exe_path.starts_with(d))
}

#[cfg(target_os = "windows")]
pub const PERSISTENCE_REGISTRY_RUN_PATHS: &[&str] = &[
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

#[cfg(target_os = "windows")]
pub const SUSPICIOUS_AUTORUN_PATTERNS: &[&str] = &[
    "powershell -enc",
    "-windowstyle hidden",
    "\\appdata\\local\\temp",
    "\\users\\public",
    "mshta",
    "certutil -decode",
];

#[cfg(target_os = "windows")]
pub const SUSPICIOUS_TASK_ACTIONS: &[&str] = &[
    "powershell",
    "cmd /c",
    "mshta",
    "certutil",
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public",
];

#[cfg(target_os = "macos")]
pub fn launch_agent_dirs() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        PathBuf::from(format!("{}/Library/LaunchAgents", home)),
        PathBuf::from("/Library/LaunchAgents"),
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/System/Library/LaunchAgents"),
    ]
}

#[cfg(target_os = "macos")]
pub const SUSPICIOUS_PLIST_PATTERNS: &[&str] = &["curl", "wget", "/tmp/", "base64"];

#[cfg(target_os = "macos")]
pub const SUSPICIOUS_CRON_PATTERNS: &[&str] = &["curl", "wget", "base64", "/tmp/"];

#[cfg(target_os = "macos")]
pub const SUSPICIOUS_LAUNCHCTL_OUTPUT: &[&str] =
    &["curl", "wget", "/tmp/", "base64", "mshta", "powershell"];

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub const SHELL_RC_FILES: &[&str] = &[".bashrc", ".profile"];

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub const PERSISTENCE_SCAN_DIRS: &[&str] = &["/etc", "/usr/local/bin"];

#[cfg(target_os = "macos")]
pub const MACOS_SHELL_RC_FILES: &[&str] = &[".zshrc", ".bash_profile", ".zprofile"];

#[cfg(target_os = "macos")]
pub const MACOS_KEXT_SCAN_DIRS: &[&str] = &["/Library/Extensions", "/System/Library/Extensions"];

#[cfg(target_os = "windows")]
pub const SUSPICIOUS_SERVICE_PATTERNS: &[&str] = &[
    "\\temp\\",
    "\\appdata\\local\\temp",
    "\\users\\public",
    "powershell",
    "cmd /c",
    "mshta",
    "certutil",
];

#[cfg(target_os = "windows")]
pub const WMI_EVENT_CONSUMER_PATTERNS: &[&str] = &[
    "powershell",
    "cmd /c",
    "mshta",
    "certutil",
    "wscript",
    "cscript",
];

#[cfg(target_os = "windows")]
pub const SUSPICIOUS_POWERSHELL_PATTERNS: &[&str] = &[
    "invoke-expression",
    "iex(",
    "iex (",
    "downloadstring",
    "invoke-webrequest",
    "start-process",
    "encodedcommand",
    "frombase64string",
    "bitstransfer",
    "start-bitstransfer",
    "invoke-cimmethod",
    "get-wmiobject",
    "set-maliciousvalue",
    "hidden",
    "-nop",
    "-noni",
    "bypass",
    "downloadfile",
    "invoke-restmethod",
    "new-object net.webclient",
    "invoke-atomictest",
];
