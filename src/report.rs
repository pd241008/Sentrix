use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "",
            Severity::Warning => "[!]",
            Severity::Critical => "[CRIT]",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub severity: Severity,
    pub message: String,
    pub section: String,
}

impl Entry {
    pub fn render(&self) -> String {
        render_line(self.severity, &self.message)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub info: u32,
    pub warning: u32,
    pub critical: u32,
}

impl SeverityCounts {
    pub fn total(&self) -> u32 {
        self.info + self.warning + self.critical
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub lines: Vec<String>,
    pub findings: u32,
    pub severity_counts: SeverityCounts,
    pub entries: Vec<Entry>,
    #[serde(skip)]
    current_section: String,
}

impl Default for Report {
    fn default() -> Self {
        Self::new()
    }
}

impl Report {
    pub fn new() -> Self {
        Report {
            lines: vec![now_string()],
            findings: 0,
            severity_counts: SeverityCounts::default(),
            entries: Vec::new(),
            current_section: String::new(),
        }
    }

    pub fn section(&mut self, title: &str) {
        self.lines.push(String::new());
        self.lines.push(format!("== {} ==", title));
        self.current_section = title.to_string();
    }

    fn push(&mut self, severity: Severity, message: String) {
        let section = self.current_section.clone();
        self.entries.push(Entry {
            severity,
            message: message.clone(),
            section,
        });
        self.lines.push(render_line(severity, &message));
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        self.severity_counts.info += 1;
        self.push(Severity::Info, msg.into());
    }

    pub fn warn(&mut self, msg: impl Into<String>) {
        self.severity_counts.warning += 1;
        self.findings += 1;
        self.push(Severity::Warning, msg.into());
    }

    pub fn flag(&mut self, msg: impl Into<String>) {
        self.warn(msg);
    }

    pub fn critical(&mut self, msg: impl Into<String>) {
        self.severity_counts.critical += 1;
        self.findings += 1;
        self.push(Severity::Critical, msg.into());
    }

    pub fn join(&self) -> String {
        self.lines.join("\n")
    }

    pub fn to_json(&self) -> String {
        let mut entries: Vec<&Entry> = self.entries.iter().collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.severity));
        #[derive(Serialize)]
        struct JsonReport<'a> {
            lines: &'a [String],
            findings: u32,
            severity_counts: SeverityCounts,
            entries: Vec<&'a Entry>,
        }
        let json = JsonReport {
            lines: &self.lines,
            findings: self.findings,
            severity_counts: self.severity_counts,
            entries,
        };
        serde_json::to_string_pretty(&json).unwrap_or_default()
    }
}

pub fn render_line(severity: Severity, message: &str) -> String {
    match severity {
        Severity::Info => message.to_string(),
        Severity::Warning => format!("[!] {}", message),
        Severity::Critical => format!("[CRIT] {}", message),
    }
}

pub fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("epoch:{}", secs)
}
