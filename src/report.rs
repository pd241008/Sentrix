use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub lines: Vec<String>,
    pub findings: u32,
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
        }
    }

    pub fn section(&mut self, title: &str) {
        self.lines.push(String::new());
        self.lines.push(format!("== {} ==", title));
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        self.lines.push(msg.into());
    }

    pub fn flag(&mut self, msg: impl Into<String>) {
        self.findings += 1;
        self.lines.push(format!("[!] {}", msg.into()));
    }

    pub fn join(&self) -> String {
        self.lines.join("\n")
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

pub fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("epoch:{}", secs)
}
