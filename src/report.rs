use std::time::{SystemTime, UNIX_EPOCH};

pub struct Report {
    pub lines: Vec<String>,
    pub findings: u32,
}

impl Report {
    pub fn new() -> Self {
        Report {
            lines: Vec::new(),
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
}

pub fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("epoch:{}", secs)
}
