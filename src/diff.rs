use crate::report::{Entry, Report, Severity};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffResult {
    pub previous_findings: u32,
    pub current_findings: u32,
    pub new_findings: Vec<Entry>,
    pub resolved_findings: Vec<Entry>,
}

impl DiffResult {
    pub fn new_critical(&self) -> usize {
        self.new_findings
            .iter()
            .filter(|e| e.severity == Severity::Critical)
            .count()
    }

    pub fn new_warning(&self) -> usize {
        self.new_findings
            .iter()
            .filter(|e| e.severity == Severity::Warning)
            .count()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("== Scan diff ==");
        out.push('\n');
        out.push_str(&format!("previous findings: {}\n", self.previous_findings));
        out.push_str(&format!("current findings:  {}\n", self.current_findings));
        out.push_str(&format!(
            "new findings:      {} ({} critical, {} warning)\n",
            self.new_findings.len(),
            self.new_critical(),
            self.new_warning()
        ));
        out.push_str(&format!(
            "resolved findings: {}\n",
            self.resolved_findings.len()
        ));
        out.push('\n');

        if self.new_findings.is_empty() {
            out.push_str("No new findings since last scan.\n");
        } else {
            out.push_str("== New findings (since last scan) ==");
            out.push('\n');
            for e in &self.new_findings {
                out.push_str(&e.render());
                out.push('\n');
            }
        }

        if !self.resolved_findings.is_empty() {
            out.push_str("\n== Resolved findings (no longer present) ==");
            out.push('\n');
            for e in &self.resolved_findings {
                out.push_str(&e.render());
                out.push('\n');
            }
        }
        out
    }
}

fn key(e: &Entry) -> (String, String) {
    (format!("{:?}", e.severity), e.message.clone())
}

pub fn compute(previous: &Report, current: &Report) -> DiffResult {
    let prev: BTreeSet<(String, String)> = previous
        .entries
        .iter()
        .filter(|e| e.severity != Severity::Info)
        .map(key)
        .collect();
    let cur: BTreeSet<(String, String)> = current
        .entries
        .iter()
        .filter(|e| e.severity != Severity::Info)
        .map(key)
        .collect();

    let new_findings: Vec<Entry> = current
        .entries
        .iter()
        .filter(|e| e.severity != Severity::Info && !prev.contains(&key(e)))
        .cloned()
        .collect();

    let resolved_findings: Vec<Entry> = previous
        .entries
        .iter()
        .filter(|e| e.severity != Severity::Info && !cur.contains(&key(e)))
        .cloned()
        .collect();

    DiffResult {
        previous_findings: previous.findings,
        current_findings: current.findings,
        new_findings,
        resolved_findings,
    }
}
