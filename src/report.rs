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

/// Scan report — a single source of truth.
///
/// Findings are stored once, as structured [`Entry`] values, plus an ordered
/// list of section titles. Both the plain-text view ([`Report::join`]) and the
/// JSON view ([`Report::to_json`]) are *derived* at output time, so the
/// rendered text can never drift out of sync with the entries it came from.
///
/// `current_section` is transient writer state used to attribute entries to
/// the section they were logged under; it is not part of the serialized form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    timestamp_epoch: u64,
    timestamp_iso: String,
    sections: Vec<String>,
    entries: Vec<Entry>,
    findings: u32,
    severity_counts: SeverityCounts,
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
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Report {
            timestamp_epoch: secs,
            timestamp_iso: epoch_to_iso(secs),
            sections: Vec::new(),
            entries: Vec::new(),
            findings: 0,
            severity_counts: SeverityCounts::default(),
            current_section: String::new(),
        }
    }

    pub fn section(&mut self, title: &str) {
        self.sections.push(title.to_string());
        self.current_section = title.to_string();
    }

    /// All entries in the order they were recorded.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of warning + critical findings.
    pub fn findings(&self) -> u32 {
        self.findings
    }

    /// Per-severity counts.
    pub fn severity_counts(&self) -> SeverityCounts {
        self.severity_counts
    }

    /// Scan timestamp as Unix epoch seconds.
    pub fn timestamp_epoch(&self) -> u64 {
        self.timestamp_epoch
    }

    /// Scan timestamp as an ISO-8601 UTC string.
    pub fn timestamp_iso(&self) -> &str {
        &self.timestamp_iso
    }

    fn push(&mut self, severity: Severity, message: String) {
        let section = self.current_section.clone();
        self.entries.push(Entry {
            severity,
            message,
            section,
        });
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

    /// Rendered plain-text lines, derived from the entries.
    fn render_lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "scan time: {} (epoch:{})",
            self.timestamp_iso, self.timestamp_epoch
        )];

        // Preamble: entries recorded before any section() call (rare).
        for e in self.entries.iter().filter(|e| e.section.is_empty()) {
            out.push(e.render());
        }

        for (idx, title) in self.sections.iter().enumerate() {
            // Render each distinct section title only once, even if
            // section() was called repeatedly with the same title.
            if self.sections[..idx].contains(title) {
                continue;
            }
            out.push(String::new());
            out.push(format!("== {} ==", title));
            for e in self.entries.iter().filter(|e| &e.section == title) {
                out.push(e.render());
            }
        }

        // Defensive: entries referencing a section that was never declared
        // still get rendered instead of silently disappearing.
        for e in self
            .entries
            .iter()
            .filter(|e| !e.section.is_empty() && !self.sections.contains(&e.section))
        {
            out.push(e.render());
        }

        out
    }

    pub fn join(&self) -> String {
        self.render_lines().join("\n")
    }

    pub fn to_json(&self) -> String {
        let mut entries: Vec<&Entry> = self.entries.iter().collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.severity));
        #[derive(Serialize)]
        struct JsonReport<'a> {
            lines: Vec<String>,
            findings: u32,
            severity_counts: SeverityCounts,
            entries: Vec<&'a Entry>,
        }
        let json = JsonReport {
            lines: self.render_lines(),
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

/// Convert Unix epoch seconds to a UTC ISO-8601 timestamp (no external deps).
///
/// Uses the civil-from-days algorithm (Hinnant, 2017) so leap years —
/// including the 2000-02-29 and 2100 edge cases — are handled correctly.
fn epoch_to_iso(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (h, m, s) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, d, h, m, s
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_to_iso_known_values() {
        assert_eq!(epoch_to_iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso(1_000_000_000), "2001-09-09T01:46:40Z");
        // Leap day.
        assert_eq!(epoch_to_iso(951_782_400), "2000-02-29T00:00:00Z");
        // Non-leap century year: 2100-03-01 follows 2100-02-28.
        assert_eq!(epoch_to_iso(4_107_542_400), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn test_timestamp_line_has_iso_and_epoch() {
        let report = Report::new();
        let out = report.join();
        let first = out.lines().next().unwrap();
        assert!(first.starts_with("scan time: "), "got: {}", first);
        // ISO-8601 UTC timestamp followed by the raw epoch.
        assert!(first.contains("T"), "missing ISO-8601 time: {}", first);
        assert!(first.contains("Z (epoch:"), "got: {}", first);
    }

    #[test]
    fn test_join_matches_entries_and_sections() {
        let mut report = Report::new();
        report.log("preamble");
        report.section("S");
        report.warn("warning line");
        report.critical("critical line");

        let out = report.join();
        assert!(out.contains("== S =="));
        assert!(out.contains("[!] warning line"));
        assert!(out.contains("[CRIT] critical line"));
        // Section header appears exactly once even though state is not duplicated.
        assert_eq!(out.matches("== S ==").count(), 1);
    }

    #[test]
    fn test_repeated_section_title_merges_entries() {
        let mut report = Report::new();
        report.section("Recent");
        report.log("first");
        report.section("Recent");
        report.log("second");

        let out = report.join();
        assert_eq!(out.matches("== Recent ==").count(), 1);
        let first = out.find("first").unwrap();
        let second = out.find("second").unwrap();
        assert!(first < second, "entry order must be preserved");
    }

    #[test]
    fn test_legacy_json_without_sections_round_trips() {
        // Old baselines (pre-refactor) had a `lines` field and no
        // `sections`/timestamp fields; they must still deserialize for --diff.
        let legacy = r#"{
            "lines": ["epoch:1", "== S =="],
            "findings": 1,
            "severity_counts": {"info": 0, "warning": 1, "critical": 0},
            "entries": [
                {"severity": "Warning", "message": "legacy entry", "section": "S"}
            ]
        }"#;
        let restored: Report = serde_json::from_str(legacy).unwrap();
        assert_eq!(restored.findings, 1);
        assert_eq!(restored.entries.len(), 1);
        assert_eq!(restored.entries[0].message, "legacy entry");
    }

    #[test]
    fn test_json_includes_derived_lines() {
        let mut report = Report::new();
        report.section("JSON Test");
        report.flag("bad thing");

        let json = report.to_json();
        assert!(json.contains("\"lines\""));
        assert!(json.contains("== JSON Test =="));
        assert!(json.contains("[!] bad thing"));
        assert!(json.contains("scan time:"));
    }
}
