//! Helpers for decoding and parsing Windows command output.
//!
//! Two pitfalls this module fixes:
//!
//! 1. **Encoding** — `wmic` emits UTF-16LE (with a BOM) on most builds, and
//!    other tools can emit BOM-less UTF-16 or legacy codepages. Naive
//!    `String::from_utf8_lossy` on UTF-16 data yields NUL-interleaved text
//!    in which no detection pattern can ever match.
//! 2. **CSV** — quoted fields (e.g. `ExecutablePath` values containing
//!    commas) break naive `split(',')`, producing wrong field indexes and
//!    missed detections. This parser respects RFC-4180-style quotes.

/// Decode raw process stdout into clean text.
///
/// Handles UTF-16LE/BE (with or without BOM), UTF-8 BOM, and falls back to
/// lossy UTF-8 for anything else (e.g. legacy codepage output, where ASCII
/// pattern matching still mostly works).
pub fn decode_output(raw: &[u8]) -> String {
    // UTF-16 BOMs are unambiguous — decode as wide text.
    if raw.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&raw[2..], true);
    }
    if raw.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&raw[2..], false);
    }
    // UTF-8 BOM.
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(raw);

    // BOM-less UTF-16LE is common from wmic/powershell piped output: ASCII
    // chars encode as `char, 0x00`, so lots of NUL bytes is a reliable tell.
    // Valid UTF-8 text never contains NUL bytes, so this never misfires on it.
    let nul_count = raw.iter().filter(|&&b| b == 0).count();
    if raw.len() >= 2 && nul_count > raw.len() / 4 {
        return decode_utf16(raw, true);
    }

    String::from_utf8_lossy(raw).into_owned()
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Split one CSV line into fields, honoring double-quoted fields.
///
/// `""` inside a quoted field decodes to a literal `"` (RFC 4180). Quotes are
/// stripped from quoted fields; the outer CSV wrappers used by `tasklist /fo
/// csv` therefore come back clean.
pub fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    fields.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
    }
    fields.push(cur);
    fields
}

/// A CSV table parsed from command output (`wmic /format:csv`,
/// `ConvertTo-Csv`, ...): a header row plus data rows, with column lookup by
/// name instead of fragile positional indexes.
pub struct CsvTable {
    headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl CsvTable {
    /// Parse decoded text into a table. The first non-empty line is the
    /// header; remaining non-empty lines are data rows.
    pub fn parse(text: &str) -> Self {
        let mut headers: Vec<String> = Vec::new();
        let mut rows: Vec<Vec<String>> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if headers.is_empty() {
                headers = parse_csv_line(line)
                    .into_iter()
                    .map(|f| f.trim().to_lowercase())
                    .collect();
            } else {
                rows.push(parse_csv_line(line));
            }
        }
        CsvTable { headers, rows }
    }

    fn col_index(&self, name: &str) -> Option<usize> {
        self.headers.iter().position(|h| h == name)
    }

    /// Fetch a trimmed cell from a data row by header name.
    pub fn get<'a>(&self, row: &'a [String], name: &str) -> Option<&'a str> {
        self.col_index(name)
            .and_then(|i| row.get(i))
            .map(|s| s.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf16le_with_bom() {
        // "powershell" in UTF-16LE with BOM.
        let mut raw: Vec<u8> = vec![0xFF, 0xFE];
        raw.extend("powershell".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(decode_output(&raw), "powershell");
    }

    #[test]
    fn test_decode_bomless_utf16le() {
        let raw: Vec<u8> = "mshta"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_output(&raw), "mshta");
    }

    #[test]
    fn test_decode_utf16be_with_bom() {
        let mut raw: Vec<u8> = vec![0xFE, 0xFF];
        raw.extend("certutil".encode_utf16().flat_map(|u| u.to_be_bytes()));
        assert_eq!(decode_output(&raw), "certutil");
    }

    #[test]
    fn test_decode_utf8_passthrough() {
        assert_eq!(decode_output(b"plain ascii"), "plain ascii");
        assert_eq!(decode_output("\u{00e9}".as_bytes()), "\u{00e9}");
        let mut bommed: Vec<u8> = vec![0xEF, 0xBB, 0xBF];
        bommed.extend(b"ok");
        assert_eq!(decode_output(&bommed), "ok");
    }

    #[test]
    fn test_parse_csv_line_with_quoted_commas() {
        let line = r#"Node,"C:\path with,comma\evil.exe","evil, name",1234"#;
        let fields = parse_csv_line(line);
        assert_eq!(fields[0], "Node");
        assert_eq!(fields[1], r"C:\path with,comma\evil.exe");
        assert_eq!(fields[2], "evil, name");
        assert_eq!(fields[3], "1234");
    }

    #[test]
    fn test_parse_csv_line_strips_tasklist_quotes() {
        let line = r#""chrome.exe","1234","Console""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields, vec!["chrome.exe", "1234", "Console"]);
    }

    #[test]
    fn test_parse_csv_line_escaped_quotes() {
        let line = r#"a,"say ""hi""",b"#;
        let fields = parse_csv_line(line);
        assert_eq!(fields[1], r#"say "hi""#);
    }

    #[test]
    fn test_csv_table_lookup_by_header_name() {
        let table = CsvTable::parse(
            "Node,ExecutablePath,Name,ProcessId\r\nDESKTOP,C:\\path\\evil.exe,evil.exe,4242\r\n",
        );
        assert_eq!(table.rows.len(), 1);
        let row = &table.rows[0];
        assert_eq!(table.get(row, "executablepath"), Some(r"C:\path\evil.exe"));
        assert_eq!(table.get(row, "name"), Some("evil.exe"));
        assert_eq!(table.get(row, "processid"), Some("4242"));
        assert_eq!(table.get(row, "missing"), None);
    }

    #[test]
    fn test_csv_table_handles_quoted_paths_with_commas() {
        let text = concat!(
            r#""ProcessId","Name","ExecutablePath""#,
            "\r\n",
            r#""7","svc, host","C:\\Program Files, Sub\\a.exe""#,
        );
        let table = CsvTable::parse(text);
        let row = &table.rows[0];
        assert_eq!(table.get(row, "name"), Some("svc, host"));
        assert_eq!(
            table.get(row, "executablepath"),
            Some(r"C:\Program Files, Sub\a.exe")
        );
    }
}
