# Sentrix

A lightweight, cross-platform (Linux / Windows / macOS) heuristic malware
triage scanner, written in Rust with minimal dependencies.

> **NOT a full antivirus.** No signature database, no cloud lookups, no
> quarantine or removal. It flags things worth a human looking at.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
  - [High-Level Flow](#high-level-flow)
  - [Module Dependency Graph](#module-dependency-graph)
  - [Platform Dispatch](#platform-dispatch)
  - [Scan Lifecycle](#scan-lifecycle)
- [Project Structure](#project-structure)
- [What It Checks](#what-it-checks)
- [Build](#build)
- [Usage](#usage)
- [Example Output](#example-output)
- [Configuration](#configuration)
- [Adding a New Check](#adding-a-new-check)
- [Adding a New Platform](#adding-a-new-platform)
- [Testing](#testing)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

Sentrix performs automated heuristic triage on a running system. It
inspects processes, persistence mechanisms, and recently modified files to
surface indicators that may warrant manual investigation.

**Design principles:**

| Principle | Detail |
|-----------|--------|
| Zero runtime deps | std only; `winreg` on Windows for registry access |
| Cross-platform | Linux, Windows, macOS from a single codebase |
| No side-effects | Read-only scanner; never modifies the system |
| Modular | Each check is an isolated, testable unit |
| Library + Binary | `lib.rs` exposes a reusable API; `main.rs` is the CLI |

---

## Architecture

### High-Level Flow

```mermaid
flowchart TD
    CLI["main.rs<br/>CLI entry point"] --> LIB["lib.rs<br/>public API"]

    subgraph SCANNER["scanner/"]
        PROC["processes.rs"]
        PERS["persistence.rs"]
        RFIL["recent_files.rs"]
    end

    subgraph PLATFORM["platform/"]
        LIN["linux.rs"]
        WIN["windows.rs"]
        MAC["macos.rs"]
    end

    CFG["config.rs<br/>constants & paths"]
    RPT["report.rs<br/>Report struct"]

    LIB --> PROC
    LIB --> PERS
    LIB --> RFIL
    PROC --> CFG
    PERS --> CFG
    PROC --> RPT
    PERS --> RPT
    RFIL --> RPT
    PROC --> LIN
    PROC --> WIN
    PROC --> MAC
    PERS --> LIN
    PERS --> WIN
    PERS --> MAC
```

### Module Dependency Graph

```mermaid
graph LR
    main.rs --> lib.rs
    lib.rs --> config
    lib.rs --> report
    lib.rs --> scanner
    lib.rs --> platform

    scanner --> platform
    scanner --> config
    scanner --> report

    platform --> config
    platform --> report
```

**Dependency rules:**

- `config` and `report` are leaf modules — they depend on nothing internal.
- `platform` depends on `config` and `report`.
- `scanner` depends on `platform`, `config`, and `report`.
- `main.rs` depends on everything via `lib.rs`.

### Platform Dispatch

The `platform/mod.rs` uses `#[cfg]` attributes so only the active OS module
compiles. Each platform module exports the same public interface:

```mermaid
flowchart LR
    MOD["platform/mod.rs"]

    subgraph cfg["cfg-gated re-exports"]
        LIN["linux.rs\ncheck_processes()\ncheck_persistence()"]
        WIN["windows.rs\ncheck_processes()\ncheck_persistence()"]
        MAC["macos.rs\ncheck_processes()\ncheck_persistence()"]
    end

    MOD -->|"cfg(target_os = linux)"| LIN
    MOD -->|"cfg(target_os = windows)"| WIN
    MOD -->|"cfg(target_os = macos)"| MAC
```

Only **one** platform module is ever compiled into the binary.

### Scan Lifecycle

```mermaid
sequenceDiagram
    participant CLI as main.rs
    participant Scanner as scanner::*
    participant Platform as platform::*
    participant Config as config
    participant Report as report::Report

    CLI->>Report: Report::new()
    CLI->>Scanner: processes::run()
    Scanner->>Platform: check_processes()
    Platform->>Config: suspicious_dirs()
    Platform->>Report: report.flag() / report.log()
    CLI->>Scanner: persistence::run()
    Scanner->>Platform: check_persistence()
    Platform->>Report: report.flag() / report.log()
    CLI->>Scanner: recent_files::run()
    Scanner->>Config: suspicious_dirs()
    Scanner->>Report: report.log()
    CLI->>CLI: report.join() -> stdout / file
```

---

## Project Structure

```
Sentrix/
├── Cargo.toml                        # Package metadata, targets, deps
├── README.md
├── .gitignore
├── src/
│   ├── main.rs                       # CLI entry point, arg parsing
│   ├── lib.rs                        # Library root — public API
│   ├── config.rs                     # Suspicious dirs, patterns, constants
│   ├── report.rs                     # Report struct + output formatting
│   ├── scanner/
│   │   ├── mod.rs                    # Scanner module root
│   │   ├── processes.rs              # Process location checks
│   │   ├── persistence.rs            # Persistence mechanism checks
│   │   └── recent_files.rs           # Recently modified file checks
│   └── platform/
│       ├── mod.rs                    # cfg-gated re-exports
│       ├── linux.rs                  # /proc, cron, shell rc
│       ├── windows.rs                # tasklist, registry Run keys
│       └── macos.rs                  # ps, LaunchAgents/Daemons
└── tests/
    └── integration.rs                # Integration tests
```

---

## What It Checks

| Check | Linux | Windows | macOS |
|-------|-------|---------|-------|
| Suspicious process locations | `/proc/*/exe` from `/tmp`, `/dev/shm`, `/var/tmp` | `wmic` with full `ExecutablePath` (tasklist fallback) | `ps -axo pid,args` with full executable paths |
| Deleted-but-running binaries | `(deleted)` in `/proc/*/exe` | — | — |
| Persistence — cron | `/etc/crontab`, `/etc/cron.d/*` | — | `/etc/crontab`, `/etc/cron.d/*`, per-user `crontab -l` |
| Persistence — shell rc | `.bashrc`, `.profile` download-exec patterns | — | `.zshrc`, `.bash_profile`, `.zprofile` download-exec patterns |
| Persistence — registry | — | `HKCU`/`HKLM` `Run` + `RunOnce` keys | — |
| Persistence — scheduled tasks | — | `schtasks /query` with action pattern matching | — |
| Persistence — launch agents | — | — | On-disk plist scan + `launchctl list` cross-reference |
| Persistence — startup folder | — | `AppData\Roaming\...\Startup` directory scan | — |
| Persistence — WMI events | — | WMI `__EventConsumer` command pattern matching | — |
| Persistence — services | — | `wmic service` path pattern matching | — |
| Persistence — kernel extensions | — | — | `/Library/Extensions`, `/System/Library/Extensions` scan |
| Persistence — PowerShell script blocks | — | `Get-WinEvent` with `Microsoft-Windows-PowerShell/Operational` log | — |
| Persistence — network extensions | — | — | `/Library/SystemExtensions`, `/Library/NetworkExtensions` scan |
| Recently modified files | `/tmp`, `/dev/shm`, `/var/tmp` | `%LOCALAPPDATA%\Temp`, `C:\Users\Public` | `/tmp`, `/var/tmp`, `/private/tmp`, `/Users/Shared` |

**Suspicious patterns detected in persistence entries:**

- Windows: `powershell`, `cmd /c`, `mshta`, `certutil`, temp/public paths (registry + scheduled tasks + services + WMI)
- macOS: `curl`, `wget`, `/tmp/`, `base64` in plist files, crontab entries, and shell rc files
- Linux: `curl|bash`, `wget|sh`, `base64 -d`, `/dev/tcp/` in shell rc files

---

## Build

Requires **Rust 1.70+** ([install via rustup](https://rustup.rs)).

```bash
cargo build --release
```

Output binary:
- Linux/macOS: `target/release/sentrix`
- Windows: `target\release\sentrix.exe`

### Cross-Compilation

Build natively on each target OS, or cross-compile:

```bash
# Example: build for Windows from Linux
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Usage

```
./sentrix                     # full scan, prints to stdout
./sentrix --quick             # skip the recent-file-modification pass
./sentrix --out report.txt    # write report to file
./sentrix --json              # output report as JSON
./sentrix --json --out report.json  # write JSON report (reuseable for --diff)
./sentrix --diff report.json  # compare against a previous JSON report
./sentrix --config custom.toml  # use custom detection patterns
```

**Privileges:**
- **Windows:** Run from an elevated (Administrator) terminal for full registry access.
- **macOS/Linux:** `sudo` to access root-owned paths you'd otherwise miss.

### Severity Levels

Findings carry a severity: **critical**, **warning**, or **info**. In plain
text, critical findings are prefixed `[CRIT]` and warnings `[!]`; info lines
are unmarked. The JSON output (`--json`) includes a structured `entries` array
sorted by urgency (critical → warning → info) plus per-level counts.

### Comparing Scans (`--diff`)

Run once saving a JSON report, then compare a later run against it to see only
what changed since the last scan:

```bash
./sentrix --json --out baseline.json   # first run: save baseline
./sentrix --diff baseline.json         # later run: show new/resolved findings
./sentrix --diff baseline.json --json  # diff as JSON for pipelines
```

`--diff` exits with code `2` if new findings appeared since the baseline, `0`
otherwise. The exit-code contract still applies to normal runs: `2` when any
findings were flagged, `0` when clean.

---

## Example Output

A sample plain-text report (pathnames redacted) as it appears on Linux:

```
$ ./sentrix --quick
scan time: 2026-09-22T15:33:00Z (epoch:1785838014)

== Suspicious process locations ==
[!] PID 1831 is executing a deleted binary: /root/.opencode/bin/opencode (deleted) — common dropper/rootkit trick

== Persistence (cron / systemd / shell rc) ==
[CRIT] Reverse-shell pattern (/dev/tcp/) detected in /root/.bashrc
[!] Suspicious download-and-execute pattern in /root/.profile

== Recently modified files (last 3 days) ==
Recently modified: /etc/ld.so.cache
Recently modified: /etc/hosts
Recently modified: /etc/cron.d/sample
```

The same scan as JSON highlights the structured severity data:

```
$ ./sentrix --quick --json
{
  "findings": 2,
  "severity_counts": { "info": 3, "warning": 1, "critical": 1 },
  "entries": [
    {
      "severity": "Critical",
      "message": "Reverse-shell pattern (/dev/tcp/) detected in /root/.bashrc",
      "section": "Persistence (cron / systemd / shell rc)"
    },
    {
      "severity": "Warning",
      "message": "PID 1831 is executing a deleted binary: ... (deleted)",
      "section": "Suspicious process locations"
    }
  ]
}
```

## Configuration

All tunable constants live in `src/config.rs` and can be overridden via a TOML configuration file.

| Constant | Description | Default |
|----------|-------------|---------|
| `RECENT_FILE_DAYS` | How many days back to scan for modified files | `3` |
| `suspicious_dirs()` | Platform-specific list of temp/suspicious directories | per-OS |
| `SUSPICIOUS_AUTORUN_PATTERNS` | Windows registry value patterns to flag | 6 patterns |
| `SUSPICIOUS_TASK_ACTIONS` | Windows scheduled task action patterns to flag | 7 patterns |
| `SUSPICIOUS_POWERSHELL_PATTERNS` | PowerShell script block patterns to flag | 18 patterns |
| `SUSPICIOUS_PLIST_PATTERNS` | macOS plist content patterns to flag | 4 patterns |
| `SUSPICIOUS_CRON_PATTERNS` | macOS crontab entry patterns to flag | 4 patterns |
| `SUSPICIOUS_LAUNCHCTL_OUTPUT` | macOS launchctl label patterns to flag | 6 patterns |
| `MACOS_NETWORK_EXT_PATTERNS` | macOS network/system extension name patterns to flag | 7 patterns |
| `MACOS_NETWORK_EXT_ALLOWLIST` | macOS extension identifier prefixes exempt from flagging | 21 prefixes |
| `SHELL_RC_FILES` | Linux shell rc files to inspect | `.bashrc`, `.profile` |
| `PERSISTENCE_SCAN_DIRS` | Linux dirs to scan for recent modifications | `/etc`, `/usr/local/bin` |

### Custom Configuration File

Create a TOML file with your custom patterns and pass it via `--config`:

```bash
./Sentrix --config /path/to/custom.toml
```

See `sentrix.example.toml` for the full configuration format with all available options.

---

## Adding a New Check

1. **Create** `src/scanner/new_check.rs` with a `pub fn run(report: &mut Report)`.
2. **Register** it in `src/scanner/mod.rs`: `pub mod new_check;`.
3. If platform-specific, add implementation in `src/platform/{linux,windows,macos}.rs`.
4. **Call** it from `src/main.rs` in the scan sequence.
5. **Add** constants to `src/config.rs` if needed.
6. **Write tests** in `tests/integration.rs`.

```rust
// src/scanner/new_check.rs
use crate::report::Report;
use crate::platform;

pub fn run(report: &mut Report) {
    platform::check_new_thing(report);
}
```

---

## Adding a New Platform

1. **Create** `src/platform/newplatform.rs` exporting:
   - `pub fn check_processes(report: &mut Report)`
   - `pub fn check_persistence(report: &mut Report)`
2. **Add cfg gate** in `src/platform/mod.rs`:
   ```rust
   #[cfg(target_os = "newplatform")]
   mod newplatform;
   #[cfg(target_os = "newplatform")]
   pub use newplatform::*;
   ```
3. **Add** platform-specific paths to `src/config.rs`.

---

## Testing

```bash
cargo test            # run all tests
cargo test -- --nocapture  # show println! output
```

**Current status:** `tests/integration.rs` is populated with 17 integration
tests covering `Report` behavior (severity markers, JSON round-trip, sorted
entries), config loading (valid, empty, malformed), the recent-files scanner
(including nested directories and the depth cap), pattern constants, config
override flow, and `--diff` comparisons. Unit tests also cover `config_loader`,
`Report` rendering/round-trips, the ISO-8601 timestamp conversion, and the
Windows output helpers (UTF-16 decoding, quote-aware CSV). Total: 28 tests
passing. CI measures coverage with `cargo-llvm-cov` and uploads it to Codecov.

---

## Limitations

- **No real-time monitoring** — single-shot scan only.
- **No signature scanning** — heuristic only, will miss known malware without suspicious indicators.
- **No remediation** — reports findings, never removes/quarantines.
- **No elevated by default** — needs `sudo`/Admin for full visibility.
- **Heuristic-only detection** — substring matching means trivial evasion (extra whitespace, string concatenation, case tricks) can slip through. This is by design; flagged items are meant for manual review, not automated blocking.

---

## Roadmap

| Priority | Item | Status |
|----------|------|--------|
| 1 | CI (`cargo build`/`test`/`clippy`/`fmt` on all 3 OSes) | ✅ Complete |
| 2 | Example output in README | ✅ Complete |
| 3 | Windows/macOS parity (schtasks, launchctl, WMI) | ✅ Complete |
| 4 | Configurable detection patterns (external TOML/YAML) | ✅ Complete |
| 5 | Structured output (`--json`, severity levels) | ✅ Complete |
| 6 | Test coverage (unit tests, cargo-llvm-cov in CI, Codecov upload) | ✅ Complete |
| 7 | Nice-to-haves (`--diff`, `CONTRIBUTING.md`) | ✅ Complete |

See [docs/PROGRESS.md](docs/PROGRESS.md#roadmap-status) for detailed status,
gaps, and implementation notes for each item.

---

## License

MIT
