# Sentrix — Development Progress

## Completed Commits

- [x] **Commit 1:** Skeleton (Cargo.toml, .gitignore, README, minimal src/main.rs + src/lib.rs)
  - Commit: `65cd346`
- [x] **Commit 2:** Add config module (src/config.rs)
  - Commit: `03a2af5` (merged via PR #3)
- [x] **Commit 3:** Add report module (src/report.rs)
  - Commit: `6990ec7` (merged via PR #3)
- [x] **Commit 4:** Add platform modules (src/platform/*)
  - Commit: `313e827` (merged via PR #3)
- [x] **Commit 5:** Add scanner modules (src/scanner/*)
  - Commit: `313e827` (merged via PR #3 — combined with platform modules)
- [x] **Commit 6:** Wire up main.rs + lib.rs
  - CLI with `--quick`, `--out`, `--json`, `--config` flags
  - Orchestrates scan lifecycle across all three platforms
- [x] **Commit 7:** Integration tests + CI + docs
  - 11 integration tests + 3 unit tests (14 total passing)
  - GitHub Actions CI (ubuntu/windows/macos)
  - MIT LICENSE file
  - CONTRIBUTING.md
- [x] **Verify build after each commit**

## Notes

- Commits 2–5 were merged as a single PR (#3) rather than individual commits.
- Additional PRs:
  - PR #2: docs (architecture, development guides)
  - PR #4: docs (mermaid diagram fix, dev guides)

## Roadmap Status

### 1. CI — `.github/workflows/ci.yml`

**Status: Complete**

GitHub Actions workflow created. Runs on ubuntu-latest, windows-latest,
and macos-latest with:

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test`
- `cargo build --release`

### 2. Example Output in README

**Status: Complete**

`## Example Output` section added with a sample plain-text report and a JSON
snippet showing structured severity data.

### 3. Windows / macOS Parity

**Status: Complete (100%)**

All three platforms have process metadata, persistence, and recent file detection.

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Process metadata | Deep: `/proc/*/exe` symlinks, deleted binary detection | Deep: `wmic` with full `ExecutablePath` (tasklist fallback) | Deep: `ps -axo pid,args` with full executable paths |
| Deleted-but-running binaries | Yes (`(deleted)` flag) | No (not possible) | No (not possible) |
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

**Note:** Neither Windows nor macOS can detect deleted-but-running binaries (Linux `/proc` advantage).

### 4. Configurable Detection Patterns

**Status: Complete (100%)**

All detection patterns can now be overridden via an external TOML configuration file.

**Implemented features:**
- `--config path/to/config.toml` CLI flag
- Optional external TOML config file that overrides built-in defaults
- Support for all platform-specific patterns (Windows, macOS, Linux)
- Uses `toml` + `serde` crates for robust parsing with proper error messages
- Example config file: `sentrix.example.toml`

### 5. Structured Output (`--json`)

**Status: Complete**

`Report` struct derives `Serialize` via `serde`. New `--json` CLI flag
produces pretty-printed JSON output. `Report::new()` now includes a
timestamp line.

**Output:**
- Plain text via `report.join()` (default)
- JSON via `report.to_json()` (`--json` flag)

**Severity levels (complete):**
- `Severity { Info, Warning, Critical }` with `log()`, `warn()`, `critical()` methods
  (`flag()` kept as an alias for `warn()`)
- Plain text prefixes: `[CRIT]` for critical, `[!]` for warnings, unmarked info
- JSON includes `severity_counts` and an `entries` array sorted by urgency
  (critical → warning → info)
- Findings count = warnings + criticals; exit code `2` when non-zero

**`--diff` mode (complete):**
- `--diff FILE` compares the current scan against a previous JSON report
- Highlights new findings (critical/warning) since the baseline and resolved findings
- `--json --out baseline.json` writes a reusable baseline; `--diff` supports `--json` output
- Exit code `2` when new findings appeared since baseline, `0` otherwise

### 6. Test Coverage

**Status: Complete (20 tests)**

- `config_loader` — 3 unit tests (valid config, empty config, invalid TOML)
- Integration tests — 17 tests covering:
  - Report behavior (timestamp, section, log, flag, JSON serialization)
  - Severity markers/counts, JSON entries sorted by severity, JSON round-trip
  - Config loading with valid TOML and malformed input
  - Recent-files scanner
  - Pattern constants non-empty per platform
  - Config override flow preservation
  - `--diff` computations (new/resolved findings, no-changes, info ignored)

### 7. Nice-to-Haves

| Feature | Status | Notes |
|---------|--------|-------|
| `--diff` mode | Complete | Compare two scan reports to highlight new findings since last run |
| Severity levels | Complete | `info`/`warn`/`critical` instead of flat `flag`/`log`, JSON output sorted by urgency |
| Example output in README | Complete | Sample terminal output block |
| `CONTRIBUTING.md` | Complete | Contribution guide with PR checklist and style rules |
