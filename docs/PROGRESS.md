# Sentrix — Development Progress

## Commit Plan

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
- [ ] **Commit 6:** Wire up main.rs + lib.rs to use all modules
- [ ] **Commit 7:** Add integration tests
- [x] **Verify build after each commit**

## Notes

- Commits 2–5 were merged as a single PR (#3) rather than individual commits.
- Additional PRs:
  - PR #2: docs (architecture, development guides)
  - PR #4: docs (mermaid diagram fix, dev guides)
- Current branch: `feature/production-structure`

## Remaining Work

1. **Commit 6 — Wire up main.rs + lib.rs**
   - Implement CLI argument parsing (e.g. `clap`)
   - Add `--quick` and `--out` flags (per README)
   - Orchestrate scan lifecycle: run platform checks, collect report, output results
   - Connect `lib.rs` public API so the binary calls into `scanner` and `report`

2. **Commit 7 — Add integration tests**
   - Populate `tests/integration.rs`
   - Test Report struct behavior
   - Test Config output
   - Test Scanner edge cases

---

## Roadmap Status

### 1. CI — `.github/workflows/ci.yml`

**Status: Not started**

No `.github/` directory exists. Needs a GitHub Actions workflow that:

- Runs `cargo build` and `cargo test` on ubuntu-latest, windows-latest, macos-latest
- Runs `cargo clippy -- -D warnings`
- Runs `cargo fmt --check`
- Adds resulting badge to README header

This is the highest-impact, lowest-effort item. It proves cross-platform
support is real rather than claimed.

### 2. Example Output in README

**Status: Not started**

No `## Example Output` section exists. Needs a sample terminal output
block showing what `./Sentrix` prints when run — the `[!]` flagged
findings, section headers, and informational log lines. Fake/redacted
findings are fine. 10-minute addition with outsized trust payoff.

### 3. Windows / macOS Parity

**Status: High (~85%)**

All three platforms have process metadata, persistence, and recent file detection.

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Process metadata | Deep: `/proc/*/exe` symlinks, deleted binary detection | Deep: `wmic` with full `ExecutablePath` (tasklist fallback) | Deep: `ps -axo pid,args` with full executable paths |
| Deleted-but-running binaries | Yes (`(deleted)` flag) | No | No |
| Persistence — cron | `/etc/crontab`, `/etc/cron.d/*` | — | `/etc/crontab`, `/etc/cron.d/*`, per-user `crontab -l` |
| Persistence — shell rc | `.bashrc`, `.profile` download-exec patterns | — | — |
| Persistence — registry | — | `HKCU`/`HKLM` `Run` + `RunOnce` keys | — |
| Persistence — scheduled tasks | N/A | `schtasks /query` with action pattern matching | N/A |
| Persistence — launch agents | — | — | On-disk plist scan + `launchctl list` cross-reference |
| Recently modified files | `/tmp`, `/dev/shm`, `/var/tmp` | `%LOCALAPPDATA%\Temp`, `C:\Users\Public` | `/tmp`, `/var/tmp`, `/private/tmp`, `/Users/Shared` |

**Remaining gaps:**
- **Windows:** Could add WMI process metadata for even richer info.
- **macOS:** Could cross-reference launchctl PIDs against on-disk plists more deeply.
- **Neither** Windows nor macOS can detect deleted-but-running binaries (Linux `/proc` advantage).

### 4. Configurable Detection Patterns

**Status: Hardcoded only (~20%)**

All detection patterns live in `src/config.rs` as compile-time constants.
No external config file loading exists. No `--config` CLI flag. Changing
any pattern requires modifying `config.rs` and recompiling.

**Needs:**

- Optional external TOML/YAML config file that overrides built-in defaults
- `--config path/to/config.toml` CLI flag
- Keep "zero runtime deps" philosophy — parse manually or accept `serde` + `toml` as a deliberate exception

### 5. Structured Output (`--json`)

**Status: Not started (0%)**

Output is plain text only. `Report` stores findings as `Vec<String>`
with a simple `join()`. No `serde` or `serde_json` dependency. No
`--json` CLI flag. `ARCHITECTURE.md` documents a future `Severity`
enum + `Finding` struct plan but it is not implemented.

**Needs:**

- `enum Severity { Info, Warning, Critical }`
- `struct Finding { severity, category, message, source }`
- `--json` CLI flag producing JSON output
- Transforms Sentrix from "human reads report" to "SOC pipeline input"

### 6. Test Coverage

**Status: Not started (~0%)**

`tests/integration.rs` exists but contains only `// Integration tests`
as a comment. Zero actual test functions. No unit tests in any source
file. No coverage tooling (tarpaulin, grcov). No coverage badge.

The README claims "Tests cover: Report struct behavior, Config output,
Scanner edge cases" but this is aspirational, not accurate.

**Needs:**

- Populate `tests/integration.rs` with actual test cases
- Unit tests per suspicious pattern in `config.rs` (one test per regex/pattern)
- `cargo tarpaulin` (Linux) or `grcov` for coverage reporting
- Coverage badge in README

### 7. Nice-to-Haves (after 1–6 land)

| Feature | Status | Notes |
|---------|--------|-------|
| `--diff` mode | Not started | Compare two scan reports to highlight new findings since last run |
| Severity levels | Not started | `info`/`warn`/`critical` instead of flat `flag`/`log`, output sorted by urgency |
| `CONTRIBUTING.md` | Not started | Split from existing README sections + `DEVELOPMENT.md` content |
