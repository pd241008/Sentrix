# liteguard

A lightweight, cross-platform (Linux / Windows / macOS) heuristic malware
triage scanner, written in Rust with minimal dependencies (std only, plus
`winreg` on Windows for registry access).

It is NOT a full antivirus: no signature database, no cloud lookups, no
quarantine or removal. It flags things worth a human looking at.

## What it checks
- Processes running from suspicious/temp locations
- Deleted-but-running binaries (Linux)
- Persistence:
  - Linux: `/etc/crontab`, `/etc/cron.d/*`, shell rc files (download-and-execute / reverse-shell patterns)
  - Windows: `HKCU`/`HKLM` `...CurrentVersion\Run` and `RunOnce` registry keys
  - macOS: LaunchAgents / LaunchDaemons `.plist` files
- Recently modified files (last 3 days) in sensitive/temp directories

## Build

Requires Rust (rustc 1.70+, install via https://rustup.rs on the target machine).

```
cargo build --release
```

The compiled binary will be at:
- Linux/macOS: `target/release/liteguard`
- Windows: `target\release\liteguard.exe`

Build natively on each OS you want to run it on (or cross-compile with the
appropriate Rust target installed, e.g. `x86_64-pc-windows-gnu`).

## Usage

```
./liteguard                 # full scan, prints to stdout
./liteguard --quick         # skip the recent-file-modification pass
./liteguard --out report.txt
```

On Windows, run from an elevated (Administrator) terminal for full registry
and system-directory access. On macOS/Linux, `sudo` gets you into
root-owned paths you'd otherwise miss.
