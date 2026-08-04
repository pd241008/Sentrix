# Contributing to Sentrix

Thank you for your interest in contributing! This document describes the
workflow for proposing changes to Sentrix.

## Code of Conduct

Be respectful and constructive. We're here to improve a security tool, not
to argue on the internet.

## How to Contribute

### Reporting Issues

- Search existing issues before opening a new one.
- Include your OS, Rust version (`rustc --version`), and steps to reproduce.
- For detection pattern improvements, include the exact command line or file
  content that should be flagged.

### Proposing Changes

1. Open an issue describing the problem or enhancement.
2. Wait for maintainer feedback before writing code.
3. Fork the repo and create a feature branch (`git checkout -b my-fix`).
4. Make your changes, following the style and structure of the existing codebase.
5. Add tests for any new logic.
6. Run `cargo fmt`, `cargo clippy`, and `cargo test` before submitting.
7. Open a pull request with a clear description of the change.

## Development Setup

```bash
git clone https://github.com/<your-org>/sentrix.git
cd sentrix
cargo build
cargo test
```

### Prerequisites

- Rust 1.70+ ([install via rustup](https://rustup.rs))
- For Windows: Administrator terminal for registry access
- For macOS/Linux: `sudo` may be needed for full visibility

## Project Structure

```
src/
├── main.rs                       # CLI entry point, arg parsing
├── lib.rs                        # Library root — public API
├── config.rs                     # Suspicious dirs, patterns, constants
├── report.rs                     # Report struct + output formatting
├── config_loader.rs              # TOML config file parsing
├── scanner/
│   ├── mod.rs                    # Scanner module root
│   ├── processes.rs              # Process location checks
│   ├── persistence.rs            # Persistence mechanism checks
│   └── recent_files.rs           # Recently modified file checks
└── platform/
    ├── mod.rs                    # cfg-gated re-exports
    ├── linux.rs                  # /proc, cron, shell rc
    ├── windows.rs                # tasklist, registry Run keys
    └── macos.rs                  # ps, LaunchAgents/Daemons
```

## Adding a New Check

1. Create `src/scanner/new_check.rs` with a `pub fn run(report: &mut Report)`.
2. Register it in `src/scanner/mod.rs`: `pub mod new_check;`.
3. If platform-specific, add implementation in `src/platform/{linux,windows,macos}.rs`.
4. Call it from `src/main.rs` in the scan sequence.
5. Add constants to `src/config.rs` if needed.
6. Write tests in `tests/integration.rs`.

## Adding a New Platform

1. Create `src/platform/newplatform.rs` exporting:
   - `pub fn check_processes(report: &mut Report)`
   - `pub fn check_persistence(report: &mut Report)`
2. Add cfg gate in `src/platform/mod.rs`:
   ```rust
   #[cfg(target_os = "newplatform")]
   mod newplatform;
   #[cfg(target_os = "newplatform")]
   pub use newplatform::*;
   ```
3. Add platform-specific paths and patterns to `src/config.rs`.

## Style Guide

- Run `cargo fmt` before committing.
- Run `cargo clippy -- -D warnings` and fix all warnings.
- Use `snake_case` for functions and variables.
- Keep functions small and single-purpose.
- Platform-specific code must live behind `#[cfg(target_os = "...")]` gates.
- Do not add dependencies unless absolutely necessary.

## Testing

```bash
cargo test            # run all tests
cargo test -- --nocapture  # show println! output
```

Tests live in two places:

- **Unit tests** — co-located in the source file under `#[cfg(test)] mod tests`.
- **Integration tests** — in `tests/integration.rs`.

When adding a new check, add at least one test that verifies it flags a known
pattern and does not flag a benign string.

## Pull Request Checklist

- [ ] `cargo fmt` has been run
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] New logic is covered by tests
- [ ] README is updated if the change affects usage or configuration
- [ ] `CHANGELOG.md` is updated (if applicable)

## License

By contributing, you agree that your contributions will be licensed under the
MIT License (see [LICENSE](LICENSE)).
