# Development Guide

This document covers how Sentrix is developed, the conventions used,
and the reasoning behind our workflow.

---

## Prerequisites

- **Rust 1.70+** — install via [rustup](https://rustup.rs)
- **Git** — for version control
- **No other tools required** — no Docker, no cmake, no pkg-config

---

## Project Conventions

### File Naming

| Convention | Example |
|------------|---------|
| Modules are `snake_case` | `recent_files.rs`, `check_processes()` |
| Constants are `SCREAMING_SNAKE_CASE` | `RECENT_FILE_DAYS`, `SUSPICIOUS_PLIST_PATTERNS` |
| Platform modules match OS name | `linux.rs`, `windows.rs`, `macos.rs` |

### Module Structure

```
src/
├── lib.rs          ← always just `pub mod` declarations
├── main.rs         ← CLI only, no logic
├── config.rs       ← constants, no functions with side effects
├── report.rs       ← data structure + formatting
├── platform/       ← one file per OS, same public API
│   └── mod.rs      ← cfg-gated re-exports
└── scanner/        ← one file per check type
    └── mod.rs      ← submodule declarations
```

**Rule:** `lib.rs` should never contain logic — only `pub mod` declarations.
All logic lives in the modules it declares.

### Code Style

- **No comments unless asked.** Code should be self-documenting through
  clear naming and structure.
- **No `unwrap()` in production code.** Use `match`, `if let`, or
  `.unwrap_or_default()` for graceful degradation.
- **Prefer `flatten()` over manual error handling** in iteration:
  `entries.flatten()` instead of `if let Ok(e) = entry { ... }`.
- **Platform code uses `#[cfg]` only in `platform/mod.rs`.** Individual
  platform files should never contain `#[cfg]` — they are already gated
  at the module level.

### Error Handling

Sentrix is a triage tool — it should never crash on a bad read. Pattern:

```rust
// Good — logs and continues
let entries = match fs::read_dir(proc_dir) {
    Ok(e) => e,
    Err(_) => {
        report.log("(i) Could not read /proc.");
        return;
    }
};

// Bad — panics
let entries = fs::read_dir(proc_dir).unwrap();
```

---

## Commit Convention

We use **conventional commits** with a modular structure:

```
<type>: <description>
```

### Types

| Type | When |
|------|------|
| `skeleton` | Initial project structure |
| `feat` | New module or feature |
| `fix` | Bug fix or correction |
| `docs` | Documentation only |
| `refactor` | Code restructuring, no behavior change |
| `test` | Adding or updating tests |
| `chore` | Build config, CI, dependencies |

### Modular Commits

Each commit should be **one logical change**:

```
✅ feat: add config module with suspicious dirs and pattern constants
✅ feat: add platform and scanner modules with cross-platform checks
✅ docs: rename to sentrix, add architecture docs with mermaid diagrams

❌ feat: add everything at once
❌ fix: changed a bunch of stuff
```

### Commit Atomicity

Each commit should:

1. **Compile.** `cargo build` must pass.
2. **Be self-contained.** It should make sense on its own, not require
   the next commit to understand.
3. **Not break the previous state.** If a commit adds a module, the
   project should still build without using it yet.

---

## Branch Strategy

```
main          ← stable, production-ready
  └── dev     ← active development
       └── feature/*   ← individual features
```

- `main` is always deployable.
- `dev` is the integration branch.
- Feature branches are created from `dev` and merged back.
- Commits are made on feature branches, then merged.

---

## How to Add a New Check

1. **Create** `src/scanner/new_check.rs`:
   ```rust
   use crate::report::Report;
   use crate::platform;

   pub fn run(report: &mut Report) {
       platform::check_new_thing(report);
   }
   ```

2. **Register** in `src/scanner/mod.rs`:
   ```rust
   pub mod new_check;
   ```

3. **Implement** platform-specific logic in `src/platform/{linux,windows,macos}.rs`.

4. **Add constants** to `src/config.rs` if needed.

5. **Wire up** in `src/main.rs`:
   ```rust
   scanner::new_check::run(&mut report);
   ```

6. **Test** with `cargo test`.

---

## How to Add a New Platform

1. **Create** `src/platform/bsd.rs` (or whatever).

2. **Export** the standard interface:
   ```rust
   pub fn check_processes(report: &mut Report) { ... }
   pub fn check_persistence(report: &mut Report) { ... }
   ```

3. **Add cfg gate** in `src/platform/mod.rs`:
   ```rust
   #[cfg(target_os = "freebsd")]
   mod bsd;
   #[cfg(target_os = "freebsd")]
   pub use bsd::*;
   ```

4. **Add platform paths** to `src/config.rs`.

---

## Testing

```bash
cargo test                        # run all tests
cargo test -- --nocapture         # show println! output
cargo test test_report            # run tests matching name
```

### Test Organization

| Location | What it tests |
|----------|--------------|
| `tests/integration.rs` | Cross-module behavior, public API |
| `src/*/tests.rs` (future) | Module-internal logic |

### What to Test

- **Config:** suspicious dirs are non-empty, constants are correct.
- **Report:** `flag()` increments count, `section()` adds header.
- **Scanner edge cases:** nonexistent dirs, empty files, permission errors.
- **Platform-specific:** only on the target OS (use `#[cfg]` in tests).

---

## Release Builds

```bash
cargo build --release
```

Release profile settings in `Cargo.toml`:

| Setting | Value | Why |
|---------|-------|-----|
| `opt-level = "z"` | Optimize for size | Smaller binary for distribution |
| `lto = true` | Link-Time Optimization | Dead code elimination, smaller binary |
| `strip = true` | Strip debug symbols | Further size reduction |

The resulting binary is typically **under 500KB** on Linux.

---

## Common Pitfalls

### 1. Forgetting `#[cfg]` gates

If you add code to `platform/linux.rs` that references Windows-only
types, it will fail on Windows builds. Each platform file should only
use APIs available on that platform.

### 2. Circular module dependencies

`platform` depends on `scanner::recent_files`, and `scanner` depends on
`platform`. This works in Rust because modules are compiled together,
but it's a design smell. If it becomes problematic, move `recent_files`
to a `util/` module.

### 3. Using `unwrap()` in scan code

The scanner runs on potentially compromised systems. File reads may
fail due to permissions, race conditions, or tampering. Always handle
errors gracefully.

### 4. Adding deps without justification

Every dependency is a liability. Before adding one, ask:

- Can I implement this in ~50 lines with `std`?
- Is this dependency well-maintained and audited?
- Does this justify the binary size increase?

---

## Project Layout Reference

```
Sentrix/
├── Cargo.toml                        # Package metadata
├── README.md                         # User-facing docs
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md               # Why we built it this way
│   └── DEVELOPMENT.md                # How to work on it
├── src/
│   ├── main.rs                       # CLI entry point
│   ├── lib.rs                        # Library root
│   ├── config.rs                     # Constants & paths
│   ├── report.rs                     # Report struct
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── processes.rs
│   │   ├── persistence.rs
│   │   └── recent_files.rs
│   └── platform/
│       ├── mod.rs
│       ├── linux.rs
│       ├── windows.rs
│       └── macos.rs
└── tests/
    └── integration.rs
```
