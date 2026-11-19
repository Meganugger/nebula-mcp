# Implementation progress

## Baseline

Baseline was captured before the desktop slice was changed. The repository
checkout was clean on `feature/universal-computer-mcp` at commit `237b0e7`.
The requested commands were attempted in the execution environment:

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | blocked: `cargo` is not installed |
| `cargo check --workspace` | blocked: `cargo` is not installed |
| `cargo test --workspace` | blocked: `cargo` is not installed |
| `cargo clippy --workspace --all-targets -- -D warnings` | blocked: `cargo` is not installed |
| `cargo audit` | blocked: `cargo` is not installed |
| `cargo deny check` | blocked: `cargo` is not installed |
| `cargo build --release` | blocked: `cargo` is not installed |

No platform-specific success is claimed from these blocked checks.

## Current slice

- `implemented`: explicit `allow_desktop_mutation` policy gate and per-tool
  override.
- `implemented`: process-local, owner-bound, expiring desktop resource leases
  with bounded acquisition wait and deterministic `resource_busy`/`stale_handle`
  errors.
- `implemented`: registered desktop lock, display, cursor, window, and input
  tools with bounded schemas.
- `implemented`: Windows input dispatch uses a fixed `SendInput` helper and
  reports partial dispatch through the command result.
- `partially_implemented`: desktop discovery uses Windows PowerShell wrappers;
  exact monitor bounds, DPI mapping, UI Automation, capture, and a separate
  interactive desktop agent remain future slices.
- `deferred`: privileged broker, authenticated named-pipe IPC, ConPTY,
  Playwright session manager, hardware privacy APIs, installer, and operator
  approval records.

## CI repair verification

The failing CI jobs were reproduced locally after installing Rust 1.89. The
failure was the first-step formatting gate: `crates/tools/src/desktop.rs` was
not rustfmt-clean. After formatting that file, the local verification passed:

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | passed |
| `cargo check --workspace` | passed |
| `cargo test --workspace` | passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | passed |
| `cargo build --release` | passed |
| `python3 scripts/check_tools_doc.py` | passed |

The Windows integration lane still requires a disposable interactive Windows
account; no Windows-only runtime success is claimed from the Linux runner.
Do not mark the deferred or partial items as implemented without that evidence.