# Verification report

## Automated checks

The original baseline was blocked because the implementation environment did
not include `cargo`, `rustc`, `cargo-audit`, or `cargo-deny`. The failing
Linux, Windows, and macOS CI jobs were then reproduced as a formatting failure
in `crates/tools/src/desktop.rs`; the cross-platform cross-check, MSRV, and
dependency-audit jobs had already passed.

After formatting the source, the following checks passed locally with Rust
1.89:

```text
cargo fmt --all --check                 # passed
cargo check --workspace                 # passed
cargo test --workspace                  # passed
cargo clippy --workspace --all-targets -- -D warnings  # passed
cargo build --release                   # passed
python3 scripts/check_tools_doc.py      # passed
```

On Windows, also run:

```text
cargo test --workspace --features windows-integration
```

## Focused tests added

- Desktop lock ownership rejects a second owner.
- Desktop lock release rejects a non-owner.
- Expired desktop locks return `stale_handle`.

The repository CI run after this repair is the merge gate; these local results
only confirm the source-level failure and its fix.

## Manual Windows checks still required

Use a disposable interactive account and a visible test application. Verify
cursor position, `SendInput` partial-dispatch handling, UIPI denial, locked
desktop behavior, and that a forced close is denied unless destructive policy
is explicitly enabled.