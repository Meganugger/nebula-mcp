# Verification report

## Automated checks

The implementation environment did not include `cargo`, `rustc`, `cargo-audit`,
or `cargo-deny`. All baseline Rust checks were therefore recorded as blocked,
not passed. A maintainer must run the following before merging:

```text
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo deny check
cargo build --release
```

On Windows, also run:

```text
cargo test --workspace --features windows-integration
```

## Focused tests added

- Desktop lock ownership rejects a second owner.
- Desktop lock release rejects a non-owner.
- Expired desktop locks return `stale_handle`.

These tests require the Rust toolchain to execute; no success is asserted in
this report until a Rust-enabled CI run records it.

## Manual Windows checks still required

Use a disposable interactive account and a visible test application. Verify
cursor position, `SendInput` partial-dispatch handling, UIPI denial, locked
desktop behavior, and that a forced close is denied unless destructive policy
is explicitly enabled.