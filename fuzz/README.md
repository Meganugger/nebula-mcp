# Fuzzing

libFuzzer harnesses for the parsers that face untrusted input.

## Targets

| Target | What it fuzzes |
|---|---|
| `frame_decoder` | The newline-delimited JSON-RPC frame decoder (`FrameReader`) against arbitrary byte streams. |
| `args_parser` | `CallToolParams` deserialisation and the typed `Args` accessors against arbitrary JSON documents. |

## Running

Requires a nightly toolchain and [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run frame_decoder
cargo +nightly fuzz run args_parser
```

Each target asserts the invariant that malformed input is answered with a
structured error — never a panic, hang or unbounded allocation.

The plain-CI regression net (no nightly needed) is the deterministic
`decoder_survives_random_byte_streams` test in
`crates/protocol/src/transport.rs`.
