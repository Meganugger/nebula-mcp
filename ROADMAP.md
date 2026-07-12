# Roadmap

The 0.1.0 release implemented the full general-purpose tool surface plus stdio
and remote HTTP transports. The 0.2.0 release shipped everything from the
previous roadmap that is implementable and verifiable in software. This
roadmap tracks what remains.

## Shipped in 0.2.0 (no longer roadmap items)

- **Structured tool results** — MCP `structuredContent` is populated alongside
  the text JSON on every tool result (typed success payloads and structured
  error objects).
- **HTTP transport depth** — resumable SSE streams (monotonic event ids +
  `Last-Event-ID` replay from a bounded buffer), persistent per-session state
  (`Mcp-Session-Id` minted on initialize, 404 on expiry, `DELETE` teardown,
  idle expiry), and optional OAuth2 bearer validation via RFC 7662 token
  introspection (cached verdicts, required-scope checks) in addition to static
  tokens.
- **Per-tool rate limiting** (`security.rate_limit_per_minute` + per-tool
  overrides, sliding window) and a **global CPU/memory budget guard**
  (`security.max_memory_bytes` / `max_cpu_percent`) in addition to the
  existing per-call bounds. Both reject retryably (`rate_limited` /
  `resource_exhausted`).
- **Toolchain helpers** — first-class wrappers for
  cargo/npm/pnpm/pip/poetry/go/gradle/maven layered on the hardened executor,
  with parsed diagnostics (severity, file:line:col, codes, test failures).
- **macOS/Linux system tools** — the `unix` category (systemd/launchd
  services, package managers, journalctl/log, cron, sysctl) mirroring the
  Windows subsystem tools.
- **Fuzzing** — cargo-fuzz harnesses for the JSON-RPC frame decoder and the
  argument parsers (`fuzz/`), plus a deterministic mini-fuzz regression test
  in plain CI.
- **Stress/soak CI job** — thousands of concurrent calls driven through the
  engine, the stdio framing loop and the real HTTP transport
  (`crates/server/tests/stress.rs`).
- **Release binaries** — a tag-triggered release workflow building
  Linux/macOS/Windows binaries with SHA-256 checksums and Sigstore cosign
  (keyless) signatures.
- **Prometheus histograms** — full per-tool
  `nebula_mcp_tool_duration_seconds` histogram export alongside the existing
  counters (OTLP trace export was already in via the `otel` feature).

## Remaining

- **Native services/registry** via the `windows` crate as an alternative to
  the `sc.exe`/`reg.exe` wrappers, for callers that want to avoid spawning.
  *Deliberately deferred: it is Windows-only FFI that cannot be
  runtime-verified off a real Windows host; the spawning wrappers cover the
  functionality today.*
- **HTTP transport**: streaming tool responses onto the POST SSE channel
  (currently responses are plain JSON; notifications stream over GET).
- **Package-manager packaging** — MSI/winget/Homebrew manifests on top of the
  signed release artifacts (requires publisher accounts outside the repo).
- **Richer OAuth** — JWT/JWKS local validation as an alternative to
  introspection round-trips.

## External limitations (not solvable in software)

These require environment provisioning outside the server's control; see
[SECURITY.md](SECURITY.md):

- **TLS for remote exposure** must be terminated by a tunnel or reverse proxy;
  the server itself speaks plain HTTP behind it.
- **QUIC/HTTP3 probing** needs a `curl` built with HTTP/3.
- **Browser tools** need Node.js + Playwright (with browser binaries) installed.
- **Crash-dump/ETW tools** need the matching Windows SDK tooling (`cdb`,
  `procdump`, `logman`) and, in some cases, elevation. The server reports a
  `tool_not_found` error naming any missing external tool.
