# Roadmap

The 0.1.0 release implements the full general-purpose tool surface plus stdio
and remote HTTP transports. This roadmap tracks deepening, hardening, and the
external prerequisites no software can work around.

## Near term

- **Structured tool results** — populate MCP `structuredContent` alongside the
  text JSON so schema-aware clients get typed results.
- **HTTP transport depth** — resumable SSE streams (`Last-Event-ID`), persistent
  per-session state, and optional OAuth2 bearer validation in addition to static
  tokens.
- **Per-tool rate limiting** and a global CPU/memory budget guard in addition to
  the existing per-call bounds.
- **More toolchain helpers** — first-class wrappers for common ecosystems
  (cargo/npm/pnpm/pip/poetry/go/gradle/maven) layered on `terminal.run`, with
  parsed diagnostics.

## Platform depth

- **Native services/registry** via the `windows` crate as an alternative to the
  `sc.exe`/`reg.exe` wrappers, for callers that want to avoid spawning.
- **macOS/Linux system tools** — a `unix` category (launchd/systemd, package
  managers) mirroring the Windows subsystem tools.

## Quality & ops

- **Fuzzing** the JSON-RPC frame decoder and argument parsers.
- **Stress/soak** CI job driving thousands of concurrent calls over both
  transports.
- **Signed release binaries** and MSI/winget/Homebrew packages.
- **OTLP + Prometheus** — OTLP trace export (the `otel` feature) and a Prometheus
  `/metrics` endpoint (`--metrics-addr`) are implemented; richer histogram export
  is the next step.

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
