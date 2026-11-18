# Changelog

All notable changes to the Nebula MCP server are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and the project adheres
to [Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

Security and protocol overhaul; this release intentionally contains breaking
configuration, transport, and execution-policy changes.

### Security and runtime

- Added a written threat model and central dispatcher JSON-Schema validation.
- Resolved existing symlink components before path policy checks; built-in
  secret deny patterns are always merged with operator patterns; recursive
  discovery omits denied entries and recursive mutations validate every entry.
- Changed network access to opt-in (`allow_network = false`), disabled HTTP
  redirects, rejected local/private URL destinations, and restricted GitHub
  bearer tokens to `api.github.com`.
- Hardened child process environment inheritance and process-group cleanup,
  including cancellation, timeout, and session-close paths.
- Isolated tool panics to their request and added a Rustls crypto provider.
- Treated Docker daemon access as elevated and gated networked Git operations.

### Protocol and transport

- Added current MCP `2026-07-28` per-request metadata, `server/discover`,
  modern result metadata, request-header validation, and legacy compatibility.
- Legacy HTTP negotiation state is keyed by each client's session identifier;
  current requests do not receive a legacy session header.
- Raised the declared MSRV to Rust 1.89 to match the current dependency lockfile.
- Rejected option-looking values across typed Git positional arguments.
- Removed the client-controlled debugger command string from
  `diagnostics.analyze_dump`; it now runs only the fixed analysis command.
- Added an 8 MiB stdio JSON frame limit with oversized-frame recovery.

The original 0.1.0 release of Nebula MCP as a standalone,
**general-purpose** autonomous software-engineering MCP server, extracted from
the NebulaDisplay project and made project-agnostic, with a new remote HTTP
transport.

### Added

- **MCP protocol** (`nebula-mcp-protocol`): JSON-RPC 2.0 types, MCP 2026-07-28
  domain types, and a newline-delimited JSON stdio transport.
- **Remote HTTP transport** (`nebula-mcp-server::http`): the MCP **Streamable
  HTTP** binding on `axum` — current metadata-based `POST /mcp` plus legacy
  compatibility handling, legacy SSE notification stream, `DELETE /mcp`
  (session teardown), bearer-token
  authentication (constant-time compared), an Origin allow-list, a body-size cap
  and a startup guard that refuses non-loopback binds without auth. Enable via
  `[transport.http]`, `--http`/`--http-addr`, or `NEBULA_MCP_HTTP_ADDR`. This
  lets the server be reached by a URL from an AI platform.
- **Runtime core** (`nebula-mcp-core`):
  - TOML configuration with an atomically-swappable store and debounced hot
    reload, now including a `[transport]` section.
  - A permission engine (`EffectivePolicy`) covering symlink-aware path
    allow/deny globs with `..` containment, command allowlisting, timeouts, a hard runtime
    ceiling, output caps, and elevation/network/destructive gates.
  - Structured `tracing` telemetry (JSON/pretty to stderr, optional rotating
    files, optional OpenTelemetry OTLP export behind the `otel` feature) and
    lock-free per-tool metrics.
  - The `Tool` trait, a registry honouring category/tool enable switches, and a
    per-call `ToolContext` with unified timeout + cancellation.
- **110 tools** (`nebula-mcp-tools`) across 13 general-purpose categories:
  - **filesystem** (14): read/write/edit/append/rename/delete/move/copy, content
    search, glob, tree, hash, metadata, permissions, with large-file streaming
    and binary-safe base64 read/write.
  - **terminal** (6): one-shot run plus persistent interactive sessions.
  - **process** (3): list/info/kill via `sysinfo`.
  - **git** (24): the full everyday command surface plus worktree, cherry-pick,
    revert, reflog, show and apply.
  - **github** (13): clone, a generic authenticated REST tool, and convenience
    tools for PRs, issues, forks, releases, actions, branches, reviews, labels.
  - **network** (11): HTTP(S), file download, DNS, TCP connect, latency
    sampling, native TLS inspection, WebSocket, ping, iperf3, packet capture,
    QUIC/HTTP3 probe.
  - **powershell** (3): non-interactive, elevated, and remote execution.
  - **windows** (8): services, registry, event log, performance counters,
    scheduled tasks, environment, firewall, network adapters.
  - **diagnostics** (9): capability probe, live per-tool metrics, effective-config
    summary, WER reports, crash-dump discovery, process dump creation, minidump
    analysis, live stack capture, ETW sessions.
  - **browser** (2): Playwright-driven capture (screenshot/PDF/trace/console/
    network) and a screenshot convenience.
  - **docker** (9): ps, images, build, run, stop, rm, logs, exec, and compose.
  - **scheduler** (5): run allowlisted commands after a delay or on an interval
    and poll their captured results.
  - **security** (3): dry-run the permission engine — `check_path`,
    `check_command` and `effective_policy`.
- **Progress streaming**: any command-wrapping tool emits MCP
  `notifications/progress` when the client supplies a `progressToken`.
- **Resources**: `resources/list`, `resources/read`, and `resources/subscribe`
  (with `notifications/resources/updated` via a debounced file watcher).
- **Prompts**: curated engineering workflows (crash-dump triage, build-failure
  investigation, PR review, bisect, and project scaffolding).
- **Runtime log control**: `logging/setLevel`.
- **Prometheus metrics**: optional `--metrics-addr`.
- **Server** (`nebula-mcp-server`): concurrent, cancellable dispatch with bounded
  parallelism, graceful shutdown, and a CLI (`run`, `list-tools`, `print-config`,
  `validate-config`).
- **Tests**: workspace tests covering permission enforcement,
  process timeout/cancellation, concurrent-dispatch stress, JSON-RPC decoder
  robustness, resources/prompts/logging coverage, and a real end-to-end HTTP
  transport suite (auth rejection, initialize, tools/list + tools/call, 202 for
  notifications, parse-error handling).
- **CI**: Linux, macOS, and Windows builds/tests, a Linux→Windows cross-check,
  MSRV, and dependency audit.
- **Docs**: README, ARCHITECTURE, SECURITY, CONFIGURATION, TOOLS, API, RUNBOOK,
  ROADMAP.

### Changed from the original in-tree version

- Removed the NebulaDisplay-specific tool categories — `driver` (IddCx/WDK
  driver toolchain), `display` (QueryDisplayConfig/DXGI/DWM), and `benchmark`
  (PresentMon/WPR/GPUView/LatencyMon) — leaving a project-agnostic tool surface.
- Rebranded from "NebulaDisplay MCP" to "Nebula MCP".

### Notes

- Windows-only tools compile on all platforms and return a structured
  `platform_unsupported` error off Windows.
- External limitations (TLS for remote exposure, HTTP/3 `curl`, Node+Playwright,
  Windows crash-dump/ETW tooling) are documented in SECURITY.md and ROADMAP.md.
