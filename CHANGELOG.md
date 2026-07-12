# Changelog

All notable changes to the Nebula MCP server are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/) and the project adheres
to [Semantic Versioning](https://semver.org/).

## [0.2.0] - Unreleased

Deepening and hardening release: every software-implementable item from the
0.1.0 roadmap's "Near term", "Platform depth" and "Quality & ops" sections.

### Added

- **Structured tool results**: every tool now populates MCP
  `structuredContent` alongside the pretty-printed text JSON, so schema-aware
  clients get typed results. Error results carry a structured
  `{error: {category, message}}` payload.
- **HTTP transport depth** (`nebula-mcp-server::http`):
  - **Persistent per-session state** — `initialize` mints an `Mcp-Session-Id`;
    subsequent requests echo it, unknown/expired ids answer `404` (client
    re-initializes), `DELETE` tears the session down, and idle sessions expire
    after `transport.http.session_idle_secs` (default 1800 s).
  - **Resumable SSE streams** — every server-initiated event carries a
    monotonically increasing SSE `id`; reconnecting with `Last-Event-ID`
    replays missed events from a bounded buffer
    (`transport.http.sse_replay_events`, default 256) before the live stream
    resumes.
  - **OAuth2 bearer validation** — optional RFC 7662 token introspection
    (`[transport.http.oauth]`: introspection URL, client credentials, required
    scopes) in addition to static tokens, with a digest-keyed verdict cache.
- **Per-tool rate limiting**: `security.rate_limit_per_minute` (sliding
  60-second window) with per-tool `[tools."<name>"] rate_limit_per_minute`
  overrides (`0` = unlimited). Rejections are retryable tool errors with the
  new `rate_limited` category (JSON-RPC code `-32003`).
- **Global CPU/memory budget guard**: `security.max_memory_bytes` and
  `security.max_cpu_percent` reject *new* calls (retryable
  `resource_exhausted` errors) while the server process exceeds budget;
  in-flight calls are never killed. Sampling is throttled to 2 Hz via
  `sysinfo`.
- **toolchain category (8 tools)**: first-class wrappers for
  cargo/npm/pnpm/pip/poetry/go/gradle/maven layered on the hardened executor,
  each returning **parsed diagnostics** (severity, message, file:line:col,
  tool-specific code) plus error/warning counts — rustc headers and `-->`
  locations, libtest/go-test failures, `go` `file:line:col` errors,
  `npm ERR!`/`ERR_PNPM_*`, pip/poetry errors, Kotlin/javac/gradle task
  failures, and Maven `[ERROR] file:[line,col]` forms.
- **unix category (5 tools)** mirroring the Windows subsystem tools:
  `unix.service` (systemctl/launchctl), `unix.package`
  (apt/dnf/yum/pacman/zypper/apk/brew with elevation/destructive gating),
  `unix.logs` (journalctl JSON / `log show`), `unix.cron` and `unix.sysctl`.
  All go through the command allowlist; Windows hosts get a structured
  `platform_unsupported` error, exactly mirroring the `windows` category.
- **Prometheus histograms**: the metrics endpoint now exports a full
  per-tool `nebula_mcp_tool_duration_seconds` histogram (`_bucket` with 12
  finite `le` bounds from 1 ms to 5 min, `_sum`, `_count`) alongside the
  existing counters/gauges.
- **Fuzzing**: `cargo-fuzz` harnesses for the JSON-RPC frame decoder and the
  tool-argument parsers (`fuzz/`), plus a deterministic in-tree mini-fuzz
  regression test that runs in plain CI.
- **Stress/soak suite**: `crates/server/tests/stress.rs` drives thousands of
  concurrent calls through the engine, the stdio framing loop and the real
  HTTP transport; CI runs it in a dedicated job.
- **Release pipeline**: `.github/workflows/release.yml` builds
  Linux/macOS(x64+arm64)/Windows binaries on tags, publishes SHA-256
  checksums, and signs the manifest with Sigstore cosign (keyless OIDC).
- Introspection surfaces the new policy: `security.effective_policy` reports
  `rateLimitPerMinute`; `diagnostics.config` reports rate limit and resource
  budgets; `diagnostics.capabilities` probes the new toolchain and unix
  binaries.

### Changed

- Tool count grows from 110 to **123 across 15 categories**.
- `error_codes::RESOURCE_LIMITED` (`-32003`) added for rate-limit/budget
  rejections.
- HTTP startup validation: `require_auth` without static tokens is accepted
  when OAuth introspection is enabled; enabling OAuth without an
  introspection URL is refused.

## [0.1.0] - Unreleased

Initial release of Nebula MCP as a standalone, **general-purpose** autonomous
software-engineering MCP server, extracted from the NebulaDisplay project and
made project-agnostic, with a new remote HTTP transport.

### Added

- **MCP protocol** (`nebula-mcp-protocol`): JSON-RPC 2.0 types, MCP 2024-11-05
  domain types, and a newline-delimited JSON stdio transport.
- **Remote HTTP transport** (`nebula-mcp-server::http`): the MCP **Streamable
  HTTP** binding on `axum` — `POST /mcp` (JSON-RPC request/response), `GET /mcp`
  (SSE notification stream), `DELETE /mcp` (session teardown), bearer-token
  authentication (constant-time compared), an Origin allow-list, a body-size cap
  and a startup guard that refuses non-loopback binds without auth. Enable via
  `[transport.http]`, `--http`/`--http-addr`, or `NEBULA_MCP_HTTP_ADDR`. This
  lets the server be reached by a URL from an AI platform.
- **Runtime core** (`nebula-mcp-core`):
  - TOML configuration with an atomically-swappable store and debounced hot
    reload, now including a `[transport]` section.
  - A permission engine (`EffectivePolicy`) covering path allow/deny globs with
    lexical `..` containment, command allowlisting, timeouts, a hard runtime
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
  - **diagnostics** (7): capability probe, live per-tool metrics, effective-config
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
- **Tests**: 110 unit + integration tests, including permission enforcement,
  process timeout/cancellation, concurrent-dispatch stress, JSON-RPC decoder
  robustness, resources/prompts/logging coverage, and a real end-to-end HTTP
  transport suite (auth rejection, initialize, tools/list + tools/call, 202 for
  notifications, parse-error handling).
- **CI**: Linux (build, test, clippy `-D warnings`, fmt) and a Linux→Windows
  cross-check.
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
