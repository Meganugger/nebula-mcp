# Nebula MCP

**A production-grade, general-purpose [Model Context Protocol](https://modelcontextprotocol.io) server that turns your machine into a full autonomous software-engineering environment for any AI agent.**

Point an AI platform at Nebula MCP — over a local stdio pipe *or a remote URL* — and it gains a governed, security-gated ability to read and write files, run builds and tests, drive git and GitHub, exercise the network, manage containers, automate a browser, and (on Windows) inspect services, the registry, event logs and crash dumps. In short: everything needed to **design, build, test and ship any program end-to-end**.

> Nebula MCP began as the engineering backend for a Windows display project and has been extracted into a standalone, project-agnostic server. It carries no application-specific tooling — it is meant to be reused across all of your projects.

---

## Why Nebula MCP

- **118 tools across 14 categories**, all designed for autonomous coding agents.
- **Two transports.** Local **stdio** for editors (Claude Code, Cursor, Codex, Zed…) and remote **Streamable HTTP** so you can expose a **URL** to a hosted AI platform.
- **Security-first.** Nothing is permitted by default. Every call is checked against an allowlist-based permission policy (paths, commands, elevation, network, destructive ops) before it runs. Paths are symlink-aware and denied entries are filtered recursively. No shell interpolation — arguments are passed verbatim.
- **Robust runtime.** Bounded concurrency, per-call timeouts and a hard runtime ceiling, cooperative cancellation, output caps, structured logging, Prometheus metrics and optional OpenTelemetry.
- **Fast and small.** Rust + Tokio, four tight crates, no `unsafe` in the protocol layer.

---

## Tool categories

| Category | Tools | What it does |
| --- | --- | --- |
| `filesystem` | 14 | read/write/edit/search/glob/tree/hash/metadata/permissions, streaming + base64 |
| `terminal` | 6 | run allowlisted commands **and** persistent interactive shell/REPL sessions |
| `process` | 3 | list / inspect / kill processes |
| `git` | 24 | status, diff, blame, log, branch, checkout, merge, rebase, stash, tag, bisect, commit, push/pull/fetch, reset, clean, submodule, worktree, cherry-pick, revert, reflog, show, apply |
| `github` | 13 | clone, arbitrary authenticated REST, PRs, issues, forks, releases, Actions runs, reviews, labels |
| `network` | 11 | HTTP(S), download, DNS, TCP/latency, native TLS inspection, WebSocket, ping, iperf3, packet capture, HTTP/3 probe |
| `docker` | 9 | ps, images, build, run, stop, rm, logs, exec, compose |
| `scheduler` | 5 | deferred and recurring background jobs with captured results |
| `security` | 3 | dry-run the path/command policy and inspect the effective policy for any tool |
| `browser` | 2 | Playwright navigation + screenshot/PDF/trace/console/network capture |
| `desktop` | 8 | Lease-coordinated Windows window enumeration, pointer, keyboard, and focus control |
| `powershell` | 3 | non-interactive, elevated and remote PowerShell *(Windows)* |
| `windows` | 8 | services, registry, event log, perf counters, scheduled tasks, env, firewall, adapters *(Windows)* |
| `diagnostics` | 9 | toolchain capabilities, live metrics, config summary, WER, crash dumps, procdump, cdb analyze, ETW *(mostly Windows)* |

Cross-platform categories work on Linux/macOS/Windows. Windows-only tools compile everywhere but return `platform_unsupported` off Windows. See [TOOLS.md](TOOLS.md) for every tool and argument.

---

## Quick start

### 1. Build

```bash
cargo build --release        # binary at target/release/nebula-mcp
```

### 2. Write a config

Generate a documented starting point and tighten the allowlists:

```bash
./target/release/nebula-mcp print-config > nebula-mcp.toml
```

At minimum, grant the paths and commands your work needs:

```toml
[security]
allowed_paths    = ["/home/me/projects/**"]
allowed_commands = ["git", "cargo", "npm", "node", "python", "go", "docker"]
```

### 3a. Run over stdio (local editors)

```bash
./target/release/nebula-mcp run --config nebula-mcp.toml
```

Register it with an MCP-capable editor, e.g. Claude Code:

```json
{
  "mcpServers": {
    "nebula": {
      "command": "/abs/path/target/release/nebula-mcp",
      "args": ["run", "--config", "/abs/path/nebula-mcp.toml"]
    }
  }
}
```

### 3b. Run over remote HTTP (expose a URL)

```bash
export NEBULA_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
./target/release/nebula-mcp run --config nebula-mcp.toml --http --http-addr 127.0.0.1:8765
```

The server now speaks the **MCP Streamable HTTP** transport at `http://127.0.0.1:8765/mcp`. Verify it:

```bash
curl -s http://127.0.0.1:8765/mcp \
  -H "Authorization: Bearer $NEBULA_MCP_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/list" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

---

## Exposing the server to an AI platform

To let a hosted AI platform reach the server, put a **TLS-terminating tunnel** in front of the loopback listener and paste the resulting HTTPS URL (with `/mcp`) plus your bearer token into the platform's custom/remote MCP settings.

```bash
# pick one — all publish 127.0.0.1:8765 over HTTPS
cloudflared tunnel --url http://127.0.0.1:8765
ngrok http 8765
tailscale funnel 8765
```

Then in the AI platform's **custom MCP server** configuration:

- **URL:** `https://<your-tunnel-host>/mcp`
- **Header:** `Authorization: Bearer <your token>`

The agent can now call every allowlisted tool on your machine.

> **Security checklist before exposing anything.** Keep `require_auth = true` and use a long random token. Terminate TLS at the tunnel (never expose plain HTTP publicly). Scope `allowed_paths`/`allowed_commands` to exactly what the task needs; leave `allow_elevated`/`allow_destructive` off unless required. Set `allowed_origins` if browser clients will connect. Read [SECURITY.md](SECURITY.md).

---

## Security model

Nebula MCP is **empty-deny by default**:

- A tool may only touch a path matching `allowed_paths` and not matching the built-in and configured `denied_paths` (which ships denying `.ssh`, `.aws`, `.gnupg`, `*.pem`, `*.key`, `id_rsa*`, `.env*`). Existing path components are resolved before matching.
- A tool may only execute a program named in `allowed_commands`; explicit paths must match the resolved executable. Arguments are passed as a verbatim array — **there is no shell**, so no command injection.
- Per-call **timeouts**, a hard **runtime ceiling**, and **output caps** bound every call.
- `allow_elevated`, `allow_network`, `allow_destructive` and `allow_desktop_mutation` are explicit gates, off by default, scopable per tool. Docker is additionally treated as elevated because its daemon is commonly root-equivalent.
- Paths are normalised and existing symlink components are resolved before matching. The GitHub token is read from the environment and never echoed.

Every gate can be relaxed globally under `[security]` or, better, scoped per tool under `[tools."<name>"]`. Dry-run any decision with the `security.*` tools before trusting it.

---

## Configuration

Configuration is a single TOML document with `[server]`, `[logging]`, `[transport.http]`, `[security]`, optional `[categories.<name>]` switches, and optional `[tools."<name>"]` overrides. It **hot-reloads** on change when loaded from a file. See [CONFIGURATION.md](CONFIGURATION.md) for every field, and `config/default.toml` for a fully-commented example.

Useful CLI:

```bash
nebula-mcp list-tools                       # print every tool by category
nebula-mcp print-config                     # emit a documented default config
nebula-mcp validate-config -c nebula-mcp.toml
nebula-mcp run --config … [--http] [--http-addr ADDR] [--auth-token T] [--metrics-addr 127.0.0.1:9184]
```

---

## Architecture

Four crates:

| Crate | Responsibility |
| --- | --- |
| `nebula-mcp-protocol` | JSON-RPC 2.0 + MCP types + stdio framing (no `unsafe`) |
| `nebula-mcp-core` | TOML config + hot reload, permission engine, telemetry/metrics, the `Tool` trait + registry + per-call context |
| `nebula-mcp-tools` | all 118 tool implementations, grouped by category |
| `nebula-mcp-server` | dispatch engine + **stdio and HTTP transports** + `nebula-mcp` CLI |

See [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Development

```bash
cargo test --workspace                                   # unit + integration + HTTP transport E2E
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
cargo check --workspace --target x86_64-pc-windows-gnu   # type-check Windows tools (needs mingw)
```

CI runs Linux, macOS, and native Windows build/test jobs, a Linux→Windows cross-check,
an MSRV check for the declared Rust version, and a dependency audit on every push.

---

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
