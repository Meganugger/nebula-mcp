# Configuration

Configuration is TOML. Provide it with `--config <path>` (or the
`NEBULA_MCP_CONFIG` environment variable). Without a config file the server
starts with the built-in defaults, which **deny all file and command access** —
you must supply allowlists to do useful work.

Generate a documented starting point:

```bash
nebula-mcp print-config > nebula-mcp.toml
```

Validate an edited file:

```bash
nebula-mcp validate-config --config nebula-mcp.toml
```

## Hot reload

When the server is launched with a `--config` file, it watches that file (and
its parent directory, to catch editor atomic-rename saves) and reloads on
change. Reloads are atomic pointer swaps, so in-flight calls are unaffected. A
syntactically invalid or unreadable edit is logged at `warn` and ignored — the
last valid configuration stays live, so a typo never takes the server down.

## Sections

### `[server]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string | `"nebula-mcp"` | Name advertised on `initialize`. |
| `version` | string | crate version | Version advertised on `initialize`. |
| `instructions` | string | (built-in) | Free-form guidance surfaced to the model. |
| `max_concurrent_calls` | int | `16` | Maximum tool calls running at once. |

### `[logging]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `level` | string | `"info"` | `error`/`warn`/`info`/`debug`/`trace` or an env-filter directive. `RUST_LOG` overrides this. |
| `format` | string | `"json"` | `json` or `pretty` (stderr sink). |
| `directory` | path | none | Directory for rotating file logs. Unset ⇒ stderr only. |
| `file_prefix` | string | `"nebula-mcp"` | File log name prefix. |
| `rotation` | string | `"daily"` | `minutely`/`hourly`/`daily`/`never`. |
| `otel_endpoint` | string | none | OTLP/gRPC endpoint (needs the `otel` build feature). |
| `emit_metrics` | bool | `true` | Log a per-tool metrics summary on shutdown. |

Logs always go to **stderr** (and files); stdout is reserved for the MCP
protocol.

### `[security]`

The global baseline every tool inherits. See [SECURITY.md](SECURITY.md).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `allowed_paths` | [glob] | `[]` | Paths tools may access. Empty ⇒ deny all. |
| `denied_paths` | [glob] | secret patterns | Always-denied paths (wins over allow). |
| `allowed_commands` | [string] | `[]` | Executable basenames tools may run. Empty ⇒ deny all. |
| `default_timeout_secs` | int | `120` | Default per-call timeout. |
| `max_runtime_secs` | int | `3600` | Hard ceiling for any call. |
| `max_output_bytes` | int | `8388608` | Max captured output per stream. |
| `allow_elevated` | bool | `false` | Permit elevated/admin execution. |
| `allow_network` | bool | `true` | Permit off-box network access. |
| `allow_destructive` | bool | `false` | Permit destructive operations. |

Globs use `**` to span path separators. On Windows, use escaped backslashes in
TOML strings (`"C:\\src\\**"`) or forward slashes.

### `[categories.<name>]`

Enable/disable a whole category. Categories: `filesystem`, `terminal`,
`process`, `git`, `github`, `network`, `powershell`, `windows`, `diagnostics`,
`browser`, `docker`, `scheduler`, `security`.

```toml
[categories.powershell]
enabled = false
```

### `[tools."<tool.name>"]`

Per-tool overrides layered on the `[security]` baseline. All fields optional.

| Key | Type | Meaning |
| --- | --- | --- |
| `enabled` | bool | Force this tool on/off. |
| `timeout_secs` | int | Override the default timeout. |
| `max_output_bytes` | int | Override the output cap. |
| `allowed_paths` | [glob] | **Additional** paths (merged with baseline). |
| `allowed_commands` | [string] | **Additional** commands (merged with baseline). |
| `allow_destructive` | bool | Override the destructive gate for this tool. |
| `allow_elevated` | bool | Override the elevation gate for this tool (least-privilege scoping). |

Example (least-privilege: destructive ops off globally, granted only to a
single tool, and a longer timeout for builds):

```toml
[security]
allow_destructive = false

[tools."fs.delete"]
allow_destructive = true              # while global allow_destructive stays false

[tools."terminal.run"]
timeout_secs = 600
allowed_commands = ["cargo", "npm"]   # merged with the global allowlist
```

## `[transport.http]`

Remote HTTP (MCP Streamable HTTP) transport. Disabled by default.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Serve over HTTP (also enabled by `--http`/`--http-addr`). |
| `bind` | string | `127.0.0.1:8765` | Socket address to listen on. |
| `path` | string | `/mcp` | The single MCP endpoint path. |
| `auth_tokens` | [string] | `[]` | Accepted bearer tokens. |
| `require_auth` | bool | `true` | Require a valid token on every request. |
| `allowed_origins` | [string] | `[]` | Exact-match Origin allow-list (browser clients). |
| `max_body_bytes` | int | `16777216` | Max accepted request body size. |

```toml
[transport.http]
enabled = true
bind = "127.0.0.1:8765"
require_auth = true
# Prefer supplying tokens via NEBULA_MCP_AUTH_TOKEN or --auth-token.
```

## Environment variables

| Variable | Effect |
| --- | --- |
| `NEBULA_MCP_CONFIG` | Default `--config` path. |
| `NEBULA_MCP_WORKDIR` | Default `--workdir` (workspace root for relative paths). |
| `NEBULA_MCP_HTTP_ADDR` | HTTP bind address (implies `--http`). |
| `NEBULA_MCP_AUTH_TOKEN` | Bearer token added to the HTTP transport's accepted set. |
| `NEBULA_MCP_METRICS_ADDR` | Prometheus metrics bind address. |
| `RUST_LOG` | Overrides `logging.level` if set. |
| `GITHUB_TOKEN` / `GH_TOKEN` | Auth token for the `github.*` tools (never logged). |

## CLI

```
nebula-mcp run  [--config P] [--workdir D] [--metrics-addr ADDR]
                [--http] [--http-addr ADDR] [--auth-token T] [--no-auth]
nebula-mcp list-tools                                    # print every tool
nebula-mcp print-config                                  # print a default config
nebula-mcp validate-config  --config P                   # validate and summarise
```

- `--http` / `--http-addr` / `--auth-token` / `--no-auth` control the remote
  HTTP transport (see `[transport.http]`). Without them the server speaks stdio.
- `--metrics-addr` (or `NEBULA_MCP_METRICS_ADDR`, e.g. `127.0.0.1:9184`) serves
  per-tool metrics in Prometheus text format at `http://ADDR/metrics`.
