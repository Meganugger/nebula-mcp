# Security

The server is designed to be driven by an autonomous agent, so the permission
model is the most important part of the system. **Nothing is allowed by
default.** Every capability is opt-in through configuration.

## Threat model

- The MCP client (the agent) is *semi-trusted*: it may issue any tool call,
  including mistaken or adversarial ones. Typed filesystem operations resolve
  existing symlink components and re-check recursive entries. The server does
  not claim race-free confinement against a hostile local process changing
  directories concurrently.
- The host is trusted; the server runs with the privileges of its launching
  user (elevate only when explicitly permitted).
- Secrets on disk (keys, `.env`, SSH/AWS/GPG material) must not be readable via
  the filesystem tools even if they sit inside an allowed root.

## The permission engine

Every `tools/call` resolves an `EffectivePolicy` = the `[security]` baseline
with the tool's `[tools."<name>"]` override layered on top. The policy is the
single choke point for:

### Path access
- `allowed_paths` — glob allowlist. **Empty ⇒ deny all file access.**
- `denied_paths` — glob denylist that always wins, even inside an allowed root.
  ships denying `**/.ssh/**`, `**/.aws/**`, `**/.gnupg/**`, `**/*.pem`,
  `**/*.key`, `**/id_rsa*`, `**/id_ed25519*`, `**/.env*`.
- Paths are normalised for matching and the deepest existing ancestor is
  canonicalised before policy evaluation. `..` that would escape the
  filesystem root is rejected. Recursive search/list operations omit denied
  entries; recursive copy/move/delete reject the operation before changing
  anything.

### Command execution
- `allowed_commands` — allowlist matched by the requested executable name
  (case-insensitive on Windows, trailing `.exe` stripped). Explicit executable
  paths must match the resolved path; a planted script cannot satisfy a bare
  command entry. **Empty ⇒ deny all execution.**
- There is **no shell interpolation**: `terminal.run` takes a program plus an
  argument array passed verbatim to `CreateProcess`/`execvp`. Arguments are
  never parsed by a shell, eliminating shell-injection.

### Resource bounds
- `default_timeout_secs` — per-call timeout; callers may request a shorter or
  longer value, always clamped to…
- `max_runtime_secs` — an absolute ceiling enforced by the dispatcher.
- `max_output_bytes` — captured stdout/stderr is bounded; the child is still
  fully drained so it cannot deadlock, and truncation is reported.

### Capability gates
- `allow_elevated` — required by `powershell.elevated`, service create/delete,
  machine-scope env writes, packet capture.
- `allow_network` — required by every tool that reaches off-box (`net.*`,
  `github.*`, `browser.*`, and networked Git operations). It defaults to
  `false`; URL and host tools reject credentials, local/private destinations,
  and redirects. DNS lookup is intentionally a resolution-only diagnostic and
  may report private addresses; it does not open a connection.
- `allow_destructive` — required by `fs.delete`, `process.kill`, `git.reset
  --hard`, `git.clean`, `docker.rm`, registry/service deletion.

Per-tool overrides let you, for example, enable `git.push` broadly while keeping
`fs.delete` disabled, or raise `terminal.run`'s timeout without loosening
anything else.

## Category and tool switches

- Disable an entire subsystem: `[categories.powershell] enabled = false`.
- Disable a single tool: `[tools."fs.delete"] enabled = false`.

Disabled tools are omitted from `tools/list` and rejected at call time.

## Secret handling

- The GitHub tools read a token from `GITHUB_TOKEN`/`GH_TOKEN` and **never echo
  it** in results or logs.
- Logs are structured and go to stderr/files, not stdout; tool arguments are not
  logged verbatim at `info` level.
- The server does not read environment secrets into results.
- Child processes start with a minimal portability environment. Caller-supplied
  secret-looking environment names are rejected rather than forwarded.
- GitHub bearer tokens are sent only to `https://api.github.com`; arbitrary
  caller URLs and clone hosts are rejected.

## Recommended baseline

Start from `config/default.toml` and:

1. Set `allowed_paths` to just your source/build trees.
2. Set `allowed_commands` to just the toolchain you use (`git`, `cargo`,
   `msbuild`, `powershell`, …).
3. Leave `allow_elevated`, `allow_destructive` **off**; enable per-tool only
   where required.
4. Keep `denied_paths` and extend it with any project-specific secret patterns.
5. Run the server as a least-privileged user; only grant admin when a specific
   workflow needs it, and scope it with per-tool overrides.

## Exposing the HTTP transport safely

The remote HTTP transport hands a network peer the ability to invoke every
allowlisted tool, so treat its exposure as granting shell access:

- **Keep `require_auth = true`** and use a long, random bearer token (e.g.
  `openssl rand -hex 32`). Tokens are compared in constant time; the server
  refuses to start on a non-loopback bind with auth disabled or no tokens.
- **Terminate TLS at a tunnel/reverse proxy** (Cloudflare Tunnel, ngrok,
  Tailscale Funnel, nginx). Never publish plain HTTP to the internet — the token
  would travel in clear text.
- **Bind to loopback** and let the tunnel reach it, rather than binding
  `0.0.0.0` directly, whenever possible.
- **Set `allowed_origins`** if browser-based clients will connect, to defeat
  DNS-rebinding; native clients send no `Origin` and are unaffected.
- **Scope the policy tightly.** The transport controls *who may talk to the
  server*; the `[security]` allowlists still control *what any caller can do*.
  Grant only the paths/commands the remote agent needs.
- HTTP authentication is a startup snapshot in this release; restart the HTTP
  listener after rotating tokens. Configuration hot reload applies to tool
  policy, not the listener's authentication middleware.

## Protocol eras

The server supports the current 2026-07-28 per-request metadata model and the
legacy initialization-based revisions through 2025-11-25. Current HTTP
requests must include matching `MCP-Protocol-Version`, `Mcp-Method`, and
request-target headers. Current requests do not receive a legacy
`Mcp-Session-Id`; legacy HTTP negotiation state is isolated by that session
identifier. See the [MCP versioning rules](https://modelcontextprotocol.io/specification/versioning)
and [Streamable HTTP rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

## Known external limitations

When a required external tool is missing the server returns a structured
`tool_not_found` error naming it; when a Windows-only tool runs on a non-Windows
host it returns `platform_unsupported`.

- **QUIC/HTTP3 probing** relies on a `curl` built with HTTP/3.
- **Browser tools** require Node.js and Playwright (with its browser binaries)
  installed on the host.
- **Crash-dump / ETW tools** require the matching Windows SDK tooling (`cdb`,
  `procdump`, `logman`) installed and, in some cases, elevation.
- **Docker** is treated as elevated because access to the daemon is commonly
  equivalent to host-root access. The server does not provide a container
  sandbox for Docker commands.
- **Arbitrary command execution** is not an OS sandbox. Allowing `*`, a shell,
  an interpreter, Git, Docker, or a build tool grants that program the
  launching user's OS privileges. Use an OS-level sandbox outside Nebula MCP
  when that distinction matters.
- **Windows open-world wrappers** (`powershell.*`, service creation/configuration,
  and debugger tooling) remain intentionally high impact. They are gated by
  command, elevation, destructive, network, and path policy where applicable,
  but they are not a substitute for an OS-level Windows sandbox.
