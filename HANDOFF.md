# Handoff: continue the Nebula MCP overhaul

Temporary file. It is the prompt for whoever continues this work with no
memory of the earlier sessions. Delete it, together with `OVERHAUL_LOG.md`,
before the pull request is finished (fold what matters into CHANGELOG.md,
ARCHITECTURE.md and SECURITY.md).

Branch: `hoplite/amisos-peiraieus-405652a0`, based on `main` at 66dcb54.
Work directly; do not fan the work out to sub-agents (the owner asked for
that explicitly: it was slow and expensive). Commit and push after every step
that builds, with an explicit refspec
(`git push origin HEAD:hoplite/amisos-peiraieus-405652a0`).

## 1. The task

Take the repository to the best version of itself in one piece of work and
ship it as a pull request against `main` with every check green. The owner
wants it "as good as possible, fully and correctly", with no approval steps
and no closing offer of further work. Stop early only for a blocker you
cannot clear, and say exactly what it is.

Nebula MCP is a Rust (tokio) MCP server that gives AI agents control of a
real machine (files, shell, git, GitHub, network, Docker, browser,
PowerShell, Windows internals) over stdio and an HTTP endpoint meant to sit
behind a tunnel. Its documentation promises that nothing is allowed by
default and that no tool can escape its configured sandbox. That promise is
the product, and in 0.1.0 it was false in many ways, so the permission model
comes first and everything is built on it.

The result is judged by these outcomes:

- Security claims are true. There is a written threat model
  (`OVERHAUL_LOG.md` has it; it becomes SECURITY.md), every guarantee is
  enforced where a tool author cannot skip it, and each has a test that tries
  to break it through the real dispatcher. Anything that cannot be guaranteed
  is not claimed. Every reproduced 0.1.0 defect is pinned by a regression
  test that failed before the fix.
- No client input can take the process down; a failing tool affects only its
  own request.
- Cancellation, timeout, client disconnect and shutdown leave no processes,
  tasks or watchers behind on Linux, macOS and Windows; shutdown is bounded.
- Two HTTP clients cannot observe or affect each other's requests,
  notifications, subscriptions, terminal sessions or jobs.
- The server speaks the current MCP revision (2026-07-28, stateless) and
  every legacy revision it advertises (2024-11-05, 2025-03-26, 2025-06-18,
  2025-11-25), advertises nothing it does not implement, and behaves
  differently where revisions differ.
- Every tool validates its arguments against its schema before running; its
  schema, description, annotations and structured output match what it does;
  descriptions are written for the model; errors tell the model how to fix
  the call. An agent can go from an empty directory to a pushed commit with
  typed tools alone (0.1.0 had no `git init`, `git add` or remote tool, and
  the docs referred to `fs.mkdir`, `git.add`, `git.init`, which did not
  exist).
- Linux, Windows and macOS are green in CI with format, clippy, tests, a
  minimum-Rust check that matches what is declared, and a dependency audit.
  Platform behaviour is claimed only where CI exercised it.
- Every document agrees with the code, generated ones are checked for drift
  in CI, breaking changes have migration notes in the changelog, and the
  README shows how to connect real clients.

Constraints from the owner: keep the name, the dual licence, the
general-purpose scope, both transports, and the `"*"` switch in
`allowed_commands` (document it and announce it loudly at startup). Breaking
config keys, tool names, defaults and arguments is acceptable at 0.1.0 when it
buys safety or correctness; record each with migration notes. Do not publish
a release or a crate. The repository is public: keep working exploits for
unfixed holes out of issues, logs and PR text; describe what was hardened and
let tests carry the detail.

Finish with: version bumped (0.2.0), ROADMAP.md rewritten to say what is true,
a PR description that says what changed and why, lists breaking changes with
migration notes and the decisions the owner might want to reverse, and a final
report that leads with what the server can now be trusted to do, then the
evidence (what was tested, where, on which platforms), then plainly what is
not done or not verified and what needs the owner.

## 2. Where the branch stands

Commits on the branch, oldest first:

1. `ci: test on Linux, Windows and macOS without fail-fast; fix formatting`
   and `tests: allow the platform temp dir...`: first green CI on all three
   OSes (run for c0a0be1).
2. `tests: black-box stdio harness and regression tests`:
   `crates/server/tests/support/mod.rs` drives the real binary over stdio;
   `crates/server/tests/security_regressions.rs` holds six tests for the
   reproduced 0.1.0 defects. All six failed on 0.1.0 and are `#[ignore]`d.
   They use 0.1 tool names and config syntax and must be ported (new names,
   `[server] categories`, directory roots) and un-ignored when the server
   builds again.
3. `core: strict config v2, policy engine and checked filesystem access` and
   the `wip(core)` commits: the new `crates/core`.

**The workspace is mid-port on purpose.** Root `Cargo.toml` lists only
`crates/protocol` and `crates/core` as members and excludes `crates/tools`
and `crates/server`; their sources are still the 0.1 code and do not compile
against the new core. Re-add each crate to `members` as it is ported, so
every pushed commit builds and passes for what it contains. `crates/protocol`
(hand-written JSON-RPC/MCP types) is to be deleted once the server is rebuilt
on the SDK (decision D7).

`crates/core` (new, the enforcement layer; read these files first):

- `config.rs`: strict config v2 (`deny_unknown_fields` everywhere), migration
  messages for 0.1 keys, `Config::validate(&Catalog)`.
- `policy.rs`: `PolicySet::compile`, `Policy`, `PathRules` (directory roots,
  built-in + configured deny globs matched case-insensitively on every
  ancestor, read-only globs incl. `.git`, protected server files),
  `CommandPolicy::authorize` (decides on the executable's invocation path,
  never the basename; bare-name entries never authorise a file inside an
  allowed root), `EnvPolicy` (child environment is an allowlist;
  `NEBULA_MCP_*` never passes), `NetPolicy`.
- `fs.rs`: `Fs` capability and `CheckedPath`. Lexical gate, symlink
  resolution, deny checks on resolved and requested path, then every
  operation walks from a root directory handle with no symlink following
  (cap-std), so there is no check-then-use window. Recursive operations check
  every entry. Has a test that swaps a directory for a symlink after the
  check.
- `process.rs`: `Spawner`, `Command` (`typed` for programs a tool declared,
  `caller` for caller-chosen programs checked against `allowed_commands`),
  head+tail output capture, one deadline for stdin/wait/drain, process group
  (Unix) or job object (Windows, via `process-wrap`) killed on cancel,
  timeout, leader exit and drop.
- `net.rs`: `Net` outbound guard (destination classes, host allowlist,
  vetted-address pinning, manual redirects re-vetted, capped bodies, explicit
  rustls provider). Built on hyper over the vetted `TcpStream`.
- `schema.rs`, `args.rs`: schema builder, validator with model-facing error
  messages, `check_supported` / `check_input_schema`, typed `Args` accessors.
- `tool.rs`: `ToolSpec` (name `<category>_<verb>`, `Effects`, `Platforms`),
  `Tool` trait (`spec()` + `call(ctx, args) -> ToolOutput`), `ToolRegistry`
  (rejects malformed specs; `exposed(config)`), annotations derived from
  `Effects`.
- `context.rs`: `ToolContext` = the capabilities (`fs()`, `run`/`spawn`,
  `net()`, `require_destructive`, `require_elevated`), limited by what the
  tool's `Effects` declared; `OwnerId` scopes long-lived state.
- `dispatch.rs`: `Dispatcher::call` is the single choke point: exposure and
  platform, schema validation, declared gates, bounded queue, panic
  isolation, runtime ceiling, cancellation with wind-down, and a drop guard
  that cancels everything the call started.
- `store.rs`, `hotreload.rs`: atomic config snapshots; a bad reload keeps the
  last good config; the config file, log directory and OAuth state file are
  protected from tools.
- `metrics.rs`, `telemetry.rs`: unchanged from 0.1 apart from imports.

Status of the core at the time of writing is in section 6; check it first.

## 3. Decisions already made (R = the owner may want to reverse; list them in the PR)

- D1 (R) Tool names change from `fs.read` to `fs_read` (lower snake case,
  at most 32 characters). Dots are legal in the spec but rejected or rewritten
  by claude.ai connectors, the Claude and OpenAI APIs and Copilot CLI.
- D2 (R) Categories are opt-in through `[server] categories = [...]`
  (replaces `[categories.x] enabled`). No config means no tools. Add a
  `nebula-mcp init` subcommand that writes a starter config.
- D3 `allowed_paths` entries are directories; a trailing `/**` is accepted
  and stripped with a warning; other globs are a config error.
- D4 (R) `allow_network` defaults to false; private, loopback and link-local
  destinations need `allow_private_network`. `max_output_bytes` default drops
  from 8 MiB to 1 MiB.
- D5 Typed tools no longer need their program in `allowed_commands`; that
  list governs caller-chosen programs only (`terminal_*`, `scheduler_*`,
  `powershell_*`). Enabling a category is the grant for its typed tools.
- D6 Child environment is an allowlist; `env_passthrough` extends it and
  `caller_env` names what a caller may set.
- D7 (R) Protocol layer: build the server on the official Rust SDK, `rmcp`
  3.10 (verified on the wire: dual-era on stdio and on one HTTP endpoint,
  `server/discover`, `resultType`, `ttlMs`/`cacheScope`, header validation
  with `-32020`, legacy sessions with `Mcp-Session-Id`). Delete
  `crates/protocol`. The deprecated two-endpoint HTTP+SSE transport is not
  implemented. rmcp does not do the following, so the server must: argument
  validation (the dispatcher does it), panic isolation (dispatcher), auth,
  CORS, Origin enforcement (call `enforce_origin_validation()`), allowed
  Hosts for tunnels, body limits, timeouts, connection and session caps.
- D8 HTTP auth: static bearer tokens stay, read from the live config on every
  request. Add an embedded single-operator OAuth 2.1 authorization server
  (authorization code + PKCE S256, Dynamic Client Registration and Client ID
  Metadata Documents fetched through the SSRF guard, protected-resource
  metadata, RFC 8414 metadata, rotating refresh tokens, a consent page that
  asks for `approval_secret`), because claude.ai and ChatGPT cannot send a
  static token. 401 responses carry
  `WWW-Authenticate: Bearer resource_metadata=...`; `resource` must equal
  `public_url`.
- D9 Unknown config keys are errors.
- D10 Content-heavy tools (file contents, command output, diffs, logs) return
  text only; record-like tools return `structuredContent` plus an
  `outputSchema` (use `ToolOutput::json`).
- D11 Version 0.2.0. MSRV 1.88 (what the dependency graph needs; `time` and
  rmcp require it). Use `resolver = "3"`.
- D12 Release profile must use `panic = "unwind"`; `panic = "abort"` would
  defeat panic isolation.

## 4. Remaining work, in order

### 4.1 Core

- Make sure `cargo test -p nebula-mcp-core` and
  `cargo clippy -p nebula-mcp-core --all-targets -- -D warnings` pass on
  Linux, then that CI passes on macOS and Windows (the fs and process code is
  only type-checked for Windows so far; expect fixes).
- Optional OS confinement of spawned processes (`[security.sandbox] mode`):
  Landlock on Linux (use a hard requirement, never best-effort; the sandbox
  used for development has no Landlock, GitHub runners do), `sandbox-exec`
  on macOS. Windows gets process-tree control only. Build only what CI can
  verify and document exactly what is confined. Until it exists,
  `mode = "require"` must refuse to spawn and `auto` must warn.

### 4.2 Tools (`crates/tools`), one category at a time, `fs` first

Port each module to `ToolSpec` + `Tool` and the context capabilities. Add
`crates/tools/clippy.toml` with `disallowed-methods` / `disallowed-types` for
`std::fs`, `tokio::fs`, `std::process::Command`, `tokio::process::Command`,
raw socket connects and HTTP client constructors, so a tool cannot bypass the
core. Add a registry test that registers every tool (this runs
`check_input_schema` on every schema). Hide nothing by hand: platform comes
from `Platforms`, annotations from `Effects`.

What each category must fix (found by audit of 0.1.0, described as
requirements):

- fs (14 tools: read, write, edit, append, rename, delete, move, copy,
  search, glob, tree, hash, metadata, permissions; add `fs_mkdir`): use only
  `ctx.fs()`. Keep `fs_edit`'s exactly-once replacement semantics and
  `fs_read`'s chunk protocol. Reads and searches are bounded and streamed;
  listing tools never show denied names; overwriting or truncating existing
  data and delete need the destructive gate where data is lost; no
  recursion (directory copy into itself crashed 0.1.0).
- git (24 tools; add `git_init`, `git_add`, `git_remote`): every caller
  string that reaches argv must be validated so it cannot be parsed as an
  option or sub-command (refs, remotes, branch names, URLs, bisect and rebase
  controls, pathspecs after `--`); paths go through the policy, including the
  deny list for blame/show/diff/apply and worktree paths; network gate on
  clone/fetch/pull/push/submodule; destructive gate on reset --hard, clean,
  checkout that discards, branch -D, force or deleting pushes, rebase;
  run git with `-c core.hooksPath=<null device>`, `-c core.fsmonitor=false`,
  `-c safe.bareRepository=explicit`, `-c protocol.ext.allow=never`,
  `GIT_TERMINAL_PROMPT=0`, and no caller-controlled `--output`,
  `--upload-pack`, `--receive-pack`, `--exec`, `-c`. `git_commit` must be able
  to commit new files (via `git_add`).
- github (13 tools): the token goes only to the GitHub API host; a caller may
  supply an API path, never a URL; go through `ctx.net()`; destructive gate
  for DELETE; never echo the token; `github_clone` validates its URL like the
  git tools.
- terminal (run, session_open/write/read/list/close): `Command::caller`,
  caller env through `caller_env`, sessions owned by `ctx.owner()`, capped per
  owner (`[limits]`), idle expiry, re-checked against the current policy on
  every use, whole tree killed on close, shutdown and owner disappearance.
- scheduler (after, every, list, results, cancel): same ownership and limits;
  re-authorise against the current policy at fire time; cancel kills the tree.
- process (list, info, kill): `process_kill` may not target the server, its
  ancestors or pid 0/1, must reject out-of-range pids, and needs the
  destructive gate; command lines in listings can hold secrets, say so in the
  description.
- net (http_request, download, dns_lookup, tcp_connect, latency, tls_info,
  websocket, ping, iperf, packet_capture, quic_probe): everything through
  `ctx.net()`; external programs (curl, tcpdump, ping, iperf) get validated
  arguments after `--` with a scheme and host check first; packet capture
  needs the elevated gate and a validated filter; `net_http_request` is not
  read-only.
- docker (ps, images, build, run, stop, rm, logs, exec, compose): present as
  root-equivalent; validate image and container names against a strict
  pattern and never let a caller string become an option; no caller-supplied
  raw arguments, privileged mode or host mounts outside allowed roots; network
  and destructive gates.
- browser (capture, screenshot): http/https only, destination vetted, a
  request interceptor in the driver for sub-requests, scrubbed child
  environment, driver able to find a normal Playwright install; disabled
  unless the category is listed.
- powershell (run, elevated, remote): arbitrary execution, so the shell goes
  through `Command::caller`; pass scripts via `-EncodedCommand` or stdin, not
  string splicing; network gate for remote, elevated gate for elevated.
- windows (service, registry, event_log, perf_counters, scheduled_tasks, env,
  firewall, network_adapters) and diagnostics (capabilities, metrics, config,
  wer_reports, crash_dumps, create_dump, analyze_dump, stack_trace,
  etw_trace): never interpolate caller text into PowerShell or debugger
  command strings (pass values as arguments or encoded JSON; allowlist enum
  values case-insensitively); gates on every create/change/delete/start/stop;
  `analyze_dump` accepts a fixed set of analyses, not debugger commands;
  `diagnostics_config` must not reveal tokens.
- security (check_path, check_command, effective_policy): keep as dry-run
  tools on the new policy API.

Measure the size of `tools/list` with everything enabled and document it;
keep descriptions tight.

### 4.3 Server (`crates/server`) on rmcp

- A `ServerHandler` adapter around `nebula_mcp_core::Dispatcher`. Connection
  state lives outside the engine: per process on stdio, per legacy session on
  HTTP, none for modern requests. `OwnerId` = `stdio`, the legacy session id
  bound to the credential that created it, or the credential for modern
  requests.
- Map `ToolOutput`/`CallFailure` to MCP results per negotiated revision
  (structured content and titles only where the revision has them; invalid
  arguments are an `isError` result). Unknown tool is a protocol error.
  Results never include `-32002` on 2026-07-28.
- Progress goes on the request's own stream; cancellation from
  `notifications/cancelled` (stdio, legacy HTTP) or stream close (modern
  HTTP) cancels `Call::cancel`.
- Resources (file resources under the roots through `Fs`, pagination,
  templates, bounded reads, `subscriptions/listen` and legacy
  `resources/subscribe` with per-owner caps), prompts (fix the tool names
  they mention), completions if cheap. Advertise only what exists; drop the
  `logging` capability unless per-request log notifications are implemented;
  `logging/setLevel` must never change the server's own log filter.
- HTTP: authenticate and check Origin/Host before reading the body; CORS for
  allow-listed origins; body limit; read timeout; connection cap; bounded
  graceful shutdown even with open streams; failed-auth logging and rate
  limit; constant-time token comparison (hash then `subtle`, or equivalent);
  metrics endpoint refuses non-loopback binds unless explicitly allowed.
- CLI: `run` (default), `init`, `print-config`, `validate-config`,
  `list-tools`; loud startup warning for `"*"` and for an empty category
  list; exit on stdin EOF and on SIGTERM within a bounded time.
- Port and un-ignore the six regression tests; add black-box tests for each
  guarantee in the threat model, for stdio and HTTP, both protocol eras, two
  concurrent HTTP clients, malformed and oversized input, and shutdown.

### 4.4 Hygiene, CI and documents

- Dependencies: upgrade thiserror 2, toml 1.x, notify 8 +
  notify-debouncer-mini 0.7, which 8, axum 0.8 (if still used), base64 0.23,
  sysinfo 0.38, tokio-tungstenite 0.30, x509-parser 0.18, OpenTelemetry
  0.33/0.34; drop `reqwest` if nothing needs it; remove unused `dirs`,
  `num_cpus`, `shell-words`, `regex`/`uuid` where unused, and the Windows
  display crates (`windows` with DXGI/Direct3D/DWM features, `image`), which
  are leftovers from the NebulaDisplay project this server was extracted
  from. Remove every other NebulaDisplay/display-driver reference.
  `cargo update` clears the advisories that were open on the 0.1 lockfile.
- CI: keep the three-OS matrix; add an MSRV job (`cargo +1.88 check
  --workspace --locked --all-targets`), `cargo-deny` (advisories, licences,
  sources) via `EmbarkStudios/cargo-deny-action`, a docs-drift job
  (regenerate TOOLS.md and the default config and `git diff --exit-code`),
  dependabot. `[workspace.lints]` for the workspace.
- Documents: README (truthful claims, how to connect Claude Code, Claude
  Desktop, claude.ai, ChatGPT, Cursor, VS Code, with static token versus
  OAuth), ARCHITECTURE, SECURITY (threat model, two tiers, reporting policy),
  CONFIGURATION, TOOLS.md (generated), API, RUNBOOK, ROADMAP (what is true),
  CHANGELOG (breaking changes with migration notes), `config/default.toml`
  (embedded with `include_str!` and tested equal to `Config::default()`),
  full Apache-2.0 text in LICENSE-APACHE.

## 5. Facts that are expensive to rediscover

- Development sandbox: Linux, 2 vCPU, 8 GiB, no Docker, no Landlock, Rust
  1.100. A cold build takes minutes. PID 2 is `sleep infinity`, the sandbox
  keepalive: never `pkill sleep`; kill only PIDs your tests started and give
  `timeout` a `-k`. The source-control policy rejects inline interpreter
  heredocs (`python3 - <<EOF`) and command substitution fed to `gh`; plain
  `cat > file <<'EOF'` works.
- `cargo check --target x86_64-pc-windows-gnu -p nebula-mcp-core` type-checks
  Windows code locally (the target is installed; crates with C code need
  mingw, which is not).
- The six baseline regression failures and the audit are recorded in
  `OVERHAUL_LOG.md`.
- MCP 2026-07-28 in one paragraph: no `initialize`; every request carries
  `_meta` keys `io.modelcontextprotocol/protocolVersion` and
  `.../clientCapabilities` (missing: `-32602`, HTTP 400); `server/discover`
  is mandatory; results carry `resultType`; list/read/discover results carry
  `ttlMs` and `cacheScope`; HTTP is POST only with `MCP-Protocol-Version`,
  `Mcp-Method` and `Mcp-Name` headers that must match the body (`-32020`,
  HTTP 400); unsupported version is `-32022` with `supported`; unknown method
  is `-32601` with HTTP 404; closing the response stream cancels the request;
  `subscriptions/listen` replaces the GET stream and `resources/subscribe`;
  `ping` and `logging/setLevel` are gone; resource not found is `-32602`.
  Legacy clients open with `initialize` and get legacy semantics for the
  stdio process or HTTP session. Read the specification itself
  (modelcontextprotocol.io, repository `modelcontextprotocol/modelcontextprotocol`,
  `docs/specification/2026-07-28` and `schema/2026-07-28/schema.ts`) before
  relying on this.
- Clients: Claude Code, the Anthropic and OpenAI APIs, VS Code, Gemini CLI,
  Windsurf, Cline, Zed and Copilot's cloud agent can send a static bearer
  token; claude.ai/Claude Desktop connectors and ChatGPT need OAuth (or no
  auth). Cursor, VS Code, Zed and Gemini CLI still speak legacy revisions.
  VS Code caps a request at 128 tools; clients use `readOnlyHint` and
  `destructiveHint` to decide what runs without confirmation, so wrong
  annotations are a security defect.
- cap-std: absolute symlinks are refused even when they point inside the
  root; `Dir::open_dir_nofollow` and `FollowSymlinks::No` are what make the
  component walk symlink-free.

## 6. Status when this file was last updated

See the top of `OVERHAUL_LOG.md` ("Plan and status") and `git log`. If the
last commit subject starts with `wip`, the workspace may not build yet: run
`cargo test -p nebula-mcp-core` and fix what it reports before anything else.

Last update: `cargo test -p nebula-mcp-core` passes on Linux (156 tests:
config, policy, fs, process, net, schema, args, tool, store, dispatch).
Not yet done for the core: `cargo clippy -p nebula-mcp-core --all-targets --
-D warnings` (run it and fix what it reports), the Windows type-check, and a
CI run on macOS and Windows. `schema.rs`, `args.rs` and `net.rs` were written
quickly and deserve a read-through before tools depend on them. Next step
after that: section 4.2, starting with the `fs` category.
