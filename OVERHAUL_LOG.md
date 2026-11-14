# Overhaul working log

Temporary. Folded into CHANGELOG.md / ARCHITECTURE.md / SECURITY.md and deleted
before the pull request is finished. Branch: `hoplite/amisos-peiraieus-405652a0`.
No exploit detail belongs in this file; tests carry it alongside the fixes.

## Baseline (2026-11-14, 66dcb54)

- Build ok, 121 tests pass, clippy clean, `cargo fmt --check` failed, six
  unused-dependency warnings. CI red on main since the first feature commit.
- First green CI on all three OSes: c0a0be1 (cherry-picked the CI matrix from
  the audit branch, fixed the two resource tests that hard-coded `/tmp`).
- 2879f5a adds a black-box stdio harness (`crates/server/tests/support`) and six
  regression tests for the reproduced defects. All six failed on the baseline
  binary (planted executable ran, symlink read escaped, search returned a denied
  file, the allowed root itself was refused, cancel left the process tree and
  progress running, the TLS probe was never answered). They are `#[ignore]`d
  until the commit that fixes each.
- Tool audits (read-only, by category) confirmed every reported finding and
  added more: option injection in several git tools reaching command execution,
  a second TLS-provider panic, unbounded recursion in directory copy, a process
  tool able to signal the server itself, PowerShell quoting that is not an
  escape, the browser driver unable to find a normal Playwright install.

## Threat model (becomes SECURITY.md)

Actors. The operator configures and starts the server and is trusted. The MCP
client (an AI agent, possibly steered by prompt injection in content it reads)
is the adversary: it may send any message and any tool arguments, concurrently.
Other HTTP clients are mutually untrusted. Local OS users and anything already
running as the operator are out of scope.

Tier 1, typed tools. The server performs the operation or builds the argument
vector. Guarantees (each enforced in `nebula-mcp-core`, each with a dispatcher
test):

- G-FS-1 File access is confined to the configured roots after symlink
  resolution, with no check-then-use window inside the server.
- G-FS-2 Deny patterns apply to every file a tool reads, writes, lists, moves,
  copies or deletes, on the resolved path and the requested path, case
  insensitively. Built-in patterns cannot be removed by setting `denied_paths`.
- G-FS-3 A root is a directory; allowing it allows the directory itself.
- G-FS-4 The server's own config file, state and log directories are never
  readable or writable through tools.
- G-FS-5 File tools cannot write inside `.git` directories (hooks, config).
- G-EXEC-1 Only executables matched by `allowed_commands` are spawned for
  caller-chosen programs, matched on the file that will actually run.
- G-EXEC-2 Typed tools never pass a caller string where the program would
  parse it as an option or sub-command.
- G-EXEC-3 Children get an allowlisted environment; the server's secrets are
  not inherited and callers cannot set variables unless configured.
- G-NET-1 Nothing reaches the network unless `allow_network` (default off),
  enforced by the dispatcher from tool metadata.
- G-NET-2 Connections the server makes itself go only to vetted destinations:
  loopback, private, link-local and metadata ranges are refused unless enabled,
  the vetted address is the one connected to, and every redirect is re-vetted.
- G-NET-3 Operator credentials (GitHub token) are sent only to their API host.
- G-GATE-1 Destructive and elevated operations require their gates.
- G-ARG-1 Arguments are validated against the advertised schema before a tool
  runs.
- G-PROC-1 Cancel, timeout, disconnect and shutdown kill the whole process
  tree of a call and stop its notifications; shutdown is bounded.
- G-AVAIL-1 No client input terminates the process; a panic in one call is
  contained to that call.
- G-ISO-1 HTTP clients cannot observe or affect each other's requests,
  notifications, subscriptions, terminal sessions or jobs.
- G-AUTH-1 The HTTP endpoint authenticates before reading the body; tokens and
  origins follow the live config.

Tier 2, arbitrary execution. `terminal_*`, `scheduler_*`, `powershell_*`,
`docker_*` and anything in `allowed_commands` (or `"*"`) run programs chosen
or steered by the agent. No argument filter confines them: this tier grants
the agent the operating-system user's privileges (root-equivalent for Docker),
unless OS confinement is enabled and verified for the platform. Not claimed:
confinement of what an allowlisted program does; DNS pinning for external
programs (git, docker, curl); path re-resolution by external programs after
the server validated a path.

## Decisions (owner may want to reverse those marked R)

- D1 (R) Tool names change from `fs.read` to `fs_read`. Dots are legal in the
  spec but are rejected or rewritten by several major clients.
- D2 (R) Categories are opt-in: `[server] categories = [...]`. No config means
  no tools. `nebula-mcp init` writes a starter config.
- D3 `allowed_paths` are directories (roots), not globs; a trailing `/**` is
  accepted and stripped with a warning.
- D4 (R) `allow_network` defaults to false; destinations in private ranges need
  `allow_private_network`.
- D5 Typed tools no longer need their program in `allowed_commands`; the
  allowlist governs caller-chosen programs only. Enabling a category is the
  grant for its typed tools.
- D6 Child environment is an allowlist (`env_passthrough` extends it).
- D7 Protocol: dual-era (2026-07-28 stateless + legacy 2024-11-05, 2025-03-26,
  2025-06-18, 2025-11-25). The deprecated two-endpoint HTTP+SSE transport is not
  implemented.
- D8 HTTP auth: static bearer tokens stay; an embedded single-operator OAuth
  2.1 authorization server (PKCE, DCR + client ID metadata documents,
  protected-resource metadata) is added because claude.ai and ChatGPT cannot
  send a static token.
- D9 Unknown config keys are errors.
- D10 Content-heavy tools (file contents, command output, diffs) return text
  only; record-like tools return `structuredContent` with an `outputSchema`.
- D11 Version becomes 0.2.0.

## Plan and status

Workspace members are re-added as they are ported, so every pushed commit
builds and passes for what it contains.

1. [done] CI trustworthy on three OSes; harness; failing regressions recorded.
2. [ ] Core: config v2, policy, checked paths, spawn, net guard, schema
   validation, tool metadata, context.
3. [ ] Protocol crate: JSON-RPC, per-revision MCP types, bounded framing.
4. [ ] Server: engine and connection state, stdio, HTTP (modern + legacy
   sessions), OAuth, resources, prompts, metrics, CLI.
5. [ ] Tools by category on the new core (fs first, then parallel).
6. [ ] Platform: process-tree kill on Windows (Job Objects), OS confinement
   (Landlock, Seatbelt), macOS/Windows path cases.
7. [ ] Docs regenerated and drift-checked, CI audit + MSRV + release hygiene,
   version 0.2.0, changelog with migration notes; delete this log.

## Verified where

| What | Linux (sandbox) | CI Linux | CI macOS | CI Windows |
| --- | --- | --- | --- | --- |
| baseline suite (121 + harness) | yes | c0a0be1 | c0a0be1 | c0a0be1 |
