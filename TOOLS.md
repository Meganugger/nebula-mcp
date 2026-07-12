# Nebula MCP — Tool Reference

Auto-generated from `nebula-mcp list-tools`. **123 tools across 15 categories.**

Cross-platform categories work on Linux, macOS and Windows. Categories marked *(Windows)* or *(Unix)* compile everywhere but return `platform_unsupported` when the host does not match. Every call is subject to the permission policy described in [SECURITY.md](SECURITY.md).

### `browser`

- **`browser.capture`** — Drive Playwright to navigate a URL and optionally capture a screenshot, PDF (Chromium), Playwright trace, console logs and network activity. Requires Node.js + Playwright.
- **`browser.screenshot`** — Capture a screenshot of a URL to a file with Playwright. Requires Node.js + Playwright.

### `diagnostics`

- **`diagnostics.capabilities`** — Report the host platform and availability of common external toolchains (git, cargo, node, python, go, docker, ffmpeg, cdb, ...). Cross-platform.
- **`diagnostics.metrics`** — Return live per-tool metrics (call counts, successes, failures, cancellations, mean/max durations, output bytes). Cross-platform.
- **`diagnostics.config`** — Summarise the server's effective configuration and permission policy (path/command counts, gates, disabled categories/tools). Cross-platform.
- **`diagnostics.wer_reports`** — List recent Windows Error Reporting (application crash) events as JSON. Windows only.
- **`diagnostics.crash_dumps`** — List crash dump (.dmp) files under the local WER CrashDumps directory or a provided directory. Windows only.
- **`diagnostics.create_dump`** — Create a full memory dump of a process with procdump (Sysinternals). Windows only.
- **`diagnostics.analyze_dump`** — Analyse a crash dump with cdb (!analyze -v) and return the analysis text. cdb must be allowlisted. Windows only.
- **`diagnostics.stack_trace`** — Capture stacks of all threads in a running process via cdb (~*k). Windows only.
- **`diagnostics.etw_trace`** — Control an ETW trace session with logman: create/start/stop/delete/query. Windows only.

### `docker`

- **`docker.ps`** — List Docker containers (JSON lines). Set all=true to include stopped containers.
- **`docker.images`** — List Docker images (JSON lines).
- **`docker.build`** — Build a Docker image from a build context directory (within an allowed root).
- **`docker.run`** — Run a container from an image. Supports detach, name, env, published ports and a command.
- **`docker.stop`** — Stop a running container by name or id.
- **`docker.rm`** — Remove a container (optionally forcing). Destructive.
- **`docker.logs`** — Fetch a container's logs (last N lines).
- **`docker.exec`** — Execute a command inside a running container and capture its output.
- **`docker.compose`** — Run docker compose actions (up/down/ps/logs/build) against a compose file (within an allowed root).

### `filesystem`

- **`fs.read`** — Read a file. Supports byte offset and maxBytes for streaming large files in chunks, and encoding=base64 for binary files.
- **`fs.write`** — Create or overwrite a file, creating parent directories. Use encoding=base64 to write binary content.
- **`fs.edit`** — Edit a text file by replacing an exact string. By default the old string must match exactly once (a safety check); set replaceAll to replace every occurrence.
- **`fs.append`** — Append UTF-8 text to a file, creating it if absent.
- **`fs.rename`** — Rename or move a file/directory (both paths must be within allowed roots).
- **`fs.delete`** — Delete a file or directory. Directory deletion requires recursive=true. Destructive.
- **`fs.move`** — Move a file/directory, falling back to copy+delete across filesystems.
- **`fs.copy`** — Copy a file or directory tree to a new location.
- **`fs.search`** — Search file contents by regular expression under a root directory, returning matches with line numbers.
- **`fs.glob`** — List files matching a glob pattern under a root directory.
- **`fs.tree`** — Produce a directory tree (names, types, sizes) to a bounded depth.
- **`fs.hash`** — Compute the SHA-256 digest and size of a file.
- **`fs.metadata`** — Return metadata for a path: type, size, timestamps, and read-only status.
- **`fs.permissions`** — Get or set file permissions. On Unix accepts an octal 'mode'; on Windows toggles 'readonly'.

### `git`

- **`git.status`** — Show the working tree status (porcelain v2 with branch info).
- **`git.diff`** — Show changes. Optional 'from'/'to' revisions, 'path' filter, and 'staged' flag.
- **`git.blame`** — Show what revision and author last modified each line of a file.
- **`git.log`** — Show commit logs. Optional 'maxCount', 'path', and 'revRange'.
- **`git.branch`** — List, create or delete branches. Modes: list (default), create, delete.
- **`git.checkout`** — Switch branches or restore paths. Provide 'ref' and optional 'create'.
- **`git.merge`** — Merge a ref into the current branch.
- **`git.rebase`** — Rebase the current branch onto 'ref' (add 'abort' or 'continue' to control an in-progress rebase).
- **`git.stash`** — Manage the stash. Modes: push (default), pop, list, drop, apply.
- **`git.tag`** — List or create tags. Provide 'name' to create, optional 'message' for an annotated tag.
- **`git.bisect`** — Drive a bisect session. Provide 'action' (start/good/bad/reset) and optional 'rev'.
- **`git.commit`** — Record staged changes. Provide 'message'; set 'all' to stage tracked changes first.
- **`git.push`** — Push to a remote. Optional 'remote' (default origin), 'branch', 'force', 'setUpstream'.
- **`git.pull`** — Pull from a remote. Optional 'remote', 'branch', 'rebase'.
- **`git.fetch`** — Fetch from a remote. Optional 'remote' (default origin), 'prune', 'all'.
- **`git.reset`** — Reset current HEAD. Modes: soft, mixed (default), hard. 'hard' is destructive.
- **`git.clean`** — Remove untracked files. Requires 'force'; add 'directories' for -d. Destructive.
- **`git.submodule`** — Run a submodule action: status (default), update, init, sync.
- **`git.worktree`** — Manage worktrees: list (default), add (needs 'path' and optional 'ref'), remove (needs 'path').
- **`git.cherry_pick`** — Apply the changes of an existing commit. Provide 'commit'.
- **`git.revert`** — Revert a commit, creating a new commit. Provide 'commit'; set 'noEdit' to skip the editor.
- **`git.reflog`** — Show the reference log. Optional 'maxCount' (default 30).
- **`git.show`** — Show an object (commit/tree/blob). Provide 'object' (default HEAD) and optional 'path'.
- **`git.apply`** — Apply a patch file to the working tree. Provide 'patch' (path, relative to repo). Set 'check' to only validate.

### `github`

- **`github.clone`** — Clone a repository into a directory within an allowed root (uses the git CLI).
- **`github.request`** — Make an authenticated GitHub REST API request. Covers any endpoint (PRs, issues, actions, releases, reviews, labels, ...).
- **`github.pr_list`** — List pull requests for a repository (optional 'state': open/closed/all).
- **`github.pr_create`** — Open a pull request. Requires owner, repo, title, head, base.
- **`github.issue_list`** — List issues for a repository.
- **`github.issue_create`** — Create an issue. Requires owner, repo, title.
- **`github.fork`** — Fork a repository into the authenticated account or an org.
- **`github.release_list`** — List releases for a repository.
- **`github.release_create`** — Create a release from a tag.
- **`github.workflow_runs`** — List GitHub Actions workflow runs for a repository.
- **`github.branch_list`** — List branches for a repository.
- **`github.review_create`** — Submit a review on a pull request (event: APPROVE/REQUEST_CHANGES/COMMENT).
- **`github.labels_list`** — List labels defined in a repository.

### `network`

- **`net.http_request`** — Perform an HTTP/HTTPS request and return status, headers and (capped) body.
- **`net.download`** — Download a URL to a file (within an allowed root), streaming with a maximum size cap.
- **`net.dns_lookup`** — Resolve a hostname to IP addresses.
- **`net.tcp_connect`** — Measure TCP connect latency to host:port.
- **`net.latency`** — Sample TCP connect latency over multiple attempts and report min/avg/max/jitter.
- **`net.tls_info`** — Perform a TLS handshake and report the negotiated protocol and peer certificate details.
- **`net.websocket`** — Connect to a WebSocket endpoint, optionally send a text message, and collect replies for a short window.
- **`net.ping`** — Ping a host using the system 'ping' utility (must be allowlisted).
- **`net.iperf`** — Run an iperf3 client against a server and return JSON throughput results (iperf3 must be allowlisted).
- **`net.packet_capture`** — Capture packets to a pcap file using dumpcap/tcpdump. Requires elevation and network policy; the output path must be within an allowed root.
- **`net.quic_probe`** — Probe an endpoint for HTTP/3 (QUIC) support using 'curl --http3' (curl must be allowlisted and built with HTTP/3).

### `powershell`

- **`powershell.run`** — Run a PowerShell command non-interactively (-NoProfile -NonInteractive). Have the script emit JSON (e.g. '... | ConvertTo-Json') for structured output. Windows only.
- **`powershell.elevated`** — Run a PowerShell command elevated (UAC). Output is redirected to a file and returned. Requires allow_elevated. Windows only.
- **`powershell.remote`** — Run a PowerShell command on a remote computer via Invoke-Command (WinRM must be configured). Windows only.

### `process`

- **`process.list`** — List running processes (pid, name, cpu, memory), optionally filtered by a name substring.
- **`process.info`** — Return detailed information about a process by pid.
- **`process.kill`** — Terminate a process by pid. Destructive; requires allow_destructive.

### `scheduler`

- **`scheduler.after`** — Schedule an allowlisted command to run once after a delay. Returns a job id; poll with scheduler.results.
- **`scheduler.every`** — Schedule an allowlisted command to run repeatedly on an interval. Returns a job id; cancel with scheduler.cancel.
- **`scheduler.list`** — List scheduled jobs and their run counts.
- **`scheduler.results`** — Fetch the captured results (stdout/stderr/exit) of a scheduled job's recent runs.
- **`scheduler.cancel`** — Cancel a scheduled job (aborts any in-progress run).

### `security`

- **`security.check_path`** — Dry-run the path policy: report whether a path would be allowed (and its normalised form) or why it is denied. Optionally evaluate against a specific tool's policy.
- **`security.check_command`** — Dry-run the command allowlist: report whether a program would be permitted for execution. Optionally evaluate against a specific tool's policy.
- **`security.effective_policy`** — Report the effective permission policy for a tool: timeouts, output cap, gates and the command allowlist.

### `terminal`

- **`terminal.run`** — Run an allowlisted command to completion, capturing stdout/stderr with a timeout. The program (args[0]) must be permitted by policy; arguments are passed verbatim (no shell).
- **`terminal.session_open`** — Open a persistent interactive process (e.g. a shell). Returns a session id to write to and read from across calls.
- **`terminal.session_write`** — Write text to an interactive session's stdin. Include a trailing newline to submit a command.
- **`terminal.session_read`** — Read and clear buffered output from an interactive session, optionally waiting up to waitMs for new output.
- **`terminal.session_list`** — List active interactive sessions.
- **`terminal.session_close`** — Terminate an interactive session and free its resources.

### `toolchain`

- **`toolchain.cargo`** — Run cargo (build/check/test/clippy/...) with parsed rustc diagnostics (severity, code, file:line:col) and test failures. The cargo binary must be allowlisted; args are passed verbatim.
- **`toolchain.npm`** — Run npm (install/run/test/...) with parsed npm ERR!/WARN diagnostics. The npm binary must be allowlisted; args are passed verbatim.
- **`toolchain.pnpm`** — Run pnpm (install/run/test/...) with parsed ERR_PNPM_*/WARN diagnostics. The pnpm binary must be allowlisted; args are passed verbatim.
- **`toolchain.pip`** — Run pip (install/download/...) with parsed ERROR:/WARNING: diagnostics. The pip binary must be allowlisted (override program to pip3 if needed); args are passed verbatim.
- **`toolchain.poetry`** — Run poetry (install/add/build/...) with parsed error/warning diagnostics. The poetry binary must be allowlisted; args are passed verbatim.
- **`toolchain.go`** — Run go (build/test/vet/...) with parsed file:line:col diagnostics and test failures. The go binary must be allowlisted; args are passed verbatim.
- **`toolchain.gradle`** — Run gradle (build/test/...) with parsed compiler and task-failure diagnostics. The gradle binary must be allowlisted (override program to ./gradlew for wrapper builds); args are passed verbatim.
- **`toolchain.maven`** — Run Maven (package/test/...) with parsed [ERROR]/[WARNING] diagnostics including file:[line,col] locations. The mvn binary must be allowlisted; args are passed verbatim.

### `unix`

- **`unix.service`** — Query or control a service via systemctl (Linux) or launchctl (macOS): status/list/start/stop/restart/enable/disable. stop/restart are destructive; enable/disable require elevation. Set user=true for the per-user manager. The systemctl/launchctl binary must be allowlisted. Unix only.
- **`unix.package`** — Query or manage packages via the system package manager (apt/dnf/yum/pacman/zypper/apk/brew, auto-detected or explicit): list/info/search are read-only; install requires elevation; remove requires elevation and the destructive gate. The manager binary must be allowlisted. Unix only.
- **`unix.logs`** — Query system logs via journalctl (Linux, JSON output) or `log show` (macOS): recent entries, optionally filtered by unit/priority. The journalctl/log binary must be allowlisted. Unix only.
- **`unix.cron`** — List the current (or a named) user's crontab entries via `crontab -l`. Listing another user's crontab requires elevation. The crontab binary must be allowlisted. Unix only.
- **`unix.sysctl`** — Get or set kernel parameters via sysctl: get one key, list keys by prefix, or set a value (set requires elevation). The sysctl binary must be allowlisted. Unix only.

### `windows`

- **`windows.service`** — Query or control a Windows service (query/start/stop/restart/create/delete/config) via sc.exe. create/delete/config require elevation; stop/restart/delete are destructive. Windows only.
- **`windows.registry`** — Query, set or delete registry keys/values via reg.exe. Delete is destructive. Windows only.
- **`windows.event_log`** — Query a Windows event log (e.g. System, Application) and return recent events as JSON. Windows only.
- **`windows.perf_counters`** — Sample Windows performance counters (e.g. '\Processor(_Total)\% Processor Time') via Get-Counter. Windows only.
- **`windows.scheduled_tasks`** — List or control scheduled tasks (query/run/end) via schtasks.exe. Windows only.
- **`windows.env`** — Get or set a Windows environment variable at Process/User/Machine scope. Machine scope requires elevation. Windows only.
- **`windows.firewall`** — List Windows firewall rules (optionally filtered by display-name substring) as JSON. Windows only.
- **`windows.network_adapters`** — List network adapters (name, status, MAC, link speed) as JSON. Windows only.
