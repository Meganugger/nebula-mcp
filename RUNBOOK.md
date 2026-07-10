# Autonomous Build Runbook

This runbook shows how an AI agent drives Nebula MCP through a complete
project lifecycle — **scaffold → build → test → fix → ship** — using only MCP
tool calls. It is transport-agnostic: the same calls work over stdio or the
remote HTTP transport. It assumes a config whose `allowed_paths` covers the
working directory and whose `allowed_commands` include the toolchain in use
(e.g. `git`, `cargo`, `npm`, `node`, `python`, `docker`).

Each step below is a `tools/call`. Arguments are shown as the tool's `arguments`
object.

## 0. Confirm the environment

```jsonc
{"name":"diagnostics.capabilities","arguments":{}}                 // which toolchains are present
{"name":"security.effective_policy","arguments":{"tool":"terminal.run"}}
```

## 1. Scaffold

```jsonc
{"name":"fs.mkdir","arguments":{"path":"myapp/src"}}
{"name":"fs.write","arguments":{"path":"myapp/README.md","content":"# myapp\n"}}
{"name":"git.branch","arguments":{"mode":"list"}}                  // (in an existing repo)
```

Or bootstrap with the project's own generator via `terminal.run`
(`cargo init`, `npm create`, `python -m venv`, …).

## 2. Build & test, streaming output

Pass a `progressToken` in `_meta` to stream stdout as `notifications/progress`
instead of one final blob:

```jsonc
{"name":"terminal.run","arguments":{"program":"cargo","args":["build"]},
 "_meta":{"progressToken":"build-1"}}
{"name":"terminal.run","arguments":{"program":"cargo","args":["test"]},
 "_meta":{"progressToken":"test-1"}}
```

For long or interactive processes, use a persistent session:

```jsonc
{"name":"terminal.session_open","arguments":{"program":"bash"}}    // → sessionId
{"name":"terminal.session_write","arguments":{"sessionId":"…","data":"npm run dev\n"}}
{"name":"terminal.session_read","arguments":{"sessionId":"…","waitMs":2000}}
```

## 3. Diagnose & fix

```jsonc
{"name":"fs.search","arguments":{"root":"myapp/src","pattern":"TODO|error\\[","glob":"*.rs"}}
{"name":"fs.read","arguments":{"path":"myapp/src/main.rs"}}
{"name":"fs.edit","arguments":{"path":"myapp/src/main.rs","oldString":"…","newString":"…"}}
{"name":"git.log","arguments":{"path":"myapp/src/main.rs","maxCount":5}}
{"name":"git.blame","arguments":{"path":"myapp/src/main.rs"}}
```

Re-run the build/test calls until they pass.

## 4. Verify a running service

```jsonc
{"name":"net.http_request","arguments":{"method":"GET","url":"http://127.0.0.1:3000/health"}}
{"name":"browser.screenshot","arguments":{"url":"http://127.0.0.1:3000","path":"myapp/shot.png"}}
{"name":"docker.compose","arguments":{"file":"myapp/compose.yaml","action":"up"}}
```

## 5. Ship

```jsonc
{"name":"git.add","arguments":{"paths":["-A"]}}
{"name":"git.commit","arguments":{"message":"feat: initial working build","all":true}}
{"name":"git.push","arguments":{"remote":"origin","branch":"main","setUpstream":true}}
{"name":"github.pr_create","arguments":{
  "owner":"me","repo":"myapp","title":"Initial build","head":"feature","base":"main"}}
```

## Notes

- Every path is checked against `allowed_paths`/`denied_paths`; every program
  against `allowed_commands`. Dry-run a decision first with `security.check_path`
  / `security.check_command`.
- Destructive calls (`fs.delete`, `git.reset --hard`, `git.clean`, `docker.rm`,
  `process.kill`) require `allow_destructive`, best granted per-tool.
- Watch progress and health with `diagnostics.metrics` and, if enabled, the
  Prometheus `/metrics` endpoint.
