# API

The server speaks the [Model Context Protocol](https://modelcontextprotocol.io)
using JSON-RPC 2.0. It implements protocol revision **2024-11-05** and offers
two transports that share the same method set below.

## Transports

### stdio (default)

- **stdin**: newline-delimited JSON-RPC requests/notifications from the client.
- **stdout**: newline-delimited JSON-RPC responses. Nothing else is ever written
  here.
- **stderr**: human/JSON logs (and optionally rotating files).

Blank lines are ignored. Each response is written atomically with a trailing
newline.

### Remote HTTP — MCP Streamable HTTP (`--http`)

A single endpoint (default `/mcp`):

- **`POST /mcp`** — body is one JSON-RPC message or an array of them. Requests
  are answered with `Content-Type: application/json` (a single object, or an
  array for a batch); a body of only notifications is acknowledged with
  `202 Accepted`.
- **`GET /mcp`** — opens a `text/event-stream` (SSE) carrying server-initiated
  notifications (progress, resource updates) plus keep-alives. Every event
  carries a monotonically increasing SSE `id:`; see *Resumable SSE* below.
- **`DELETE /mcp`** — ends the session named by the `Mcp-Session-Id` header
  (`404` if unknown/expired).

Every request must present `Authorization: Bearer <token>` — a configured
static token or, when `[transport.http.oauth]` is enabled, any token the
authorization server reports active (RFC 7662 introspection) with the required
scopes — unless auth is explicitly disabled on a loopback bind. Malformed JSON
yields `400` with a JSON-RPC parse-error body; a bad/absent token yields `401`.

#### Sessions

The response to a `POST` containing `initialize` includes an
`Mcp-Session-Id` header. Include that header on subsequent requests: the
server tracks per-session state and echoes the id back. A request presenting
an unknown or expired id (idle longer than `session_idle_secs`, default
1800 s) is answered `404 Not Found` — re-initialize to obtain a fresh session.
Requests without the header are served statelessly for backwards
compatibility.

#### Resumable SSE

Each SSE event carries an `id:` field. If the stream drops, reconnect with the
standard `Last-Event-ID` header; the server replays every buffered event with
a greater id (bounded by `sse_replay_events`, default 256) before resuming
live delivery, so no notification is lost across brief disconnects.

The method set, parameters and results below are identical across both
transports.

## Methods

### `initialize`

Request:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize",
 "params":{"protocolVersion":"2024-11-05","capabilities":{},
           "clientInfo":{"name":"my-agent","version":"1.0"}}}
```

Result:

```json
{"jsonrpc":"2.0","id":1,"result":{
  "protocolVersion":"2024-11-05",
  "capabilities":{
    "tools":{"listChanged":false},
    "resources":{"subscribe":true,"listChanged":false},
    "prompts":{"listChanged":false},
    "logging":{}
  },
  "serverInfo":{"name":"nebula-mcp","version":"0.1.0"},
  "instructions":"..."}}
```

### `notifications/initialized`

Client → server notification (no response) after a successful `initialize`.

### `tools/list`

Request:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

Result: `{ "tools": [ { "name", "description", "inputSchema", "annotations" }, … ] }`.
Only enabled tools are returned. `inputSchema` is a JSON Schema object and is the
authoritative argument reference for each tool.

### `tools/call`

Request:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call",
 "params":{"name":"fs.read","arguments":{"path":"src/main.rs"}}}
```

Result (`CallToolResult`):

```json
{"jsonrpc":"2.0","id":3,"result":{
  "content":[{"type":"text","text":"{ ...json... }"}],
  "structuredContent":{ "...": "typed JSON mirroring the text block" },
  "isError":false}}
```

Most tools return a single `text` content block containing a pretty-printed
JSON document, plus the same value verbatim as `structuredContent` for
schema-aware clients. Error results carry
`structuredContent: {"error": {"category", "message"}}`.
`browser.screenshot` and similar write artifacts to disk and return their paths.

### `ping`

Request `{"jsonrpc":"2.0","id":4,"method":"ping"}` → result `{}`.

### `resources/list` and `resources/read`

The server exposes files under the workspace root as resources, gated by the
same path allow/deny policy as the filesystem tools.

```json
{"jsonrpc":"2.0","id":5,"method":"resources/list","params":{}}
```

Result: `{ "resources": [ { "uri":"file:///…", "name", "mimeType", "size" }, … ] }`.

```json
{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"file:///work/src/main.rs"}}
```

Result: `{ "contents": [ { "uri", "mimeType", "text" | "blob" } ] }`. Text files
return `text`; binary files return base64 `blob`. Reads are policy-checked and
truncated to the configured output cap.

Subscribe to change notifications for a resource:

```json
{"jsonrpc":"2.0","id":6,"method":"resources/subscribe","params":{"uri":"file:///work/build.log"}}
{"jsonrpc":"2.0","id":7,"method":"resources/unsubscribe","params":{"uri":"file:///work/build.log"}}
```

While subscribed, the server emits (whenever the file/dir changes, debounced):

```json
{"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"file:///work/build.log"}}
```

### `prompts/list` and `prompts/get`

Curated engineering-workflow prompts (crash-dump triage, build-failure
investigation, PR review, bisect, display-pipeline diagnosis).

```json
{"jsonrpc":"2.0","id":7,"method":"prompts/list","params":{}}
{"jsonrpc":"2.0","id":8,"method":"prompts/get","params":{"name":"triage_crash_dump","arguments":{"dumpPath":"C:/dumps/app.dmp"}}}
```

`prompts/get` returns `{ "description", "messages":[{"role":"user","content":{"type":"text","text":"…"}}] }`.

### `logging/setLevel`

Adjust the server's log verbosity at runtime (syslog-style levels map onto the
tracing filter):

```json
{"jsonrpc":"2.0","id":9,"method":"logging/setLevel","params":{"level":"debug"}}
```

Result `{}` on success.

### `notifications/cancelled`

Client → server notification to cancel an in-flight request:

```json
{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}
```

The corresponding tool call is aborted (its child process, if any, is killed)
and returns an error result with the `cancelled` category.

### `notifications/progress` (server → client)

If a `tools/call` includes a progress token in `_meta`, the server streams
progress updates for the duration of the call:

Request opting into progress:

```json
{"jsonrpc":"2.0","id":7,"method":"tools/call",
 "params":{"name":"terminal.run",
           "arguments":{"program":"cargo","args":["build"]},
           "_meta":{"progressToken":"build-1"}}}
```

Server-initiated notifications while it runs:

```json
{"jsonrpc":"2.0","method":"notifications/progress",
 "params":{"progressToken":"build-1","progress":0,"message":"started: cargo"}}
{"jsonrpc":"2.0","method":"notifications/progress",
 "params":{"progressToken":"build-1","progress":1,"message":"cargo running 3s"}}
```

Command-wrapping tools emit an immediate `started` update and periodic
heartbeats; the final result arrives as the normal `tools/call` response.

## Error model

Two distinct failure channels:

1. **Protocol errors** — returned as JSON-RPC `error` objects:

   | Code | Meaning |
   | --- | --- |
   | `-32700` | Parse error (invalid JSON frame) |
   | `-32600` | Invalid request |
   | `-32601` | Method not found / unknown or disabled tool |
   | `-32602` | Invalid params (unparseable `tools/call` params) |
   | `-32603` | Internal error |
   | `-32003` | Rate limit / resource budget rejection (retryable) |

2. **Tool execution errors** — returned as a *successful* JSON-RPC response
   whose `result` is a `CallToolResult` with `isError: true` and a text block of
   the form `"[<category>] <message>"` (mirrored in `structuredContent.error`).
   This lets the model read and react to failures. Categories include:

   `invalid_arguments`, `permission_denied`, `path_not_allowed`,
   `command_not_allowed`, `timeout`, `cancelled`, `rate_limited`,
   `resource_exhausted`, `output_too_large`, `tool_not_found`,
   `platform_unsupported`, `io`, `execution`, `internal`.

   `rate_limited` and `resource_exhausted` are retryable: back off and retry
   once the window slides or the server's usage drops under budget.

## Example session

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"a","version":"1"}}}
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05", ...}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"terminal.run","arguments":{"program":"cargo","args":["test"]}}}
← {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"exitCode\":0,\"stdout\":\"...\"}"}],"isError":false}}
```
