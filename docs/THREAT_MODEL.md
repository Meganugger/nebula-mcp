# Nebula MCP Threat Model

## Scope

Nebula MCP is a local or remotely reachable JSON-RPC server that can read and
write the configured workspace, execute allowlisted programs, reach networks,
control containers, and invoke GitHub and platform tools. The primary asset is
the operator's machine and credentials in its environment.

## Trust boundaries

1. **Client → protocol parser**: JSON-RPC frames, HTTP headers, bodies, IDs,
   method names, and tool arguments are hostile input.
2. **Dispatcher → capability implementation**: a tool must not be able to skip
   authorization, schema validation, cancellation, timeout, or audit context.
3. **Policy → filesystem/process/network**: paths, executable resolution,
   process arguments, environment, redirects, and DNS results cross into OS or
   remote authority.
4. **HTTP client → connection state**: legacy sessions, cancellation IDs,
   subscriptions, jobs, and notification streams must be isolated per client.
5. **Configuration file → runtime**: reloads are untrusted operator input and
   must fail closed without replacing a valid snapshot with partial state.

## Threats and invariants

| Threat | Invariant | Enforcement and evidence |
| --- | --- | --- |
| Path traversal, symlink escape, TOCTOU | At check time, a path stays below an allowed root, and every filesystem entry revealed or mutated is checked | Central checked-path API canonicalises the deepest existing ancestor; dispatcher regression tests. A hostile local process can still race a later filesystem operation, so race-free confinement is explicitly out of scope until an open-beneath implementation lands. |
| Secret disclosure | Built-in secret patterns are always denied and cannot be replaced by user patterns | Deny-set union at config build; recursive traversal tests |
| Command confusion or option injection | The executable actually spawned is allowlisted; caller strings cannot become wrapper options | Central spawn builder and typed argument validation; planted-executable and option-injection tests |
| Credential leakage | Child processes receive a minimal explicit environment; HTTP tokens are never sent to caller URLs | Sanitized process environment and GitHub endpoint validation tests |
| SSRF | URL and host destinations are checked for loopback/private/metadata ranges; redirects are not followed | Shared URL/host validation, disabled HTTP redirects, and local-destination tests. DNS rebinding between validation and connect remains an explicit limitation. |
| Resource exhaustion | Executing calls and captured output are bounded; frame size, queued calls, sessions, jobs, watchers, and HTTP connections are not yet fully bounded | Runtime semaphore, output caps, bounded session buffers, and timeouts are covered; the remaining limits are tracked in ROADMAP.md rather than claimed as complete. |
| Request cross-talk | No client can cancel, observe, subscribe to, or receive notifications for another client | Per-connection legacy state; stateless modern requests; multi-client HTTP tests |
| Panic/aborted cleanup | A tool panic is converted to a request error; started command trees are killed on cancellation and timeout | panic boundary, cancellation, timeout, and process-tree tests. Full Windows/macOS runtime cleanup and disconnect/shutdown integration remain CI work. |
| Config fail-open | Unknown keys and invalid security changes are rejected; previous good snapshot remains active | strict deserialization and hot-reload tests |

## Explicit limits

Allowing `"*"` in `allowed_commands` grants the operating-system user’s full
process authority. Typed argument filtering cannot make an arbitrary interpreter
safe. Docker access is root-equivalent on most hosts. Unless an OS sandbox is
actually detected and enforced, the server does not claim to confine arbitrary
child processes.

The HTTP transport supports bearer-token authentication and configured origin
checks. TLS termination, tunnel identity, token storage, and authorization at a
reverse proxy remain operator responsibilities.
