# 0001: Keep desktop leases in the server before adding the agent

## Status

Accepted for the first desktop-control slice.

## Decision

Keep the lease manager in `nebula-mcp-tools` and share it through
`ToolServices`. Desktop-mutating tools require both the policy gate and a live
owner-bound lease. Lease expiry uses a monotonic clock, while the response
also includes a wall-clock expiry for operator display.

## Rationale

This is the smallest compatible change that prevents two MCP requests from
mutating the same desktop concurrently without changing the existing dispatch
or tool trait. The manager is process-local and therefore cannot be treated as
cross-process authorization.

## Consequences

The server must release all leases on exit. A future
`nebula-desktop-agent`/named-pipe design must repeat the authorization and
replay checks at the IPC boundary rather than trusting this in-process manager.
This ADR does not claim UI Automation, DPI conversion, capture, or broker
security are implemented.