# Privileged tools

No privileged broker tools are exposed by the current desktop slice.

Existing elevation-capable wrappers remain protected by the existing
`allow_elevated` policy gate. A future `windows.elevated_exec` implementation
must route through a separately authenticated broker, independently validate
the operation, cap and redact output, and record an audit event. The MCP
server must never self-elevate or treat a natural-language confirmation as
authorization.