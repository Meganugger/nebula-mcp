# Security boundaries

1. JSON-RPC framing and schema validation are protocol boundaries.
2. The core policy engine is the authorization choke point for paths, commands,
   network, elevation, destructive operations, and desktop mutation.
3. Desktop leases coordinate in-process mutating calls; they do not confer
   Windows privileges.
4. Windows UIPI, UAC, secure desktops, logon sessions, ACLs, and service
   isolation remain enforced by Windows.
5. A future privileged service must independently authenticate and authorize
   every request. MCP-server authorization must never be forwarded as trust.

Unsupported shortcuts include UAC bypasses, credential dumping, stealth
persistence, permissive Everyone named-pipe ACLs, and using LocalSystem as a
general-purpose desktop controller.