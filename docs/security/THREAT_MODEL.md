# Threat model

Nebula MCP is a high-impact remote-control and code-execution system.

## Trust assumptions

- MCP clients, files, web pages, terminal output, and application text are
  untrusted and may contain prompt injection.
- The operating system kernel and configured launching account are trusted.
- Policy allowlists are not an operating-system sandbox.
- Shells, interpreters, Docker, package managers, Git hooks, and build systems
  can grant control equivalent to the launching account.
- Windows integrity levels, UAC secure desktops, RDP state, and session
  isolation remain security boundaries.

## Current desktop boundary

Desktop mutations are denied by default and require an explicit
`allow_desktop_mutation` policy decision plus an expiring owner-bound lease.
The lease manager is process-local. It is not a replacement for authenticated
IPC, named-pipe ACLs, or a privileged broker.

## Residual risks

Path checks cannot provide race-free confinement against a hostile local
process. PowerShell wrappers and interactive desktop control remain high-impact
capabilities. Do not expose them remotely without authenticated HTTP, TLS at a
trusted proxy, narrow policy, and operator review.