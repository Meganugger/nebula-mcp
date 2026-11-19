# Nebula MCP Overhaul Plan

> This plan is executed as one end-to-end change; it is not an approval gate.

## Goal

Make the server’s security, lifecycle, protocol, platform, documentation, and
CI claims match the behavior an operator can verify.

## Architecture

The dispatcher owns cross-cutting guarantees: schema validation, capability
requirements, cancellation, timeout, panic isolation, and request identity.
The policy engine owns checked paths, executable resolution, network targets,
and child-process environment/lifecycle. Legacy HTTP state is scoped to a
connection; modern requests carry their own metadata and do not use sessions.

## Work sequence

1. Establish trustworthy CI on Linux, macOS, and Windows, including formatting,
   clippy, tests, MSRV, and dependency audit.
2. Harden the policy and execution core: strict config, safe defaults, deny-set
   union, path and command checks, network gate, sanitized environment, process
   tree cleanup, and regression tests through dispatch.
3. Add dispatcher-owned schema validation and metadata-driven capability gates;
   correct annotations and hide unsupported platform tools.
4. Separate modern stateless MCP requests from legacy negotiated sessions and
   isolate HTTP cancellation, notifications, subscriptions, and jobs.
5. Repair resources, network/GitHub/Docker/PowerShell/Windows argument handling,
   output bounds, and shutdown cleanup category by category.
6. Reconcile generated/reference documentation, migration notes, and the
   runbook. Remove stale NebulaDisplay remnants and the working log.

## Reversible decisions

- Keep the hand-written protocol crate for now; it gives precise control over
  dual-era behavior and transport security. Re-evaluate `rmcp` after the
  current revision support matrix is verified against the exact SDK release.
- Keep dotted tool names for compatibility, while using category filters to
  reduce `tools/list` payloads. A future major release may rename them.
- Retain explicit `allowed_commands = ["*"]`, but treat it as an announced
  privileged mode and never describe it as sandboxing.
- Default network access to disabled and deny loopback/private/metadata targets
  unless the operator explicitly opts in. This is a breaking safety default.
- Keep the generic GitHub REST tool only for the GitHub API origin and expose
  typed endpoint tools for common operations; arbitrary caller URLs are not a
  supported contract.
