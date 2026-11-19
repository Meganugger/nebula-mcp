# Roadmap

The 0.2.0 line is a security and protocol foundation, not a promise that
every capability of the current MCP revision is already implemented. The
following is the remaining work, ordered by trust impact.

## Protocol and transport

- Implement request-scoped SSE delivery and `subscriptions/listen` for current
  clients; keep notifications isolated to the originating HTTP client.
- Replace static bearer tokens with MCP authorization discovery and an OAuth
  resource-server flow where a deployment needs delegated access.
- Add current-revision structured tool output schemas and complete cache
  metadata to every list/read result.

## Runtime hardening

- Replace canonicalize-and-use path checks with descriptor-based operations
  (`openat2`/`cap-std` on Unix and corresponding Windows primitives) when
  race-free confinement against hostile local processes is required.
- Add bounded, expiring session and scheduler state, and reap all child
  process trees on shutdown on every supported operating system.
- Add per-client rate limits and a global CPU/memory budget.
- Add fuzzing for JSON-RPC framing, schema validation, path parsing, and
  argument extraction.

## Platform and release

- Expand native Windows cleanup tests and add macOS-specific process and
  filesystem coverage.
- Add Windows UI Automation, monitor-aware DPI coordinate conversion, desktop
  capture, and a separately scoped privileged broker only after their trust
  boundaries and native test coverage are in place.
- Add interactive desktop-agent process separation, installer/service artifacts,
  and operator approval records for sensitive desktop workflows.
- Add signed release binaries and packaging only after the trust and CI
  guarantees above remain green.

## External prerequisites

- TLS for remote exposure still needs a tunnel or reverse proxy.
- QUIC/HTTP3 probing needs a `curl` built with HTTP/3.
- Browser tools need Node.js, Playwright, and browser binaries.
- Crash-dump/ETW tools need matching Windows SDK tools and, sometimes,
  elevation.
- OS-level confinement for arbitrary interpreters, shells, Git, and Docker is
  outside the server's typed-tool policy and must be supplied by the operator.