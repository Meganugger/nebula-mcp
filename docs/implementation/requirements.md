# Requirements matrix

This matrix is intentionally conservative: a feature is only `implemented`
when the current tree contains the behavior and a passing test or CI job.

| Requirement | State | Evidence / limitation |
| --- | --- | --- |
| Empty configuration denies file and command access | implemented | Existing core policy tests |
| Secret deny patterns win over allowed roots | implemented | Existing core policy tests |
| Desktop mutation is deny-first | implemented | `allow_desktop_mutation` defaults false |
| Exclusive desktop resource lease | implemented | `DesktopLockManager` unit tests |
| Lease expiry and owner binding | implemented | `DesktopLockManager` unit tests |
| Desktop input schema and action bound | implemented | `desktop.input` schema and limit |
| Windows `SendInput` path | partially_implemented | Fixed helper is present; Windows CI evidence pending |
| Window/display/cursor inspection | partially_implemented | Windows PowerShell adapters; DPI/bounds fidelity pending |
| Dedicated interactive desktop agent | deferred | Requires a separate process and session lifecycle |
| Secure named-pipe IPC | deferred | Requires Windows ACL and token-identity integration |
| Privileged broker | deferred | Must be designed and tested independently |
| UI Automation COM STA worker | deferred | Not present in this slice |
| Browser session isolation | deferred | Existing capture tools are not persistent sessions |
| MCP HTTP authentication | implemented | Existing HTTP transport and tests |
| Multi-principal authorization | deferred | Existing transport auth is not a full principal model |
| Windows installer | deferred | No installer artifact is shipped yet |