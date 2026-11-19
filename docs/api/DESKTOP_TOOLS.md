# Desktop tool API

## Locking

`desktop.lock_acquire` accepts `resource`, `leaseMs`, `waitMs`, and `purpose`.
It returns an opaque `lockId`, owner, resource, and wall-clock expiry.
`desktop.lock_release` is owner-bound. `desktop.lock_status` lists live leases.
Expired or missing leases return `stale_handle`; contention returns
`resource_busy`.

## Inspection

`desktop.displays`, `desktop.cursor`, and `desktop.windows` are read-only
interactive-session queries. Windows-only calls return `platform_unsupported`
off Windows.

## Mutation

`desktop.input` accepts at most 100 actions and requires a `lockId`.
`desktop.window` requires a `lockId` and a `windowId`. Both require the
`allow_desktop_mutation` policy gate. `force = true` additionally requires
destructive authorization. Neither tool bypasses UIPI, UAC, or the secure
desktop.