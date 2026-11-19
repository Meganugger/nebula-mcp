# Installation

The current release is a portable Rust binary. Build it with Rust 1.89 or
newer and copy `nebula-mcp` plus a reviewed configuration file to the target
machine. The default configuration denies file, command, network, elevated,
destructive, and desktop-mutating operations.

No Windows service, startup registration, or privileged broker is installed by
the current slice. Do not create one manually as a workaround: services run in
Session 0 and are not desktop agents.

An MSI, per-user desktop-agent registration, and optional least-privilege
broker are deferred until their ACL and clean-machine tests exist.