# Remote access

Remote HTTP is disabled by default. When enabled, bind to loopback and put a
TLS-terminating, authenticated reverse proxy or tunnel in front of it. A
non-loopback bind must not be used with authentication disabled.

Use a long-lived secret from an environment variable or protected deployment
store, scope paths and commands narrowly, and keep `allow_elevated`,
`allow_destructive`, and `allow_desktop_mutation` disabled unless the workflow
requires them. Do not expose the privileged service or any future named pipe
directly to a network client.