# Runtime Dependency Readiness Gate

PB-1C adds a deterministic metadata-only dependency readiness gate before runtime execution.

The gate does not probe services, call providers, open sockets, or execute commands. It consumes dependency readiness records by hash/reference and returns `BLOCKED` unless all required dependencies are ready and verified.

Optional degraded dependencies may continue only when policy metadata explicitly permits degraded operation. Unknown, missing, stale, incompatible, unverified, malformed, unsupported, or exception paths fail closed.
