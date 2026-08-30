# Pre-Commit Governance Validation

PB-1F adds a deterministic metadata-only validator for commit and release-gate readiness metadata.

The validator returns only `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`. It never commits, merges, deploys, calls providers, opens sockets, mutates policy, creates approvals, or authorizes execution.

Missing, malformed, unsupported, expired, duplicated, hash-mismatched, secret-bearing, sensitive, or unknown metadata fails closed as `BLOCKED`.
