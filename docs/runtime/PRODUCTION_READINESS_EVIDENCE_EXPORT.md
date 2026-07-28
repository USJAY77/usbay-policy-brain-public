# Production Readiness Evidence Export

PB-1E defines a deterministic evidence package for human governance review. It does not certify legal compliance, create approvals, authorize execution, deploy software, mutate policy, or call external providers.

The exporter consumes hash-only references for policy, execution contracts, approvals, runtime readiness, dependency readiness, adapter readiness, timestamp evidence, rollback readiness, test results, CI checks, gaps, and restrictions.

Decisions are `READY`, `READY_WITH_RESTRICTIONS`, or `BLOCKED`. Missing, malformed, stale, failed, sensitive, unsupported, or unverifiable metadata returns `BLOCKED`. Restrictions can produce `READY_WITH_RESTRICTIONS` only when policy-authorized and backed by hash-only evidence.

Generated JSON and Markdown are deterministic for identical input, and the package hash excludes host-specific paths or machine identity.
