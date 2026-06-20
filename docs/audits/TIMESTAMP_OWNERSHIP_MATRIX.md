# PB-RFC3161-001 Timestamp Ownership Matrix

| Responsibility | Canonical Owner | Providers / Adapters | Duplicate Ownership Status |
| --- | --- | --- | --- |
| RFC3161 request validation | `governance.rfc3161_timestamp` | `governance.proof_timestamp_anchor` | none |
| Timestamp anchor verification | `governance.rfc3161_timestamp` | `governance.proof_timestamp_anchor` | provider only |
| Timestamp chain readiness | `governance.rfc3161_timestamp` | `scripts.verify_timestamp_chain` | adapter only |
| PB008 local receipt verification | `governance.rfc3161_timestamp` | `scripts.pb008_timestamp_verifier` | deprecated provider |
| Generic timestamp interface validation | `governance.rfc3161_timestamp` | `governance.timestamping` | adapter only |

## Deprecation Map

`scripts.pb008_timestamp_verifier` remains supported for PB008 local receipt compatibility and existing tests. It must not own runtime timestamp readiness. Readiness consumes `governance.rfc3161_timestamp.timestamp_chain_readiness_report`.

## Fail-Closed Ownership Rules

- Missing timestamp chain evidence blocks readiness when configured.
- Invalid timestamp metadata blocks readiness.
- Broken timestamp continuity blocks readiness.
- Duplicate timestamp owners block readiness if introduced.
- No module other than `governance.rfc3161_timestamp` may declare runtime timestamp ownership.
