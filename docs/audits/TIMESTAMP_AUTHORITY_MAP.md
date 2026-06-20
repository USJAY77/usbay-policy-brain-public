# PB-RFC3161-001 Timestamp Authority Map

Canonical timestamp authority: `governance.rfc3161_timestamp`

| Module | Classification | Authority Surface |
| --- | --- | --- |
| `governance.rfc3161_timestamp` | owner | Canonical RFC3161 request validation and timestamp authority readiness |
| `governance.proof_timestamp_anchor` | provider | Proof bundle timestamp anchor verification consumed by RFC3161 preflight |
| `governance.timestamping` | adapter | Generic timestamp verification result interface adapter |
| `scripts.verify_timestamp_chain` | adapter | Read-only timestamp chain verifier for readiness evidence |
| `scripts.pb008_timestamp_verifier` | deprecated provider | PB008 local receipt compatibility adapter; not runtime authority |

Duplicate owner paths: `0`

Runtime mutation: none.

External TSA calls: none.

Deployment behavior: none.

Fail-closed readiness input: `USBAY_RFC3161_TIMESTAMP_CHAIN_PATH`
