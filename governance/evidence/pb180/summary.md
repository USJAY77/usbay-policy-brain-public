# PB-180 API Adapter Contract

Decision: VERIFIED

Status: READY_FOR_REVIEW

PB-180 defines a mock-only API adapter contract. It validates request method, endpoint metadata, policy version, audit identifier, approval binding, and dry-run state.

No outbound requests are performed. Mutating API methods require human review unless a valid approval binding exists. Unsupported methods are blocked.

Validation:

- python3 compile: PASS
- focused adapter tests: PASS, 22 passed
- outbound API requests: DISABLED

