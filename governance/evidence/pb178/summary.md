# PB-178 Desktop Adapter Contract

Decision: VERIFIED

Status: READY_FOR_REVIEW

PB-178 defines a mock-only desktop adapter contract. The contract validates desktop action, target, execution request, approval binding, policy version, and audit identifier before returning a governance decision.

No live desktop execution is enabled. Requests with live execution flags fail closed. Unsupported desktop actions are blocked. High-risk desktop actions require a valid approval binding or return HUMAN_REVIEW.

Validation:

- python3 compile: PASS
- focused adapter tests: PASS, 22 passed
- live desktop execution: DISABLED

