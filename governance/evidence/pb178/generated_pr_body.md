PURPOSE

Define the governed desktop adapter contract for future USBAY execution targets without enabling live desktop execution.

RISK

Desktop automation can mutate local state if it is not policy-gated, approval-bound, and audit-bound. This PB creates contracts only and blocks live execution.

POLICY LINK

USBAY fail-closed governance, audit-first engineering, human approval, evidence-required execution.

GOVERNANCE CHECKS

- Desktop action schema defined.
- Target schema defined.
- Execution request schema defined.
- Unsupported actions block.
- Live desktop execution fails closed.

AUDIT

Evidence is stored in governance/evidence/pb178/results.json with validation status, files created, and control outcomes.

IMPACT

USBAY gains a desktop adapter interface for future reviewed execution work while preserving mock-only behavior.

Decision: VERIFIED

Status: READY_FOR_REVIEW
