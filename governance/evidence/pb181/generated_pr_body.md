PURPOSE

Define the approval binding required before any governed execution adapter request can proceed.

RISK

Adapter requests without decision, approval, token, policy, or authority binding can create unauditable execution drift. This PB fails closed when any binding field is missing.

POLICY LINK

USBAY fail-closed governance, audit-first engineering, human approval, evidence-required execution.

GOVERNANCE CHECKS

- Decision id required.
- Approval id required.
- Policy version required.
- Execution token required.
- Authority id required.
- Missing fields fail closed.

AUDIT

Evidence is stored in governance/evidence/pb181/results.json and governance/evidence/pb181/approval_binding_report.json.

IMPACT

USBAY gains a shared approval boundary for desktop, browser, API, and future adapter classes.

Decision: VERIFIED

Status: READY_FOR_REVIEW
