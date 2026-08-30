PURPOSE

Create the local Audit Explorer UI view model for governed USBAY evidence lookup.

RISK

Audit explorers can mislead users if lookups are ambiguous, missing, or lack audit hashes. This PB fails closed when lookup evidence is incomplete.

POLICY LINK

USBAY fail-closed governance, audit-first engineering, human approval, evidence-required execution.

GOVERNANCE CHECKS

- Decision id lookup supported.
- Approval id lookup supported.
- Execution id lookup supported.
- Audit hash displayed.
- Policy version displayed.
- Ambiguous lookup fails closed.

AUDIT

Evidence is stored in governance/evidence/pb191/results.json and audit_explorer_ui_report.json.

IMPACT

USBAY gains a local audit explorer view model without external evidence access.

Decision: VERIFIED

Status: READY_FOR_REVIEW
