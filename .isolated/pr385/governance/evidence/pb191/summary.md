# PB-191 Audit Explorer UI

Decision: VERIFIED

Status: READY_FOR_REVIEW

PB-191 adds a local audit explorer UI view model. It supports decision id, approval id, and execution id lookup with audit hash and policy version display.

Missing, incomplete, or ambiguous lookups fail closed.

Validation:

- python3 compile: PASS
- focused Control Plane UX tests: PASS, 17 passed

