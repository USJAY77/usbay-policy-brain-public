# PB-190 Adapter Registry UI

Decision: VERIFIED

Status: READY_FOR_REVIEW

PB-190 adds a local adapter registry UI view model. It displays desktop, browser, and API adapter states, disabled and blocked adapters, and readiness state.

Missing adapter state or missing audit evidence produces FAIL_CLOSED readiness.

Validation:

- python3 compile: PASS
- focused Control Plane UX tests: PASS, 17 passed

