PURPOSE

Create the local Adapter Registry UI view model for governed USBAY adapter state.

RISK

Adapter dashboards can hide unsupported targets if missing adapters are not shown as blocked. This PB fails closed when desktop, browser, or API adapter state is missing.

POLICY LINK

USBAY fail-closed governance, audit-first engineering, human approval, evidence-required execution.

GOVERNANCE CHECKS

- Desktop adapter state displayed.
- Browser adapter state displayed.
- API adapter state displayed.
- Disabled adapter state displayed.
- Blocked adapter state displayed.
- Readiness state displayed.

AUDIT

Evidence is stored in governance/evidence/pb190/results.json and adapter_registry_ui_report.json.

IMPACT

USBAY gains a local adapter registry view model without enabling adapters.

Decision: VERIFIED

Status: READY_FOR_REVIEW
