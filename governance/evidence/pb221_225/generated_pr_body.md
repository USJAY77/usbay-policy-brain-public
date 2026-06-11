1. Purpose
- Prepares USBAY for a first controlled live pilot without activating production automation.
- Defines a limited GitHub -> USBAY Gateway -> Human Approval -> Codex pilot contract, connector activation gates, monitoring events, KPI reporting, and a first revenue pilot plan.

2. Governance Impact
- Affects pilot readiness, connector activation governance, runtime monitoring, incident response, and local-only KPI evidence.
- Does not deploy, push, merge, activate production, activate connectors, or call LinkedIn, Notion, Euria, GitHub, Codex, browser, desktop, or external APIs.

3. Risk Assessment
- If pilot scope is too broad, live automation could escape governance boundaries.
- If activation gates are incomplete, credentials or approvals could be mistaken for authorization.
- If monitoring events are incomplete, unsafe states may not block fast enough.
- If KPI reporting stores sensitive data, audit evidence could become a data hygiene risk.

4. Validation Evidence
- `python3 -m py_compile pilot/controlled_live_pilot.py connectors/activation_governance.py monitoring/runtime_monitoring.py reporting/pilot_kpi_reporting.py`
- `python3 -m json.tool governance/evidence/pb221_225/controlled_live_pilot_contract.json`
- `python3 -m json.tool governance/evidence/pb221_225/connector_activation_governance.json`
- `python3 -m json.tool governance/evidence/pb221_225/runtime_monitoring_contract.json`
- `python3 -m json.tool governance/evidence/pb221_225/pilot_kpi_report.json`
- `python3 -m json.tool governance/evidence/pb221_225/validation_results.json`
- `pytest -q tests/test_controlled_live_pilot.py tests/test_connector_activation_governance.py tests/test_runtime_monitoring_incidents.py tests/test_pilot_kpi_reporting.py tests/test_first_revenue_automation_plan.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" pilot/controlled_live_pilot.py connectors/activation_governance.py monitoring/runtime_monitoring.py reporting/pilot_kpi_reporting.py tests/test_controlled_live_pilot.py tests/test_connector_activation_governance.py tests/test_runtime_monitoring_incidents.py tests/test_pilot_kpi_reporting.py tests/test_first_revenue_automation_plan.py governance/evidence/pb221_225`

5. Fail-Closed Check
- Pilot contract defaults to `BLOCKED`.
- Connector activation fails closed if credential, approval, policy hash, or attestation is missing.
- Runtime monitoring returns `BLOCKED` for every unsafe state.
- KPI reporting is local-only and does not activate production.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit human approval is required before first controlled live pilot.
- No production or sales automation activation is included.
