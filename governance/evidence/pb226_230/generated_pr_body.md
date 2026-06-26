1. Purpose
- Prepares USBAY for a first controlled live pilot activation review without activating live automation.
- Defines one approved pilot workflow: GitHub -> USBAY Gateway -> Human Approval -> Codex.

2. Governance Impact
- Adds pilot customer/use-case selection evidence, approval gate contract, monitoring readiness counters, kill switch contract, and commercial evidence pack.
- Does not deploy, push, merge, activate production, activate connectors, or call LinkedIn, Notion, Euria, GitHub, Codex, browser, desktop, or external APIs.

3. Risk Assessment
- If pilot approval evidence is missing or expired, live action must remain blocked.
- If monitoring readiness is malformed, unsafe states may not be visible.
- If kill switch behavior is wrong, connector, audit, or approval failures may fail to disable the pilot.
- If commercial evidence stores customer or personal data, the pilot package violates data hygiene controls.

4. Validation Evidence
- `python3 -m py_compile pilot/approval_gate.py pilot/monitoring_readiness.py pilot/kill_switch.py`
- `python3 -m json.tool governance/evidence/pb226_230/pilot_approval_contract.json`
- `python3 -m json.tool governance/evidence/pb226_230/pilot_monitoring_readiness.json`
- `python3 -m json.tool governance/evidence/pb226_230/pilot_kill_switch_contract.json`
- `python3 -m json.tool governance/evidence/pb226_230/validation_results.json`
- `pytest -q tests/test_pilot_approval_gate.py tests/test_pilot_monitoring_readiness.py tests/test_pilot_kill_switch.py tests/test_pilot_commercial_evidence.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" pilot/approval_gate.py pilot/monitoring_readiness.py pilot/kill_switch.py tests/test_pilot_approval_gate.py tests/test_pilot_monitoring_readiness.py tests/test_pilot_kill_switch.py tests/test_pilot_commercial_evidence.py governance/evidence/pb226_230`

5. Fail-Closed Check
- Pilot approval contract defaults to `BLOCKED`.
- Missing credential, approval, policy hash, connector readiness, attestation, or expiry evidence blocks pilot readiness.
- Kill switch defaults to `ENABLED` and automation remains `BLOCKED`.
- Connector failure, audit failure, approval expiry, or unsafe state disables the pilot.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before first controlled live pilot.
- No live automation activation is included in this package.
