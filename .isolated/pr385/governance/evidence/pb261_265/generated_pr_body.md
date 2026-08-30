1. Purpose
- Adds a cross-system governance orchestrator connecting LinkedIn -> Notion -> Euria -> USBAY Control Plane -> GitHub -> Codex -> Mac -> Terminal.
- Keeps the full flow READ_ONLY by default and DRY_RUN only.

2. Governance Impact
- Adds workflow registry, workflow state engine, approval routing engine, cross-system audit chain, and end-to-end dry-run simulation.
- Does not deploy, push, merge, activate production, activate connectors, run browser automation, run desktop automation, run terminal write commands, or execute external APIs.

3. Risk Assessment
- If unknown workflow states do not fail closed, unsafe execution paths could appear authorized.
- If approval routing permits execution, downstream systems could mutate state.
- If audit chain omits a step, replayability across systems is weakened.
- If dry-run flags drift, operators could confuse simulation with live automation.

4. Validation Evidence
- `python3 -m py_compile orchestration/cross_system_orchestrator.py`
- `python3 -m json.tool governance/evidence/pb261_265/workflow_registry.json`
- `python3 -m json.tool governance/evidence/pb261_265/workflow_state_engine.json`
- `python3 -m json.tool governance/evidence/pb261_265/approval_routing_engine.json`
- `python3 -m json.tool governance/evidence/pb261_265/cross_system_audit_chain.json`
- `python3 -m json.tool governance/evidence/pb261_265/full_end_to_end_dry_run_simulation.json`
- `python3 -m json.tool governance/evidence/pb261_265/validation_results.json`
- `pytest -q tests/test_cross_system_orchestrator.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" orchestration/cross_system_orchestrator.py tests/test_cross_system_orchestrator.py governance/evidence/pb261_265`

5. Fail-Closed Check
- READ_ONLY is the default state.
- DRY_RUN only is enforced.
- Unknown state fails closed to BLOCKED.
- Connector activation, production activation, browser automation, desktop automation, terminal write commands, and external API execution are all blocked.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before any live cross-system orchestration.
- No production execution is included in this change.
