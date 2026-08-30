1. Purpose
- Adds the first controlled Mac execution pilot contracts for local desktop actions under USBAY policy, approval, audit, and fail-closed controls.
- Keeps live execution disabled until separate human approval.

2. Governance Impact
- Adds controlled execution authority, human-approved desktop action checks, kill switch, live pilot window contract, and execution evidence chain.
- Does not deploy, push, merge, activate production, execute desktop actions, use pyautogui live, click, type, scroll, open apps, control the Mac, call external APIs, or store raw screenshots.

3. Risk Assessment
- If execution authority is too permissive, unsafe screens or critical risk could execute.
- If approvals can be reused, expired, missing, or mismatched, stale authority could trigger actions.
- If kill switch rollback lacks an audit hash, incident replayability is weakened.
- If evidence stores raw screenshots or sensitive data, desktop governance violates data hygiene requirements.

4. Validation Evidence
- `python3 -m py_compile runtime/computer_use/controlled_mac_execution.py`
- `python3 -m json.tool governance/evidence/pb251_255/controlled_execution_authority.json`
- `python3 -m json.tool governance/evidence/pb251_255/human_approved_desktop_actions.json`
- `python3 -m json.tool governance/evidence/pb251_255/execution_kill_switch_contract.json`
- `python3 -m json.tool governance/evidence/pb251_255/live_mac_pilot_window.json`
- `python3 -m json.tool governance/evidence/pb251_255/mac_execution_evidence_chain.json`
- `python3 -m json.tool governance/evidence/pb251_255/validation_results.json`
- `pytest -q tests/test_controlled_execution_authority.py tests/test_human_approved_desktop_actions.py tests/test_execution_kill_switch.py tests/test_live_mac_pilot_window.py tests/test_mac_execution_evidence_chain.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" runtime/computer_use/controlled_mac_execution.py tests/test_controlled_execution_authority.py tests/test_human_approved_desktop_actions.py tests/test_execution_kill_switch.py tests/test_live_mac_pilot_window.py tests/test_mac_execution_evidence_chain.py governance/evidence/pb251_255`

5. Fail-Closed Check
- Default execution authority is `BLOCKED`.
- Execution requires policy `ALLOW`, approval `APPROVED`, LOW or MEDIUM risk, known screen class, non-sensitive screen, and `ENABLED_SAFE` kill switch.
- HIGH requires approval and CRITICAL always blocks.
- Missing, expired, reused, or mismatched approvals block.
- Audit failure, unknown screen, approval failure, or unsafe state disables execution.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before first real Mac action.
- No live execution activation is included in this change.
