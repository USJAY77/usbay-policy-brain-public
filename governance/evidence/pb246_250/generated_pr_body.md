1. Purpose
- Adds a governed Mac computer-use dry-run loop that observes metadata, classifies screens, scores risk, proposes actions, and requires human approval before execution.
- Keeps all desktop execution disabled.

2. Governance Impact
- Adds screenshot capture governance, deterministic vision observation loop, action proposal engine, human approval execution flow, and controlled dry-run evidence.
- Does not deploy, push, merge, activate production, execute desktop actions, use pyautogui live, click, type, scroll, open apps, control the Mac, call providers, call browser/desktop automation, call external APIs, or store raw screenshots.

3. Risk Assessment
- If raw screenshots are stored, sensitive screen data could leak.
- If unknown screens do not fail closed, automation could act without confidence.
- If HIGH or CRITICAL risk actions bypass approval/blocking, Mac execution governance fails.
- If approval expiry is ignored, stale approval could authorize unsafe execution.

4. Validation Evidence
- `python3 -m py_compile runtime/computer_use/mac_dry_run_loop.py`
- `python3 -m json.tool governance/evidence/pb246_250/screenshot_capture_governance.json`
- `python3 -m json.tool governance/evidence/pb246_250/vision_observation_loop_report.json`
- `python3 -m json.tool governance/evidence/pb246_250/action_proposal_engine_contract.json`
- `python3 -m json.tool governance/evidence/pb246_250/human_approval_execution_flow.json`
- `python3 -m json.tool governance/evidence/pb246_250/validation_results.json`
- `pytest -q tests/test_screenshot_capture_governance.py tests/test_vision_observation_loop.py tests/test_action_proposal_engine.py tests/test_human_approval_execution_flow.py tests/test_controlled_mac_dry_run.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" runtime/computer_use/mac_dry_run_loop.py tests/test_screenshot_capture_governance.py tests/test_vision_observation_loop.py tests/test_action_proposal_engine.py tests/test_human_approval_execution_flow.py tests/test_controlled_mac_dry_run.py governance/evidence/pb246_250`

5. Fail-Closed Check
- Raw screenshot storage is disabled.
- Sensitive screens return `BLOCKED`.
- `UNKNOWN` classification fails closed.
- HIGH risk requires human approval.
- CRITICAL risk blocks.
- Missing or expired approvals fail closed.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before controlled Mac execution pilot.
- No real execution is included in this change.
