1. Purpose
- Adds a governed vision/computer-use foundation for Mac readiness without enabling live desktop execution.
- Defines local-only vision capabilities, screen classification, sensitive screen detection, deterministic risk scoring, and proposed desktop actions.

2. Governance Impact
- Affects future computer-use policy, approval, audit, and fail-closed controls.
- Does not deploy, push, merge, activate production, use pyautogui live, click, type, scroll, open apps, control the desktop, call model/provider APIs, or store raw screenshots.

3. Risk Assessment
- If screen classification is wrong, unknown or sensitive screens could be mishandled.
- If sensitive markers are missed, private information could be exposed.
- If risk scoring is non-deterministic, audit replay and approval enforcement weaken.
- If the adapter executes actions instead of proposing them, USBAY would violate fail-closed desktop governance.

4. Validation Evidence
- `python3 -m py_compile runtime/computer_use/vision_governance.py`
- `python3 -m json.tool governance/evidence/pb241_245/vision_capability_registry.json`
- `python3 -m json.tool governance/evidence/pb241_245/screen_classification_report.json`
- `python3 -m json.tool governance/evidence/pb241_245/sensitive_screen_detection_contract.json`
- `python3 -m json.tool governance/evidence/pb241_245/vision_risk_scoring_report.json`
- `python3 -m json.tool governance/evidence/pb241_245/desktop_execution_adapter_contract.json`
- `python3 -m json.tool governance/evidence/pb241_245/validation_results.json`
- `pytest -q tests/test_vision_capability_registry.py tests/test_screen_classification_engine.py tests/test_sensitive_screen_detection.py tests/test_vision_risk_scoring.py tests/test_governed_desktop_execution_adapter.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" runtime/computer_use/vision_governance.py tests/test_vision_capability_registry.py tests/test_screen_classification_engine.py tests/test_sensitive_screen_detection.py tests/test_vision_risk_scoring.py tests/test_governed_desktop_execution_adapter.py governance/evidence/pb241_245`

5. Fail-Closed Check
- Execution capabilities default to `DISABLED`.
- `UNKNOWN` screen classification fails closed.
- Sensitive screens return `BLOCKED` or `HUMAN_APPROVAL_REQUIRED`.
- `HIGH` and `CRITICAL` risk require approval; `CRITICAL` blocks execution.
- Desktop adapter only proposes actions and never executes pyautogui actions.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before any controlled Mac execution pilot.
- No controlled desktop execution is included in this change.
