1. Purpose
- Adds readiness-only governed automation contracts for the live gateway, connector gates, human approval queue, and dry-run automation harness.
- Keeps production automation disabled while proving local evaluation, audit evidence, approval expiry behavior, and connector default-deny state.

2. Governance Impact
- Affects policy evaluation readiness, audit evidence generation, connector governance state, and human approval gating.
- Does not deploy, push, merge, activate connectors, or perform external API, browser, desktop, or production actions.

3. Risk Assessment
- If the gateway request contract is wrong, governance decisions may fail closed and block review automation.
- If approval expiry or connector states are wrong, a CISO would reject production activation because non-read actions could lack explicit current human approval.
- If audit writing fails, the gateway and dry-run harness deny rather than assume success.

4. Validation Evidence
- `python3 -m py_compile gateway/governance_gateway.py connectors/connector_contracts.py approval/human_approval_queue.py automation/dry_run_harness.py`
- `python3 -m json.tool governance/evidence/pb212_215/connector_gate_contracts.json`
- `python3 -m json.tool governance/evidence/pb212_215/human_approval_queue_contract.json`
- `python3 -m json.tool governance/evidence/pb212_215/dry_run_automation_report.json`
- `python3 -m json.tool governance/evidence/pb212_215/validation_results.json`
- `pytest -q tests/test_governance_gateway.py tests/test_connector_contracts.py tests/test_human_approval_queue.py tests/test_dry_run_harness.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" gateway/governance_gateway.py connectors/connector_contracts.py approval/human_approval_queue.py automation/dry_run_harness.py tests/test_governance_gateway.py tests/test_connector_contracts.py tests/test_human_approval_queue.py tests/test_dry_run_harness.py governance/evidence/pb212_215`
- Full-suite attempt: `pytest -q` was interrupted after 400.06s with 97 failed and 451 passed; visible failures were outside the PB-212-PB-215 focused slice and centered on existing runtime gateway policy registry signature invalidation symptoms.

5. Fail-Closed Check
- Malformed gateway requests, missing policies, unknown policy hashes, evaluator timeouts, evaluator exceptions, and audit write failures return `FAIL_CLOSED`.
- Expired approvals fail closed.
- All governed connectors default to `DISABLED`.
- The dry-run harness records evidence and never performs live connector, API, browser, desktop, or production actions.

6. Human Approval Required
- Human review is required before merge.
- Separate human approval, renewed signatures, deployment attestation, and connector credential governance are required before any real automation activation.
- Full-suite failures must be triaged before merge.
