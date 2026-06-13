1. Purpose
- Adds governed terminal-use foundations so USBAY can inspect repository state and propose safe corrections through terminal contracts.
- Allows only read-only verification commands and correction proposals; write, push, merge, delete, install, network, and secret-reading commands remain blocked.

2. Governance Impact
- Adds terminal capability registry, command risk classification, safe verification harness, correction proposal flow, and terminal audit evidence chain.
- Does not deploy, push, merge, activate production, run write commands, run prohibited git/destructive/install/network commands, read secrets, call external APIs, or store sensitive output.

3. Risk Assessment
- If command classification is too broad, destructive or network commands could run.
- If shell injection is missed, a read-only command could hide a prohibited command.
- If sensitive paths are readable, terminal evidence may leak credentials.
- If stdout/stderr is stored when sensitive markers are present, audit logs become unsafe.

4. Validation Evidence
- `python3 -m py_compile terminal/command_governance.py terminal/verification_harness.py terminal/correction_proposal.py`
- `python3 -m json.tool governance/evidence/pb256_260/terminal_capability_registry.json`
- `python3 -m json.tool governance/evidence/pb256_260/command_risk_classification.json`
- `python3 -m json.tool governance/evidence/pb256_260/safe_verification_harness_report.json`
- `python3 -m json.tool governance/evidence/pb256_260/correction_proposal_flow.json`
- `python3 -m json.tool governance/evidence/pb256_260/terminal_audit_evidence_chain.json`
- `python3 -m json.tool governance/evidence/pb256_260/validation_results.json`
- `pytest -q tests/test_terminal_capability_registry.py tests/test_command_risk_classification.py tests/test_safe_verification_harness.py tests/test_correction_proposal_flow.py tests/test_terminal_audit_evidence_chain.py`
- `git diff --check`
- `rg -n "^(<<<<<<<|=======|>>>>>>>)" terminal/command_governance.py terminal/verification_harness.py terminal/correction_proposal.py tests/test_terminal_capability_registry.py tests/test_command_risk_classification.py tests/test_safe_verification_harness.py tests/test_correction_proposal_flow.py tests/test_terminal_audit_evidence_chain.py governance/evidence/pb256_260`

5. Fail-Closed Check
- Unknown commands, shell injection patterns, sensitive paths, and timeouts fail closed.
- HIGH risk commands require human approval.
- CRITICAL commands block.
- Correction proposals do not modify files or run git add, commit, push, merge, delete, install, or network commands.

6. Human Approval Required
- Human review is required before merge.
- Separate explicit approval is required before human-approved terminal correction pilot.
- No write-command execution is included.
