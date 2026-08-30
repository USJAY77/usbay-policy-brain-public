# PB-ENFORCEMENT-AUDIT-002 - Execution Test Coverage Audit

Date: 2026-06-20

## PASS

| Required coverage | Test evidence | Status |
| --- | --- | --- |
| Missing evidence | `tests/test_gateway_app.py::test_execute_blocks_when_canonical_readiness_evidence_is_blocked` with `evidence_normalization` | Covered |
| Missing lineage | `tests/test_gateway_app.py::test_execute_blocks_when_canonical_readiness_evidence_is_blocked` with `lineage_normalization` | Covered |
| Duplicate ownership | `tests/test_gateway_app.py::test_execute_blocks_when_canonical_readiness_evidence_is_blocked` with `duplicate_ownership` | Covered |
| Duplicate reason code | `tests/test_gateway_app.py::test_execute_blocks_when_canonical_readiness_evidence_is_blocked` with `duplicate_reason_codes` | Covered |
| Stale attestation | `tests/test_gateway_app.py::test_execute_blocks_stale_runtime_attestation` | Covered |
| Replay attack | `tests/test_gateway_app.py::test_execute_blocks_nonce_replay_runtime_enforcement` and decide-first replay tests | Covered |
| Revoked runtime | `tests/test_gateway_app.py::test_execute_blocks_runtime_revocation_state` | Covered |
| Parity failure | `tests/test_gateway_app.py::test_execute_blocks_when_canonical_runtime_validation_is_blocked`; `tests/test_runtime_parity_validator.py::test_runtime_parity_validator_fails_closed_for_blocked_runtime_evaluation` | Covered |
| Missing route gate proof | `tests/test_gateway_app.py::test_route_execution_requires_canonical_gate_proof_before_compute_validation` | Covered |
| Static route call graph | `tests/test_gateway_app.py::test_route_execution_callsite_is_limited_to_validated_gateway_flow` | Covered |
| Runtime automation canonical gate | `tests/test_runtime_policy_validator_extraction.py::test_execute_automation_requires_canonical_gate_proof` | Covered |
| Corrupted evidence snapshot hash | `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_hash_fails_closed` | Covered |
| Corrupted evidence snapshot metadata | `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_meta_fails_closed` | Covered |
| Corrupted runtime manifest | `tests/test_runtime_parity_validator.py::test_runtime_manifest_corruption_fails_closed` | Covered |
| Corrupted runtime provenance | `tests/test_runtime_parity_validator.py::test_runtime_provenance_corruption_fails_closed` | Covered |
| Stale runtime hash | `tests/test_runtime_parity_validator.py::test_runtime_stale_hash_degrades_without_execution_match` | Covered |
| CLI automation blocked-gate entrypoint | `tests/test_runtime_policy_validator_extraction.py::test_cli_automation_entrypoint_blocks_when_canonical_gate_blocks` | Covered |
| CLI command blocked-gate entrypoint | `tests/test_runtime_policy_validator_extraction.py::test_cli_command_entrypoint_blocks_before_runtime_executor_when_canonical_gate_blocks` | Covered |

## FAIL

No required coverage item is fully uncovered.

## RISK

- `/execute` missing lineage coverage still uses canonical readiness blocker injection because lineage is represented through canonical readiness reports in this path.
- CLI-level blocked-gate coverage now exercises `runtime/enforcement_gateway.py` entrypoints through `main([...])` without invoking the runtime executor.

## EVIDENCE

Requested validation suites include the relevant test files:
- `tests/test_gateway_app.py`
- `tests/test_runtime_policy_validator_extraction.py`
- `tests/test_runtime_parity_validator.py`
- `tests/test_execution_guard.py`
- `tests/test_compute_governance.py`

## REMEDIATION

No remediation is required for the stated coverage list. Optional future hardening: add real lineage artifact corruption fixtures if lineage storage becomes file-backed in the execution gate path.
