# PB-ENFORCEMENT-AUDIT-002 - Bypass Matrix V2

Date: 2026-06-20

## PASS

| Bypass attempt | Expected result | Actual result | Evidence |
| --- | --- | --- | --- |
| Missing gate proof to `route_execution` | Block | Blocks with `canonical_gate_proof_required` | `security/compute_router.py:13`; `tests/test_gateway_app.py:420` |
| Direct `route_execution()` | Block unless proof is provided | Blocks without proof | `security/compute_router.py:52`; `tests/test_gateway_app.py:420` |
| Direct compute router call with blocked proof | Block | Proof validator rejects non-READY/non-VALID proof | `security/compute_router.py:15` to `:30` |
| Stale attestation | Block | `/execute` returns runtime attestation stale denial | `tests/test_gateway_app.py:317` |
| Revoked runtime | Block | `/execute` returns runtime revoked denial | `tests/test_gateway_app.py:338` |
| Duplicate ownership | Block | `/execute` blocks when readiness evidence reports duplicate ownership | `tests/test_gateway_app.py:390` |
| Duplicate reason code | Block | `/execute` blocks when readiness evidence reports duplicate reason codes | `tests/test_gateway_app.py:390` |
| Missing lineage | Block | `/execute` blocks when readiness evidence reports lineage normalization failure | `tests/test_gateway_app.py:390` |
| Missing evidence | Block | `/execute` blocks when readiness evidence reports evidence normalization failure | `tests/test_gateway_app.py:390` |
| Runtime parity failure | Block | `/execute` blocks with `RUNTIME_EVALUATION_BLOCKED` | `tests/test_gateway_app.py:369` |
| Replay attack | Block | `/execute` blocks runtime nonce replay | `tests/test_gateway_app.py:297` |
| Automation helper direct call with blocked proof | Block | `_execute_automation` raises canonical gate error | `tests/test_runtime_policy_validator_extraction.py:155` |
| Runtime command execution with unavailable gate | Block | `_canonical_execution_gate_for_runtime` returns blocked gate on exception | `runtime/enforcement_gateway.py:72` |
| Corrupted evidence snapshot hash | Block | `validate_evidence_snapshot` raises `EVIDENCE_SNAPSHOT_HASH_MISMATCH` | `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_hash_fails_closed` |
| Corrupted evidence snapshot metadata | Block | `validate_evidence_snapshot` raises `EVIDENCE_SNAPSHOT_META_INVALID` | `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_meta_fails_closed` |
| Corrupted runtime manifest | Block | Runtime attestation parity returns untrusted/fail-closed state | `tests/test_runtime_parity_validator.py::test_runtime_manifest_corruption_fails_closed` |
| Corrupted runtime provenance | Block | Runtime attestation parity returns `RUNTIME_ATTESTATION_UNTRUSTED` | `tests/test_runtime_parity_validator.py::test_runtime_provenance_corruption_fails_closed` |
| Stale runtime hash | Block/degrade from valid execution state | Runtime parity returns non-valid degraded state | `tests/test_runtime_parity_validator.py::test_runtime_stale_hash_degrades_without_execution_match` |
| CLI automation blocked-gate attempt | Block | CLI exits nonzero and prints deny reason | `tests/test_runtime_policy_validator_extraction.py::test_cli_automation_entrypoint_blocks_when_canonical_gate_blocks` |
| CLI command blocked-gate attempt | Block | CLI exits nonzero before runtime executor | `tests/test_runtime_policy_validator_extraction.py::test_cli_command_entrypoint_blocks_before_runtime_executor_when_canonical_gate_blocks` |

## FAIL

No verified bypass succeeded.

## RISK

- The bypass matrix now includes direct CLI entrypoint tests for automation and command blocked-gate attempts.
- Evidence snapshot corruption, runtime manifest corruption, provenance corruption, and stale hash behavior are covered by integration-style validator tests. Missing lineage/evidence `/execute` readiness blockers still use canonical readiness blocker injection to prove HTTP gate behavior.

## EVIDENCE

Validation tests added or present:
- `tests/test_gateway_app.py::test_execute_blocks_when_canonical_readiness_evidence_is_blocked`
- `tests/test_gateway_app.py::test_route_execution_requires_canonical_gate_proof_before_compute_validation`
- `tests/test_gateway_app.py::test_route_execution_callsite_is_limited_to_validated_gateway_flow`
- `tests/test_gateway_app.py::test_execute_blocks_stale_runtime_attestation`
- `tests/test_gateway_app.py::test_execute_blocks_runtime_revocation_state`
- `tests/test_gateway_app.py::test_execute_blocks_when_canonical_runtime_validation_is_blocked`
- `tests/test_gateway_app.py::test_execute_blocks_nonce_replay_runtime_enforcement`
- `tests/test_runtime_policy_validator_extraction.py::test_enforcement_gateway_requires_canonical_execution_gate`
- `tests/test_runtime_policy_validator_extraction.py::test_execute_automation_requires_canonical_gate_proof`
- `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_hash_fails_closed`
- `tests/test_runtime_policy_validator_extraction.py::test_corrupted_evidence_snapshot_meta_fails_closed`
- `tests/test_runtime_policy_validator_extraction.py::test_cli_automation_entrypoint_blocks_when_canonical_gate_blocks`
- `tests/test_runtime_policy_validator_extraction.py::test_cli_command_entrypoint_blocks_before_runtime_executor_when_canonical_gate_blocks`
- `tests/test_runtime_parity_validator.py::test_runtime_manifest_corruption_fails_closed`
- `tests/test_runtime_parity_validator.py::test_runtime_provenance_corruption_fails_closed`
- `tests/test_runtime_parity_validator.py::test_runtime_stale_hash_degrades_without_execution_match`
- `tests/test_runtime_parity_validator.py::test_runtime_evidence_manifest_hash_corruption_fails_closed`

## REMEDIATION

No bypass remediation required. Future strengthening can add real lineage artifact corruption fixtures if lineage storage becomes file-backed in the execution gate path.
