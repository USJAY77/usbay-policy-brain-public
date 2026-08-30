from __future__ import annotations

import json

from runtime.computer_use.pb_1i_chain_closure_verification import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    REQUIRED_STAGE_ORDER,
    canonical_pb_1i_json,
    evaluate_pb_1i_chain_closure_verification,
    expected_pb_1i_chain_hash,
    expected_pb_1i_evidence_hash,
    expected_pb_1i_package_hash,
)


HASH = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
HASH_D = "sha256:" + ("d" * 64)
MERGE = "82720b2e708dd10408f3bd46f64ea3d53357b127"


def _stage(index: int, **overrides):
    record = {
        "stage_id": REQUIRED_STAGE_ORDER[index],
        "status": READY,
        "evidence_hash": HASH,
        "audit_hash": HASH_B,
        "decision_hash": HASH_C,
        "merge_commit": MERGE,
        "pull_request": f"PR-{270 + index}",
        "approval_reference": HASH_D,
        "policy_version": "policy-v1",
        "chronology_marker": index + 1,
        "fail_closed_propagation": True,
        "capability_supported": True,
        "metadata_stale": False,
    }
    record.update(overrides)
    return record


def _stage_metadata(**overrides):
    stages = {stage: _stage(index) for index, stage in enumerate(REQUIRED_STAGE_ORDER)}
    stages.update(overrides)
    return stages


def _safety_flags(**overrides):
    flags = {
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "deployment_authorized": False,
        "runtime_mutation": False,
    }
    flags.update(overrides)
    return flags


def _payload(**overrides):
    payload = {
        "chain_order": list(REQUIRED_STAGE_ORDER),
        "stage_metadata": _stage_metadata(),
        "safety_flags": _safety_flags(),
        "restriction_metadata": [],
    }
    payload["expected_chain_hash"] = expected_pb_1i_chain_hash(payload)
    payload["expected_evidence_hash"] = expected_pb_1i_evidence_hash(payload)
    payload["expected_package_hash"] = expected_pb_1i_package_hash(payload)
    payload.update(overrides)
    return payload


def _blocked(payload, reason):
    result = evaluate_pb_1i_chain_closure_verification(payload)

    assert result.final_decision == BLOCKED
    assert reason in result.reason_codes
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.deployment_authorized is False
    assert result.runtime_mutation is False
    assert result.evidence_hash.startswith("sha256:")
    return result


def test_complete_chain_ready() -> None:
    result = evaluate_pb_1i_chain_closure_verification(_payload())

    assert result.final_decision == READY
    assert result.reason_codes == ()


def test_complete_chain_with_restrictions() -> None:
    stages = _stage_metadata(
        **{
            "PB-1H_INTEGRATED_GOVERNANCE_CHAIN_HARDENING": _stage(
                6,
                status=READY_WITH_RESTRICTIONS,
                restriction_reference=HASH,
            )
        }
    )
    payload = _payload(stage_metadata=stages, restriction_metadata=[{"restriction_reference": HASH}])
    payload["expected_chain_hash"] = expected_pb_1i_chain_hash(payload)
    payload["expected_evidence_hash"] = expected_pb_1i_evidence_hash(payload)
    payload["expected_package_hash"] = expected_pb_1i_package_hash(payload)

    assert evaluate_pb_1i_chain_closure_verification(payload).final_decision == READY_WITH_RESTRICTIONS


def test_missing_stage_metadata_blocks() -> None:
    stages = _stage_metadata()
    stages.pop("PB-1B_RUNTIME_FAIL_CLOSED_EXECUTION_GATE")
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "PB_1B_METADATA_MISSING")


def test_invalid_stage_order_blocks() -> None:
    order = list(REQUIRED_STAGE_ORDER)
    order.reverse()
    _blocked(_payload(chain_order=order, expected_chain_hash=HASH), "INVALID_CHAIN_ORDER")


def test_missing_evidence_hash_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1C_RUNTIME_DEPENDENCY_READINESS_GATE"]["evidence_hash"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "EVIDENCE_HASH_MISSING")


def test_missing_audit_hash_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1D_GOVERNED_EXECUTION_ADAPTER_CONTRACT"]["audit_hash"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "AUDIT_HASH_MISSING")


def test_missing_decision_hash_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1E_PRODUCTION_READINESS_EVIDENCE_EXPORT"]["decision_hash"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "DECISION_HASH_MISSING")


def test_missing_approval_reference_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1F_PRECOMMIT_GOVERNANCE_VALIDATION"]["approval_reference"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "APPROVAL_REFERENCE_MISSING")


def test_missing_policy_version_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1G_INTEGRATED_GOVERNANCE_CHAIN_VALIDATION"]["policy_version"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "POLICY_VERSION_MISSING")


def test_chain_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_chain_hash=HASH), "CHAIN_HASH_MISMATCH")


def test_evidence_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_evidence_hash=HASH), "EVIDENCE_HASH_MISMATCH")


def test_package_hash_mismatch_blocks() -> None:
    _blocked(_payload(expected_package_hash=HASH), "PACKAGE_HASH_MISMATCH")


def test_chronology_mismatch_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1H_INTEGRATED_GOVERNANCE_CHAIN_HARDENING"]["chronology_marker"] = 2
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "CHRONOLOGY_MISMATCH")


def test_stale_metadata_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1C_RUNTIME_DEPENDENCY_READINESS_GATE"]["metadata_stale"] = True
    _blocked(_payload(stage_metadata=stages), "STALE_METADATA")


def test_unsupported_capability_metadata_blocks() -> None:
    stages = _stage_metadata(PB_1X_UNKNOWN=_stage(0))
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "UNSUPPORTED_CAPABILITY_METADATA")


def test_upstream_blocked_propagates() -> None:
    stages = _stage_metadata()
    stages["PB-1H_INTEGRATED_GOVERNANCE_CHAIN_HARDENING"]["status"] = BLOCKED
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "UPSTREAM_BLOCKED")


def test_unknown_decision_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1B_RUNTIME_FAIL_CLOSED_EXECUTION_GATE"]["status"] = "ALLOW"
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "UNKNOWN_DECISION")


def test_missing_merge_metadata_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1B_RUNTIME_FAIL_CLOSED_EXECUTION_GATE"]["merge_commit"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "MERGE_METADATA_MISSING")


def test_missing_pull_request_reference_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1C_RUNTIME_DEPENDENCY_READINESS_GATE"]["pull_request"] = ""
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "PULL_REQUEST_METADATA_MISSING")


def test_fail_closed_flag_missing_blocks() -> None:
    stages = _stage_metadata()
    stages["PB-1D_GOVERNED_EXECUTION_ADAPTER_CONTRACT"]["fail_closed_propagation"] = False
    _blocked(_payload(stage_metadata=stages, expected_chain_hash=HASH), "FAIL_CLOSED_PROPAGATION_MISSING")


def test_direct_execution_rejected() -> None:
    _blocked(_payload(direct_execution_requested=True), "EXECUTION_SURFACE_REJECTED")


def test_execution_flags_must_remain_false() -> None:
    _blocked(_payload(safety_flags=_safety_flags(execution_allowed=True)), "EXECUTION_FLAG_NOT_FALSE")


def test_sensitive_data_rejected_without_leakage() -> None:
    result = _blocked(_payload(raw_payload="synthetic-sensitive"), "SENSITIVE_DATA_REJECTED")

    assert "synthetic-sensitive" not in json.dumps(result.to_dict(), sort_keys=True)


def test_credential_literal_rejected_without_leakage() -> None:
    synthetic_marker = "g" + "hp_" + ("x" * 36)
    result = _blocked(_payload(reference=synthetic_marker), "CREDENTIAL_LITERAL_REJECTED")

    assert synthetic_marker not in json.dumps(result.to_dict(), sort_keys=True)


def test_output_is_deterministic() -> None:
    payload = _payload()

    assert evaluate_pb_1i_chain_closure_verification(payload).to_dict() == evaluate_pb_1i_chain_closure_verification(payload).to_dict()


def test_canonical_json_is_stable() -> None:
    decision = evaluate_pb_1i_chain_closure_verification(_payload())

    assert canonical_pb_1i_json(decision) == canonical_pb_1i_json(decision)


def test_redacted_evidence_contains_hashes_only() -> None:
    decision = evaluate_pb_1i_chain_closure_verification(_payload())
    payload = decision.to_dict()

    assert payload["chain_hash"].startswith("sha256:")
    assert payload["evidence_hash"].startswith("sha256:")
    assert payload["package_hash"].startswith("sha256:")
    assert payload["execution_allowed"] is False
    assert payload["provider_execution"] is False
    assert payload["production_activation"] is False
