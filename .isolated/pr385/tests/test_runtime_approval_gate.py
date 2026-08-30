import hashlib
import json
import re
from pathlib import Path

from governance.runtime import runtime_approval_gate as gate
from governance.runtime.runtime_approval_gate import (
    ACTION_CONTRACT_HASH_MISMATCH,
    ACTOR_ROLE_HASH_MISMATCH,
    APPROVAL_BLOCKED,
    APPROVAL_ELIGIBLE,
    APPROVAL_HASH_MISMATCH,
    BLOCKED_APPROVAL,
    DECISION_CONTINUITY_MISMATCH,
    DUAL_APPROVAL_NOT_SATISFIED,
    DUPLICATE_APPROVER_REFERENCE,
    EVIDENCE_HASH_MISMATCH,
    EXECUTION_FLAG_ENABLED,
    EXPIRED_APPROVAL,
    FUTURE_APPROVAL_INVALID,
    INSUFFICIENT_APPROVER_COUNT,
    INVALID_HASH,
    MALFORMED_APPROVAL_ID,
    MISSING_APPROVAL,
    MISSING_APPROVER_REFERENCE,
    NON_HASH_ONLY_EVIDENCE,
    PENDING_APPROVAL,
    POLICY_HASH_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RAW_APPROVAL_CONTENT_PRESENT,
    REJECTED_APPROVAL,
    REVOKED_APPROVAL,
    SENSITIVE_DATA_PRESENT,
    TENANT_HASH_MISMATCH,
    TIMESTAMP_INVALID,
    TIMESTAMP_ORDER_INVALID,
    UNKNOWN_APPROVAL_STATUS,
    UNKNOWN_APPROVAL_VERSION,
    UNKNOWN_METADATA,
    UNKNOWN_SCHEMA_VERSION,
    UNREDACTED_EVIDENCE,
    RuntimeApprovalGateRequest,
    deterministic_approval_hash,
    validate_runtime_approval,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_approval_gate.json"
SOURCE = Path(gate.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _approval(**overrides):
    payload = {
        "approval_id": "approval-runtime-001",
        "approval_hash": _hash("placeholder"),
        "policy_hash": _hash("policy"),
        "evidence_hash": _hash("evidence"),
        "tenant_hash": _hash("tenant"),
        "decision_hash": _hash("decision"),
        "actor_role_hash": _hash("actor-role"),
        "action_contract_hash": _hash("action-contract"),
        "issued_at": "2026-07-14T08:00:00Z",
        "expires_at": "2026-07-15T08:00:00Z",
        "schema_version": "phase-b.runtime-approval-gate.v1",
        "approval_version": "phase-b.approval-reference.v1",
        "approval_status": "APPROVED",
        "required_approver_count": 1,
        "recorded_approver_count": 1,
        "dual_approval_required": False,
        "approver_hashes": (_hash("approver-1"),),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_algorithm": "sha256",
        "redacted": True,
        "hash_only": True,
    }
    payload.update(overrides)
    if "approval_hash" not in overrides:
        payload["approval_hash"] = deterministic_approval_hash(payload)
    return payload


_DEFAULT_APPROVAL = object()


def _request(approval=_DEFAULT_APPROVAL, **overrides):
    approval_payload = _approval() if approval is _DEFAULT_APPROVAL else approval
    payload = {
        "approval": approval_payload,
        "policy_hash": _hash("policy"),
        "evidence_hash": _hash("evidence"),
        "tenant_hash": _hash("tenant"),
        "decision_hash": _hash("decision"),
        "actor_role_hash": _hash("actor-role"),
        "action_contract_hash": _hash("action-contract"),
        "as_of": "2026-07-14T12:00:00Z",
    }
    payload.update(overrides)
    return RuntimeApprovalGateRequest(**payload)


def test_valid_single_approval_where_dual_approval_not_required():
    result = validate_runtime_approval(_request())

    assert result.status == APPROVAL_ELIGIBLE
    assert result.denial_code is None
    assert HASH_RE.match(result.gate_hash)
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.hash_only is True
    assert result.redacted is True


def test_valid_dual_approval():
    approval = _approval(
        required_approver_count=2,
        recorded_approver_count=2,
        dual_approval_required=True,
        approver_hashes=(_hash("approver-1"), _hash("approver-2")),
    )
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_ELIGIBLE


def test_missing_approval_blocks():
    result = validate_runtime_approval(_request(approval=None))

    assert result.status == APPROVAL_BLOCKED
    assert MISSING_APPROVAL in result.denial_reasons


def test_pending_rejected_revoked_blocked_statuses_block():
    statuses = {
        "PENDING": PENDING_APPROVAL,
        "REJECTED": REJECTED_APPROVAL,
        "REVOKED": REVOKED_APPROVAL,
        "BLOCKED": BLOCKED_APPROVAL,
    }
    for status, reason in statuses.items():
        approval = _approval(approval_status=status)
        approval["approval_hash"] = deterministic_approval_hash(approval)
        result = validate_runtime_approval(_request(approval=approval))
        assert result.status == APPROVAL_BLOCKED
        assert reason in result.denial_reasons


def test_expired_approval_blocks():
    approval = _approval(expires_at="2026-07-14T09:00:00Z")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert EXPIRED_APPROVAL in result.denial_reasons


def test_malformed_timestamps_block():
    approval = _approval(issued_at="2026-07-14 08:00:00")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert TIMESTAMP_INVALID in result.denial_reasons


def test_invalid_expiry_ordering_blocks():
    approval = _approval(expires_at="2026-07-14T08:00:00Z")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert TIMESTAMP_ORDER_INVALID in result.denial_reasons


def test_future_invalid_approval_blocks():
    approval = _approval(issued_at="2026-07-15T08:00:00Z", expires_at="2026-07-16T08:00:00Z")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert FUTURE_APPROVAL_INVALID in result.denial_reasons


def test_insufficient_approval_count_blocks():
    approval = _approval(required_approver_count=2, recorded_approver_count=1)
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert INSUFFICIENT_APPROVER_COUNT in result.denial_reasons


def test_duplicate_approver_hashes_block():
    approval = _approval(
        required_approver_count=2,
        recorded_approver_count=2,
        dual_approval_required=True,
        approver_hashes=(_hash("approver-1"), _hash("approver-1")),
    )
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert DUPLICATE_APPROVER_REFERENCE in result.denial_reasons


def test_missing_approver_reference_blocks():
    approval = _approval(recorded_approver_count=1, approver_hashes=())
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert MISSING_APPROVER_REFERENCE in result.denial_reasons


def test_dual_approval_not_satisfied_blocks():
    approval = _approval(dual_approval_required=True, required_approver_count=2, recorded_approver_count=1)
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert DUAL_APPROVAL_NOT_SATISFIED in result.denial_reasons


def test_malformed_approval_hash_blocks():
    result = validate_runtime_approval(_request(approval=_approval(approval_hash="sha256:not-valid")))

    assert result.status == APPROVAL_BLOCKED
    assert INVALID_HASH in result.denial_reasons


def test_approval_hash_mismatch_blocks():
    result = validate_runtime_approval(_request(approval=_approval(approval_hash=_hash("wrong"))))

    assert result.status == APPROVAL_BLOCKED
    assert APPROVAL_HASH_MISMATCH in result.denial_reasons


def test_policy_evidence_tenant_mismatch_blocks():
    approval = _approval(policy_hash=_hash("other-policy"), evidence_hash=_hash("other-evidence"), tenant_hash=_hash("other-tenant"))
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert POLICY_HASH_MISMATCH in result.denial_reasons
    assert EVIDENCE_HASH_MISMATCH in result.denial_reasons
    assert TENANT_HASH_MISMATCH in result.denial_reasons


def test_decision_action_actor_mismatch_blocks():
    approval = _approval(
        decision_hash=_hash("other-decision"),
        action_contract_hash=_hash("other-action"),
        actor_role_hash=_hash("other-actor-role"),
    )
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert DECISION_CONTINUITY_MISMATCH in result.denial_reasons
    assert ACTION_CONTRACT_HASH_MISMATCH in result.denial_reasons
    assert ACTOR_ROLE_HASH_MISMATCH in result.denial_reasons


def test_unsupported_schema_and_approval_version_block():
    approval = _approval(schema_version="phase-b.unknown", approval_version="phase-b.unknown")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert UNKNOWN_SCHEMA_VERSION in result.denial_reasons
    assert UNKNOWN_APPROVAL_VERSION in result.denial_reasons


def test_unknown_and_capitalization_mismatch_status_blocks():
    for status in ("approved", "APPROVED ", "ALLOW"):
        approval = _approval(approval_status=status)
        approval["approval_hash"] = deterministic_approval_hash(approval)
        result = validate_runtime_approval(_request(approval=approval))
        assert result.status == APPROVAL_BLOCKED
        assert UNKNOWN_APPROVAL_STATUS in result.denial_reasons


def test_unknown_metadata_blocks():
    approval = _approval()
    approval["approval_comment_hash"] = _hash("not-allowed")

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert UNKNOWN_METADATA in result.denial_reasons


def test_raw_personal_data_and_credentials_block():
    approval = _approval()
    approval["comment"] = "human approved this"
    approval["token"] = "secret-token"

    result = validate_runtime_approval(_request(approval=approval))

    assert result.status == APPROVAL_BLOCKED
    assert RAW_APPROVAL_CONTENT_PRESENT in result.denial_reasons
    assert SENSITIVE_DATA_PRESENT in result.denial_reasons


def test_unredacted_and_non_hash_only_evidence_blocks():
    approval = _approval(redacted=False, hash_only=False)
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert NON_HASH_ONLY_EVIDENCE in result.denial_reasons
    assert UNREDACTED_EVIDENCE in result.denial_reasons


def test_execution_flags_block_and_remain_false():
    approval = _approval(execution_allowed=True, provider_execution=True, production_activation=True)
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert EXECUTION_FLAG_ENABLED in result.denial_reasons
    assert PROVIDER_EXECUTION_ENABLED in result.denial_reasons
    assert PRODUCTION_ACTIVATION_ENABLED in result.denial_reasons
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_malformed_approval_id_blocks():
    approval = _approval(approval_id="runtime-001")
    approval["approval_hash"] = deterministic_approval_hash(approval)

    result = validate_runtime_approval(_request(approval=approval))

    assert MALFORMED_APPROVAL_ID in result.denial_reasons


def test_deterministic_serialization_and_denial_evidence():
    first = validate_runtime_approval(_request())
    second = validate_runtime_approval(_request())
    blocked_first = validate_runtime_approval(_request(approval=_approval(approval_status="PENDING")))
    blocked_second = validate_runtime_approval(_request(approval=_approval(approval_status="PENDING")))

    assert first.as_dict() == second.as_dict()
    assert blocked_first.as_dict() == blocked_second.as_dict()
    assert blocked_first.denial_code in gate.DENIAL_CODES


def test_output_is_hash_only_and_redacted():
    result = validate_runtime_approval(_request())
    rendered = json.dumps(result.as_dict(), sort_keys=True)

    assert "approval-runtime-001" not in rendered
    assert "human approved" not in rendered
    assert HASH_RE.match(result.approval_id_hash)


def test_no_execution_capable_imports_or_calls():
    source = SOURCE.read_text(encoding="utf-8")

    for forbidden in (
        "import asyncio",
        "import os",
        "import socket",
        "import subprocess",
        "import threading",
        "requests",
        "urllib",
        "redis",
        "kafka",
        "tmux",
        "eval(",
        "exec(",
    ):
        assert forbidden not in source


def test_evidence_fixture_is_hash_only_and_redacted():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_gate_hash"])
    assert set(gate.DENIAL_CODES).issubset(set(evidence["denial_codes"]))
    for forbidden in ("credential_value", "provider_value", "secret_value", "token_value", "customer_email"):
        assert forbidden not in rendered
