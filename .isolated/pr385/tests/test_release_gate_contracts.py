from __future__ import annotations

import pytest

from governance.release_gate_contracts import RELEASE_GATE_POLICY_VERSION, RELEASE_REQUEST_SCHEMA, build_release_audit_record, validate_release_request


pytestmark = pytest.mark.governance


def request(**overrides):
    payload = {
        "schema": RELEASE_REQUEST_SCHEMA,
        "release_id": "rel-1",
        "release_name": "Governed release",
        "release_type": "PATCH",
        "target_environment": "STAGING",
        "policy_version": RELEASE_GATE_POLICY_VERSION,
        "policy_hash": "p" * 64,
        "evidence_hash": "e" * 64,
        "audit_registry_hash": "a" * 64,
        "release_manifest_hash": "m" * 64,
        "requested_by": "human-1",
        "approved_by": "",
        "created_at": "2026-06-18T08:00:00Z",
        "approved_at": "",
        "decision": "REVIEW_REQUIRED",
        "reason_codes": [],
        "fail_closed": True,
    }
    payload.update(overrides)
    return payload


def test_valid_release_request():
    validation = validate_release_request(request())

    assert validation.valid is True
    assert validation.status == "VERIFIED"


@pytest.mark.parametrize("field", ["policy_hash", "evidence_hash", "audit_registry_hash"])
def test_missing_required_hash_blocks(field):
    validation = validate_release_request(request(**{field: ""}))

    assert validation.valid is False


def test_unknown_release_type_blocks():
    validation = validate_release_request(request(release_type="AUTO_DEPLOY"))

    assert validation.valid is False
    assert "RELEASE_TYPE_UNKNOWN:AUTO_DEPLOY" in validation.reason_codes


def test_invalid_target_environment_blocks():
    validation = validate_release_request(request(target_environment="PROD_NOW"))

    assert validation.valid is False
    assert "RELEASE_TARGET_ENVIRONMENT_INVALID:PROD_NOW" in validation.reason_codes


def test_rollback_plan_only_release_type_allowed():
    validation = validate_release_request(request(release_type="ROLLBACK_PLAN_ONLY", target_environment="ROLLBACK_PLAN"))

    assert validation.valid is True


def test_audit_record_never_enables_release_execution():
    audit = build_release_audit_record(release=request(), action="request", reason_codes=[])

    assert audit["audit_hash"]
    assert audit["deploy_enabled"] is False
    assert audit["publish_enabled"] is False
    assert audit["rollback_enabled"] is False
    assert audit["auto_promoted"] is False
