from __future__ import annotations

from dataclasses import replace

import pytest

from governance.hashing import sha256_reference
from governance.pbsec001_target_authorization import (
    ALLOW,
    BLOCK,
    APPROVED_SCAN_PROFILES,
    BLOCKED_TARGET_AUTHORIZATION_UNKNOWN,
    PBSEC001TargetAuthorizationRegistry,
    PBSEC001TargetAuthorizationRequest,
    PBSEC001TargetRecord,
    authorize_pbsec001_target,
    target_record_binding_hash,
)


NOW = "2026-08-17T08:00:00Z"
POLICY_HASH = "sha256:" + ("a" * 64)
TARGET_HASH = sha256_reference({"redacted_target": "nonprod-app-1"})
REMOTE_HASH = sha256_reference("github:USJAY77/usbay-policy-brain-public")
LOCAL_HASH = sha256_reference("/workspace/usbay-policy-brain")
SCAN_PROFILE = next(iter(APPROVED_SCAN_PROFILES))


def workspace_binding(**overrides):
    payload = {
        "workspace_id": "workspace-1",
        "repository_id": "repo-1",
        "remote_identity_hash": REMOTE_HASH,
        "local_identity_hash": LOCAL_HASH,
        "policy_id": "policy-pbsec001-target-v1",
        "policy_version_hash": POLICY_HASH,
    }
    payload.update(overrides)
    return payload


def record_without_binding(**overrides):
    payload = {
        "target_id": "target-nonprod-1",
        "target_identity_hash": TARGET_HASH,
        "environment": "NON_PRODUCTION",
        "allowed_scan_profile": SCAN_PROFILE,
        "policy_id": "policy-pbsec001-target-v1",
        "policy_version_hash": POLICY_HASH,
        "workspace_or_repository_binding": workspace_binding(),
        "release_revision_binding_requirement": True,
        "authorized_by": ("USBAY-AUDIT", "USBAY-GLOBAL23"),
        "authorization_evidence": {
            "human_authorized": True,
            "autonomous_authorized": False,
            "authorized_by": ("USBAY-AUDIT", "USBAY-GLOBAL23"),
            "evidence_hash": sha256_reference({"pr": 999, "reviews": ["USBAY-AUDIT", "USBAY-GLOBAL23"]}),
        },
        "authorized_at": "2026-08-17T07:00:00Z",
        "expires_at": "2026-08-18T07:00:00Z",
        "enabled": True,
    }
    payload.update(overrides)
    return PBSEC001TargetRecord(**payload)


def target_record(**overrides):
    record = record_without_binding(**overrides)
    evidence = dict(record.authorization_evidence)
    evidence["record_binding_hash"] = target_record_binding_hash(record)
    return replace(record, authorization_evidence=evidence)


def request(**overrides):
    payload = {
        "target_id": "target-nonprod-1",
        "target_identity_hash": TARGET_HASH,
        "allowed_scan_profile": SCAN_PROFILE,
        "policy_id": "policy-pbsec001-target-v1",
        "policy_version_hash": POLICY_HASH,
        "workspace_or_repository_binding": workspace_binding(),
    }
    payload.update(overrides)
    return PBSEC001TargetAuthorizationRequest(**payload)


def registry(records=None):
    return PBSEC001TargetAuthorizationRegistry([target_record()] if records is None else records, clock=lambda: NOW)


def assert_blocked(reason: str, *, records=None, req=None):
    decision = registry(records).authorize(req or request())
    assert decision.decision == BLOCK
    assert decision.reason_code == reason
    assert decision.evidence["network_performed"] is False
    assert decision.evidence["scan_executed"] is False
    assert decision.evidence["deployment_authority"] is False
    assert decision.evidence["production_authority"] is False
    return decision


def test_valid_human_authorized_non_prod_target_passes():
    decision = registry().authorize(request())

    assert decision.decision == ALLOW
    assert decision.reason_code == "PBSEC001_TARGET_AUTHORIZED"
    assert decision.target_record is not None
    assert decision.evidence["network_performed"] is False
    assert decision.evidence["scan_executed"] is False


def test_missing_target_blocks_unknown_authorization():
    decision = authorize_pbsec001_target(registry(), None)

    assert decision.decision == BLOCK
    assert decision.reason_code == BLOCKED_TARGET_AUTHORIZATION_UNKNOWN


def test_unknown_target_blocks():
    assert_blocked(BLOCKED_TARGET_AUTHORIZATION_UNKNOWN, req=request(target_id="unknown"))


def test_production_target_blocks():
    assert_blocked("PBSEC001_PRODUCTION_TARGET_BLOCKED", records=[target_record(environment="PRODUCTION")])


def test_wildcard_target_blocks():
    assert_blocked("PBSEC001_WILDCARD_TARGET_BLOCKED", records=[target_record(target_id="target-*")], req=request(target_id="target-*"))


def test_disabled_target_blocks():
    assert_blocked("PBSEC001_TARGET_DISABLED", records=[target_record(enabled=False)])


def test_expired_target_blocks():
    assert_blocked("PBSEC001_TARGET_AUTHORIZATION_EXPIRED", records=[target_record(expires_at="2026-08-17T07:59:59Z")])


def test_malformed_target_blocks():
    assert_blocked("PBSEC001_TARGET_AUTHORIZATION_SCHEMA_INVALID", records=[target_record(schema_version="wrong")])


def test_duplicate_target_blocks():
    assert_blocked("PBSEC001_TARGET_AUTHORIZATION_DUPLICATE", records=[target_record(), target_record()])


def test_ambiguous_duplicate_target_identity_blocks():
    other = target_record(target_id="target-nonprod-2")
    assert_blocked("PBSEC001_TARGET_AUTHORIZATION_AMBIGUOUS", records=[target_record(), other], req=request(target_id="target-nonprod-1"))


def test_missing_policy_binding_blocks():
    assert_blocked("PBSEC001_POLICY_BINDING_MISSING", records=[target_record(policy_version_hash="")])


def test_wrong_policy_version_blocks():
    assert_blocked("PBSEC001_POLICY_VERSION_MISMATCH", req=request(policy_version_hash="sha256:" + ("b" * 64)))


def test_wrong_workspace_binding_blocks():
    assert_blocked("PBSEC001_WORKSPACE_BINDING_MISMATCH", req=request(workspace_or_repository_binding=workspace_binding(repository_id="other")))


def test_unauthorized_scan_profile_blocks():
    assert_blocked("PBSEC001_SCAN_PROFILE_UNAUTHORIZED", records=[target_record(allowed_scan_profile="ZAP_FULL_SCAN_PROD")])


def test_missing_human_authorization_evidence_blocks():
    assert_blocked("PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_MISSING", records=[target_record(authorization_evidence={})])


def test_autonomous_registration_attempt_blocks():
    decision = registry([]).register_target_autonomously("AI_AGENT", target_record())

    assert decision.decision == BLOCK
    assert decision.reason_code == "PBSEC001_AUTONOMOUS_TARGET_REGISTRATION_BLOCKED"
    assert decision.evidence["autonomous_target_registration"] is False


def test_autonomous_mutation_attempt_blocks():
    decision = registry().mutate_target_autonomously("CODEX", "target-nonprod-1", {"environment": "PRODUCTION"})

    assert decision.decision == BLOCK
    assert decision.reason_code == "PBSEC001_AUTONOMOUS_TARGET_MUTATION_BLOCKED"
    assert decision.evidence["policy_mutation"] is False


def test_no_network_before_authorization():
    network_called = False

    def forbidden_network_call():
        nonlocal network_called
        network_called = True

    decision = registry([]).authorize(request())
    if decision.decision == ALLOW:  # pragma: no cover - safety guard
        forbidden_network_call()

    assert decision.decision == BLOCK
    assert network_called is False
    assert decision.evidence["network_performed"] is False


def test_no_scan_execution_or_authority_created():
    decision = registry().authorize(request())
    summary = registry().summary()

    assert decision.decision == ALLOW
    assert decision.evidence["scan_executed"] is False
    assert summary["network_authority"] is False
    assert summary["deployment_authority"] is False
    assert summary["production_authority"] is False
    assert summary["autonomous_policy_creation"] is False
    assert summary["policy_mutation"] is False
