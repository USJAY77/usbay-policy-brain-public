from __future__ import annotations

import pytest

from governance.tenant_boundary_contracts import build_tenant_identity, validate_tenant_identity


pytestmark = pytest.mark.governance


def tenant(**overrides):
    payload = {
        "tenant_id": "tenant-1",
        "tenant_name": "Tenant One",
        "tenant_region": "EU",
        "tenant_classification": "ENTERPRISE",
        "policy_namespace": "tenant-1/policy",
        "evidence_namespace": "tenant-1/evidence",
        "audit_namespace": "tenant-1/audit",
        "release_namespace": "tenant-1/release",
        "document_namespace": "tenant-1/document",
        "requested_by": "human-1",
        "created_at": "2026-06-18T08:00:00Z",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
    }
    payload.update(overrides)
    return build_tenant_identity(**payload)


def test_valid_tenant_identity():
    validation = validate_tenant_identity(tenant())

    assert validation.valid is True
    assert validation.status == "VERIFIED"


def test_missing_tenant_id_blocks():
    validation = validate_tenant_identity(tenant(tenant_id=""))

    assert validation.status == "BLOCKED"
    assert "TENANT_TENANT_ID_MISSING" in validation.reason_codes


def test_unknown_classification_blocks():
    validation = validate_tenant_identity(tenant(tenant_classification="PUBLIC"))

    assert validation.status == "BLOCKED"
    assert "TENANT_CLASSIFICATION_UNKNOWN:PUBLIC" in validation.reason_codes


def test_wildcard_or_global_tenant_blocks():
    validation = validate_tenant_identity(tenant(tenant_id="*"))

    assert validation.status == "BLOCKED"
    assert "TENANT_IMPLICIT_OR_WILDCARD_BLOCKED" in validation.reason_codes


def test_boundary_hash_mismatch_detects_tamper():
    payload = tenant()
    payload["tenant_region"] = "US"

    validation = validate_tenant_identity(payload)

    assert validation.status == "TAMPER_DETECTED"
