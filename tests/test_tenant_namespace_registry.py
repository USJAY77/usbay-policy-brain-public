from __future__ import annotations

import pytest

from governance.tenant_namespace_registry import build_namespace_registry, resolve_namespace


pytestmark = pytest.mark.governance


def entry(tenant_id="tenant-1", **overrides):
    payload = {
        "tenant_id": tenant_id,
        "policy_namespace": f"{tenant_id}/policy",
        "evidence_namespace": f"{tenant_id}/evidence",
        "audit_namespace": f"{tenant_id}/audit",
        "release_namespace": f"{tenant_id}/release",
        "document_namespace": f"{tenant_id}/document",
        "connector_namespace": f"{tenant_id}/connector",
        "operator_namespace": f"{tenant_id}/operator",
    }
    payload.update(overrides)
    return payload


def test_valid_namespace_match():
    registry = build_namespace_registry([entry()])
    status, reasons = resolve_namespace(registry, tenant_id="tenant-1", namespace="tenant-1/policy")

    assert registry["tenant_namespace_status"] == "READY"
    assert status == "ALLOWED_WITHIN_TENANT"
    assert reasons == ()


def test_missing_namespace_blocks():
    registry = build_namespace_registry([entry(policy_namespace="")])

    assert registry["tenant_namespace_status"] == "BLOCKED"
    assert "BLOCKED_WITH_MISSING_NAMESPACE:policy_namespace" in registry["reason_codes"]


def test_tenant_mismatch_blocks():
    registry = build_namespace_registry([entry("tenant-1"), entry("tenant-2")])
    status, reasons = resolve_namespace(registry, tenant_id="tenant-2", namespace="tenant-1/policy")

    assert status == "BLOCKED"
    assert "BLOCKED_WITH_TENANT_MISMATCH" in reasons


def test_wildcard_tenant_access_blocks():
    registry = build_namespace_registry([entry("*")])

    assert registry["tenant_namespace_status"] == "BLOCKED"
    assert "TENANT_IMPLICIT_OR_WILDCARD_BLOCKED" in registry["reason_codes"]


def test_no_data_movement_enabled():
    registry = build_namespace_registry([entry()])

    assert registry["copy_enabled"] is False
    assert registry["move_enabled"] is False
    assert registry["sync_enabled"] is False
    assert registry["export_enabled"] is False
    assert registry["wildcard_tenant_access"] is False
