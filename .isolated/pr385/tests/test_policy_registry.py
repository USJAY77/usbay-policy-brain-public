from __future__ import annotations

import pytest

from governance.policy_registry import PolicyRegistry, empty_policy_registry_dashboard_state
from governance.policy_registry_contracts import build_policy_record


pytestmark = pytest.mark.governance


def policy(version="v1", status="DRAFT", created_at="2026-06-18T08:00:00Z", **overrides):
    payload = {
        "policy_id": "policy-1",
        "policy_name": "Runtime Governance",
        "policy_version": version,
        "parent_version": "" if version == "v1" else "v1",
        "status": status,
        "created_at": created_at,
        "approved_at": "2026-06-18T09:00:00Z" if status in {"APPROVED", "ACTIVE", "DEPRECATED", "RETIRED"} else "",
        "approved_by": "human-1" if status in {"APPROVED", "ACTIVE", "DEPRECATED", "RETIRED"} else "",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return build_policy_record(**payload)


def test_valid_registration_and_queries():
    records = [policy(), policy(version="v2", status="ACTIVE", created_at="2026-06-18T10:00:00Z")]
    registry = PolicyRegistry(records)

    result = registry.register_policy(records[0])

    assert result["registration_status"] == "REGISTERED_READ_ONLY"
    assert registry.get_policy_version("policy-1", "v1")["policy_version"] == "v1"
    assert registry.list_policy_versions("policy-1") == ["v1", "v2"]
    assert registry.get_latest_policy("policy-1")["policy_version"] == "v2"


def test_invalid_registration_blocks():
    record = policy()
    record["audit_hash"] = ""

    result = PolicyRegistry().register_policy(record)

    assert result["registration_status"] in {"BLOCKED", "TAMPER_DETECTED"}
    assert result["auto_promoted"] is False


def test_summary_counts_active_and_deprecated():
    registry = PolicyRegistry([policy(status="ACTIVE"), policy(version="v2", status="DEPRECATED", created_at="2026-06-18T10:00:00Z")])

    summary = registry.summary()

    assert summary["policy_count"] == 2
    assert summary["active_policy_count"] == 1
    assert summary["deprecated_policy_count"] == 1
    assert summary["auto_approved"] is False


def test_empty_dashboard_state_blocks():
    state = empty_policy_registry_dashboard_state()

    assert state["policy_registry_status"] == "BLOCKED"
    assert state["policy_count"] == 0
    assert state["promotion_status"] == "BLOCKED"
