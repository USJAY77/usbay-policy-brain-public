from __future__ import annotations

import pytest

from governance.connector_contracts import ALLOWED_CONNECTOR_TYPES
from governance.connector_registry import build_connector_registry, connector_available, empty_connector_dashboard_state


pytestmark = pytest.mark.governance


def test_valid_connector_registry_defaults_fail_closed_read_only():
    registry = build_connector_registry(last_checked_at="2026-06-17T06:00:00Z")

    assert registry["connector_count"] == len(ALLOWED_CONNECTOR_TYPES)
    assert registry["enabled_read_only_connectors"] == []
    for entry in registry["connector_registry"].values():
        assert entry["enabled"] is False
        assert entry["read_only"] is True
        assert entry["write_blocked"] is True
        assert entry["requires_human_approval"] is True
        assert entry["audit_required"] is True
        assert entry["evidence_required"] is True


def test_unknown_connector_blocks():
    available, reasons = connector_available(build_connector_registry(), "UNKNOWN")

    assert available is False
    assert "CONNECTOR_UNKNOWN:UNKNOWN" in reasons


def test_disabled_connector_blocks():
    available, reasons = connector_available(build_connector_registry(), "GITHUB")

    assert available is False
    assert "CONNECTOR_DISABLED:GITHUB" in reasons


def test_unhealthy_connector_blocks_even_when_enabled():
    registry = build_connector_registry(overrides={"GITHUB": {"enabled": True, "health_status": "DEGRADED"}})

    available, reasons = connector_available(registry, "GITHUB")

    assert available is False
    assert "CONNECTOR_UNHEALTHY:GITHUB" in reasons


def test_enabled_healthy_read_only_connector_available():
    registry = build_connector_registry(overrides={"GITHUB": {"enabled": True, "health_status": "HEALTHY", "reason_codes": []}})

    available, reasons = connector_available(registry, "GITHUB")

    assert available is True
    assert reasons == ()


def test_empty_dashboard_state_blocks_writes_and_auto_flags():
    state = empty_connector_dashboard_state()

    assert state["blocked_write_actions"] is True
    assert state["auto_connected"] is False
    assert state["auto_synced"] is False
    assert state["auto_authorized"] is False
    assert state["auto_sent"] is False
    assert state["auto_merged"] is False
    assert state["auto_deployed"] is False
    assert state["write_enabled"] is False
    assert state["secret_access_enabled"] is False
