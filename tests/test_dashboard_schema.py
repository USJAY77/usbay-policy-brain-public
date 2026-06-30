from __future__ import annotations

import pytest

from governance.capability_manifest import capability_ids
from governance.dashboard_schema import dashboard_schema, validate_dashboard_schema


pytestmark = pytest.mark.governance


def test_dashboard_schema_is_derived_from_capability_manifest():
    schema = dashboard_schema()
    validation = validate_dashboard_schema()

    assert validation["status"] == "VALID"
    assert validation["duplicate_sections"] == []
    assert validation["missing_states"] == []
    assert schema["read_only"] is True
    assert schema["execution_enabled"] is False
    assert schema["deployment_enabled"] is False
    assert schema["runtime_modification_enabled"] is False
    assert tuple(section["capability_id"] for section in schema["sections"]) == capability_ids()


def test_dashboard_schema_includes_required_recent_sections():
    sections = {section["capability_id"]: section for section in dashboard_schema()["sections"]}

    assert "prompt_status" in sections["prompt_governance"]["required_states"]
    assert "lifecycle_status" in sections["lifecycle_governance"]["required_states"]
    assert "commercial_status" in sections["commercial_governance"]["required_states"]
