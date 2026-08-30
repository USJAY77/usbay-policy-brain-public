from __future__ import annotations

import pytest

from governance.capability_manifest import (
    CAPABILITY_MANIFEST,
    DEFAULT_REQUIRED_CONTROLS,
    capability_ids,
    list_capabilities,
    validate_capability_manifest,
)


pytestmark = pytest.mark.governance


def test_capability_manifest_is_unique_and_read_only():
    validation = validate_capability_manifest()

    assert validation["status"] == "VALID"
    assert validation["duplicate_capability_ids"] == []
    assert validation["unknown_controls"] == []
    assert validation["unknown_reason_namespaces"] == []
    assert validation["missing_dashboard_states"] == []
    assert validation["execution_enabled"] is False
    assert validation["deployment_enabled"] is False
    assert validation["runtime_modification_enabled"] is False
    assert len(capability_ids()) == len(set(capability_ids()))
    assert list_capabilities()[0] is not CAPABILITY_MANIFEST[0]


def test_capability_manifest_covers_recent_governed_layers():
    ids = set(capability_ids())

    assert {"model_governance", "prompt_governance", "lifecycle_governance", "commercial_governance"} <= ids


def test_every_capability_has_baseline_controls():
    required = set(DEFAULT_REQUIRED_CONTROLS)

    for capability in CAPABILITY_MANIFEST:
        assert required <= set(capability["controls"])
