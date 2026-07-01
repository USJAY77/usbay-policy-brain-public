from __future__ import annotations

import pytest

from governance.reason_code_registry import REASON_CODE_NAMESPACES, list_reason_code_namespaces, validate_reason_code_registry


pytestmark = pytest.mark.governance


def test_reason_code_registry_has_no_duplicate_definitions():
    validation = validate_reason_code_registry()

    assert validation["status"] == "VALID"
    assert validation["duplicate_reason_codes"] == []
    assert validation["empty_namespaces"] == []


def test_reason_code_registry_uses_common_namespace_for_shared_codes():
    namespaces = list_reason_code_namespaces()

    assert "common" in namespaces
    assert "MISSING_AUDIT_LINKAGE" in namespaces["common"]
    assert "MISSING_EVIDENCE_LINKAGE" in namespaces["common"]
    assert "MISSING_LINEAGE" in namespaces["common"]
    assert namespaces is not REASON_CODE_NAMESPACES
