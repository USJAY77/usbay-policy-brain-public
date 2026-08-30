from __future__ import annotations

import json

from governance.production_integration_matrix import (
    DEFERRED,
    DEFERRED_INTEGRATION_ORDER,
    EXECUTION_FLAGS,
    OBJECT_LOCK_INTEGRATION,
    REGULATOR_EXPORT_INTEGRATION,
    RFC3161_INTEGRATION,
    TIMESTAMP_AUTHORITY_INTEGRATION,
    WORM_INTEGRATION,
    deferred_production_integrations,
    production_integration_matrix,
    verify_production_integration_matrix,
)
from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER
from governance.regulator_export_profile import REGULATOR_EXPORT_MODE
from governance.worm_immutable_storage import WORM_IMMUTABLE_STORAGE_MODE


def test_production_integration_matrix_is_deterministic_and_hash_only() -> None:
    first = production_integration_matrix()
    second = production_integration_matrix()

    assert first == second
    assert verify_production_integration_matrix(first) == ()
    assert first["status"] == DEFERRED
    assert first["matrix_hash"].startswith("sha256:")

    rendered = json.dumps(first, sort_keys=True)
    assert "raw_payload" not in rendered
    assert "approval_content" not in rendered
    assert "private_key" not in rendered
    assert "credential" not in rendered
    assert "secret" not in rendered


def test_all_future_integrations_remain_fail_closed() -> None:
    matrix = production_integration_matrix()

    for flag in EXECUTION_FLAGS:
        assert matrix[flag] is False
    for integration in matrix["integrations"]:
        for flag in EXECUTION_FLAGS:
            assert integration[flag] is False


def test_integration_order_is_fixed_and_dependency_safe() -> None:
    integrations = {item.integration_id: item for item in deferred_production_integrations()}

    assert tuple(production_integration_matrix()["integration_order"]) == DEFERRED_INTEGRATION_ORDER
    assert DEFERRED_INTEGRATION_ORDER == (
        RFC3161_INTEGRATION,
        TIMESTAMP_AUTHORITY_INTEGRATION,
        "external_signing_authority",
        WORM_INTEGRATION,
        OBJECT_LOCK_INTEGRATION,
        REGULATOR_EXPORT_INTEGRATION,
    )
    assert RFC3161_INTEGRATION in integrations[TIMESTAMP_AUTHORITY_INTEGRATION].dependencies
    assert TIMESTAMP_AUTHORITY_INTEGRATION in integrations[WORM_INTEGRATION].dependencies
    assert OBJECT_LOCK_INTEGRATION in integrations[REGULATOR_EXPORT_INTEGRATION].dependencies


def test_matrix_uses_existing_placeholder_constants() -> None:
    integrations = {item.integration_id: item for item in deferred_production_integrations()}

    assert integrations[RFC3161_INTEGRATION].current_placeholder == DEFAULT_POLICY_OID_PLACEHOLDER
    assert integrations[WORM_INTEGRATION].current_placeholder == WORM_IMMUTABLE_STORAGE_MODE
    assert integrations[REGULATOR_EXPORT_INTEGRATION].current_placeholder == REGULATOR_EXPORT_MODE


def test_matrix_fails_closed_on_drift() -> None:
    matrix = production_integration_matrix()
    matrix["integrations"][0]["execution_allowed"] = True
    matrix["matrix_hash"] = "sha256:" + ("0" * 64)

    errors = verify_production_integration_matrix(matrix)

    assert "PRODUCTION_INTEGRATION_MATRIX_EXECUTION_FLAG_INVALID" in errors
    assert "PRODUCTION_INTEGRATION_MATRIX_HASH_INVALID" in errors
