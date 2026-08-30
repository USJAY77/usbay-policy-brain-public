from __future__ import annotations

import pytest

from governance.owner_roles import (
    AGGREGATE_OWNER,
    CONTRACT_OWNER,
    DEPRECATED_PROVIDER,
    PROVIDER,
    list_owner_roles,
    owner_role_registry,
    validate_owner_role,
)


pytestmark = pytest.mark.governance


def test_owner_roles_are_canonical_and_read_only():
    registry = owner_role_registry()

    assert set(list_owner_roles()) == {AGGREGATE_OWNER, CONTRACT_OWNER, PROVIDER, DEPRECATED_PROVIDER}
    assert validate_owner_role(AGGREGATE_OWNER) is True
    assert validate_owner_role("duplicate_owner") is False
    assert registry["read_only"] is True
    assert registry["execution_enabled"] is False
    assert registry["deployment_enabled"] is False
    assert registry["runtime_modification_enabled"] is False
