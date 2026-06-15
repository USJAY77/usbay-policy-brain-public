from __future__ import annotations

# Purpose: compatibility shim for modular governance provenance helpers.
# Governance scope: preserves existing test imports while implementation is isolated.
# Fail-closed expectation: all behavior delegates to canonical helper modules.
# Sensitive-data handling: this shim handles no evidence or secret material directly.

from tests.helpers import (
    RUNTIME_TRUST_STATE_FIELDS,
    current_authority_lineage_snapshot,
    ensure_test_release_manifest,
    install_isolated_audit_key_registry,
    install_signed_runtime_attestation_fixture,
    install_runtime_authority,
    runtime_trust_state,
    valid_test_release_manifest,
)

__all__ = [
    "RUNTIME_TRUST_STATE_FIELDS",
    "current_authority_lineage_snapshot",
    "ensure_test_release_manifest",
    "install_isolated_audit_key_registry",
    "install_signed_runtime_attestation_fixture",
    "install_runtime_authority",
    "runtime_trust_state",
    "valid_test_release_manifest",
]
