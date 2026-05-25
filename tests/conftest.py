from __future__ import annotations

from pathlib import Path

import pytest


CRITICAL_NODEIDS = {
    "tests/test_production_readiness.py::test_ci_evidence_manifest_rejects_invalid_signature",
    "tests/test_production_readiness.py::test_ci_evidence_manifest_rejects_untrusted_ci_private_secret",
    "tests/test_production_readiness.py::test_ci_evidence_public_key_fingerprint_normalizes_escaped_newlines",
    "tests/test_production_readiness.py::test_ci_evidence_public_key_fingerprint_ignores_trailing_whitespace",
    "tests/test_production_readiness.py::test_ci_evidence_trust_policy_fingerprint_matches_manifest_fingerprint",
    "tests/test_live_pilot_v1.py::test_live_pilot_v1_verification_markers_all_pass",
}

GOVERNANCE_FILES = {
    "tests/test_enterprise_nonce_replay.py",
    "tests/test_gateway_app.py",
    "tests/test_gateway_hydra.py",
    "tests/test_governance_validation.py",
    "tests/test_hydra_consensus.py",
    "tests/test_node_attestation.py",
    "tests/test_policy_verification_workflow.py",
    "tests/test_public_release_safety.py",
    "tests/test_redis_store.py",
    "tests/test_runtime_governance_monitor.py",
}

DEPENDENCY_FILES = {
    "tests/test_codex_trigger.py",
    "tests/test_ci_tiered_validation.py",
}

SLOW_FILES = {
    "tests/test_production_readiness.py",
    "tests/test_tenant_audit_package.py",
}

DEPENDENCY_NODEIDS = {
    "tests/test_production_readiness.py::test_ci_dependency_sbom_contains_auditable_inventory",
    "tests/test_production_readiness.py::test_ci_dependency_sbom_fails_closed_on_incomplete_inventory",
    "tests/test_production_readiness.py::test_ci_dependency_sbom_fails_closed_without_governance_crypto",
}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        path = Path(str(item.fspath)).as_posix()
        try:
            path = str(Path(path).relative_to(Path.cwd())).replace("\\", "/")
        except ValueError:
            path = path.replace("\\", "/")

        if item.nodeid in CRITICAL_NODEIDS:
            item.add_marker(pytest.mark.critical)
        if path in GOVERNANCE_FILES:
            item.add_marker(pytest.mark.governance)
        if path in DEPENDENCY_FILES or item.nodeid in DEPENDENCY_NODEIDS:
            item.add_marker(pytest.mark.dependency)
        if path in SLOW_FILES:
            item.add_marker(pytest.mark.slow)
        if not any(item.iter_markers(name=name) for name in ("critical", "governance", "dependency")):
            item.add_marker(pytest.mark.regression)
