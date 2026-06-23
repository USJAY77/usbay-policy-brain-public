from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GAME_HARNESS = os.path.join(_ROOT, "tests", "game_dom_harness.mjs")


def _node_with_jsdom() -> bool:
    return bool(shutil.which("node")) and os.path.isdir(
        os.path.join(_ROOT, "node_modules", "jsdom")
    )


@pytest.fixture(scope="session")
def dom_result():
    """Render the additive demo-only /game prototype once, execute its real
    client-side JavaScript inside jsdom via the shared harness, and return the
    parsed interaction report.

    Session-scoped so every interactive/UX DOM test file reuses a single jsdom
    run (jsdom's module load is expensive); this keeps the suite to one render.
    Strictly additive and read-only: no live server, no /api, no /execute, no
    governance enforcement, no external calls.
    """
    if not _node_with_jsdom():
        pytest.skip("node + jsdom not available for interactive DOM tests")
    from fastapi.testclient import TestClient

    from gateway.app import app

    client = TestClient(app)
    resp = client.get("/game")
    assert resp.status_code == 200, f"/game returned {resp.status_code}"
    proc = subprocess.run(
        ["node", _GAME_HARNESS],
        input=resp.text,
        capture_output=True,
        text=True,
        cwd=_ROOT,
        timeout=300,
    )
    assert proc.returncode == 0, f"harness exited {proc.returncode}: {proc.stderr}"
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - diagnostic path
        raise AssertionError(
            f"harness produced no JSON: {exc}\n"
            f"stdout: {proc.stdout[:800]}\nstderr: {proc.stderr[:800]}"
        )
    # Optional, additive: when the GAME-010R stability gate sets this env var,
    # persist the parsed render so the gate can read benchmark timing and the
    # safety-regression evidence from the SAME single jsdom render (no extra
    # import). Purely diagnostic; no effect on test behavior when unset.
    _dump = os.environ.get("GAME_STABILITY_DUMP")
    if _dump:
        try:
            with open(_dump, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
        except OSError:  # pragma: no cover - best-effort diagnostic
            pass
    return data


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
