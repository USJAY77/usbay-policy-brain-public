from __future__ import annotations

from pathlib import Path

from governance.dependencies import (
    GOVERNANCE_DOMAIN_MODULES,
    build_governance_dependency_map,
    validate_governance_dependency_map,
)
from governance.telemetry import measure_governance_validation
from governance.trust_policy import validate_trust_policy_interface


ROOT = Path(__file__).resolve().parents[1]


def _module_sources() -> dict[str, str]:
    sources: dict[str, str] = {}
    for module_name in GOVERNANCE_DOMAIN_MODULES.values():
        sources[module_name] = (ROOT / Path(*module_name.split(".")).with_suffix(".py")).read_text(encoding="utf-8")
    return sources


def test_governance_dependency_map_is_deterministic() -> None:
    first = build_governance_dependency_map(ROOT)
    second = build_governance_dependency_map(ROOT)

    assert first.to_dict() == second.to_dict()
    assert first.nodes == tuple(sorted(GOVERNANCE_DOMAIN_MODULES.values()))
    assert first.edges == (
        ("governance.chronology", "governance.interfaces"),
        ("governance.evidence", "governance.interfaces"),
        ("governance.timestamping", "governance.interfaces"),
        ("governance.trust_policy", "governance.interfaces"),
    )


def test_circular_dependency_introduction_fails_closed() -> None:
    sources = _module_sources()
    sources["governance.evidence"] += "\nfrom governance.chronology import validate_chronology_consensus_interface\n"
    sources["governance.chronology"] += "\nfrom governance.evidence import validate_evidence_manifest_interface\n"

    result = validate_governance_dependency_map(ROOT, module_sources=sources)

    assert result.valid is False
    assert "GOVERNANCE_CIRCULAR_IMPORT_DETECTED" in result.failures
    assert "GOVERNANCE_FORBIDDEN_DOMAIN_IMPORT:governance.evidence:governance.chronology" in result.failures
    assert "GOVERNANCE_FORBIDDEN_DOMAIN_IMPORT:governance.chronology:governance.evidence" in result.failures


def test_forbidden_runtime_domain_access_fails_closed() -> None:
    sources = _module_sources()
    sources["governance.trust_policy"] += "\nfrom scripts.generate_ci_evidence_manifest import signer_key_id\n"

    result = validate_governance_dependency_map(ROOT, module_sources=sources)

    assert result.valid is False
    assert "GOVERNANCE_RUNTIME_COUPLING_FORBIDDEN:governance.trust_policy:scripts.generate_ci_evidence_manifest" in result.failures


def test_dependency_graph_drift_fails_closed() -> None:
    graph = build_governance_dependency_map(ROOT)

    result = validate_governance_dependency_map(ROOT, expected_graph_hash="0" * 64)

    assert result.valid is False
    assert graph.graph_hash != "0" * 64
    assert "GOVERNANCE_DEPENDENCY_GRAPH_DRIFT" in result.failures


def test_governance_telemetry_integrity_for_trust_policy_validation() -> None:
    policy = {
        "policy_version": "ci-evidence-trust-v1",
        "allowed_signers": [
            {
                "signer_id": "github-actions-production-readiness",
                "public_key_fingerprint": "a" * 64,
                "public_key_pem": "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----\n",
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
        "revoked_fingerprints": [],
    }

    result, metric = measure_governance_validation(
        "trust_policy",
        "unit_test",
        validate_trust_policy_interface,
        policy,
    )

    assert result.valid is True
    assert metric.domain == "trust_policy"
    assert metric.operation == "unit_test"
    assert metric.validation_latency_ns >= 0
    assert metric.artifact_count == 1
    assert metric.valid is True
    assert metric.failure_count == 0
