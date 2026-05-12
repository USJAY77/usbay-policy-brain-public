from __future__ import annotations

from pathlib import Path

from governance.dependencies import GOVERNANCE_DOMAIN_MODULES
from governance.operations_observability import (
    collect_governance_health_snapshot,
    verify_baseline_lineage_status,
    verify_dependency_graph_status,
    verify_governance_status,
)
from governance.release_integrity import (
    DEFAULT_BASELINE_TAG,
    build_release_integrity_manifest,
    sign_release_integrity_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def _module_sources() -> dict[str, str]:
    return {
        module_name: (ROOT / Path(*module_name.split(".")).with_suffix(".py")).read_text(encoding="utf-8")
        for module_name in GOVERNANCE_DOMAIN_MODULES.values()
    }


def test_governance_status_snapshot_is_valid_and_audit_safe() -> None:
    snapshot = verify_governance_status(ROOT, regression_suite_status="passed")
    payload = snapshot.to_dict()

    assert payload["valid"] is True
    assert payload["signer_continuity_status"] == "valid"
    assert payload["release_baseline_status"] == "valid"
    assert payload["regression_suite_status"] == "passed"
    assert payload["dependency_graph_hash"]
    assert payload["trust_policy_fingerprint"]
    assert payload["metrics"]["trust_policy_validation_count"] == 1
    assert "PRIVATE KEY" not in str(payload)


def test_stale_baseline_detection_fails_closed() -> None:
    manifest = build_release_integrity_manifest(
        ROOT,
        release_id="ops-stale-baseline",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:00:00Z",
    )
    manifest["governance_baseline"]["tag_commit"] = "0" * 40
    manifest["release_signature"] = sign_release_integrity_manifest(manifest)

    snapshot = collect_governance_health_snapshot(ROOT, release_manifest=manifest)

    assert snapshot.valid is False
    assert snapshot.release_baseline_status == "invalid"
    assert "release_integrity_tag_drift" in snapshot.failures
    assert snapshot.metrics.fail_closed_rejection_count >= 1


def test_dependency_corruption_records_drift_telemetry() -> None:
    sources = _module_sources()
    sources["governance.evidence"] += "\nfrom governance.chronology import validate_chronology_consensus_interface\n"

    snapshot = collect_governance_health_snapshot(ROOT, dependency_module_sources=sources)

    assert snapshot.valid is False
    assert snapshot.metrics.dependency_drift_events >= 1
    assert "GOVERNANCE_FORBIDDEN_DOMAIN_IMPORT:governance.evidence:governance.chronology" in snapshot.failures


def test_release_mismatch_fails_closed() -> None:
    manifest = build_release_integrity_manifest(
        ROOT,
        release_id="ops-release-mismatch",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:00:00Z",
    )
    manifest["trust_policy_fingerprint"] = "0" * 64

    snapshot = collect_governance_health_snapshot(ROOT, release_manifest=manifest)

    assert snapshot.valid is False
    assert "release_integrity_signature_invalid" in snapshot.failures
    assert "release_integrity_trust_policy_mismatch" in snapshot.failures


def test_rollback_invalidation_records_fail_closed_event() -> None:
    previous = build_release_integrity_manifest(
        ROOT,
        release_id="ops-rollback-prev",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:00:00Z",
    )
    current = build_release_integrity_manifest(
        ROOT,
        release_id="ops-rollback-current",
        governance_baseline_tag=DEFAULT_BASELINE_TAG,
        generated_at="2026-05-12T00:01:00Z",
        previous_manifest=previous,
    )

    snapshot = collect_governance_health_snapshot(ROOT, release_manifest=current)

    assert snapshot.valid is False
    assert "release_integrity_rollback_target_invalid" in snapshot.failures
    assert snapshot.metrics.fail_closed_rejection_count >= 1


def test_dependency_and_baseline_diagnostics_pass() -> None:
    dependency = verify_dependency_graph_status(ROOT)
    baseline = verify_baseline_lineage_status(ROOT)

    assert dependency["graph_hash"]
    assert baseline["release_baseline_status"] == "valid"
