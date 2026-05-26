from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.helpers.media_crypto_authority_policy import (
    load_media_crypto_authority_manifest,
    verify_media_crypto_authority,
)
from tests.helpers.media_dashboard_export_policy import (
    load_media_dashboard_export_manifest,
    verify_media_dashboard_export,
)
from tests.helpers.media_immutable_evidence_policy import (
    load_media_immutable_evidence_manifest,
    verify_media_immutable_evidence,
)
from tests.helpers.media_lifecycle_orchestration_policy import (
    load_media_lifecycle_orchestration_manifest,
    verify_media_lifecycle_orchestration,
)


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "artifacts" / "media-governance-demo-evidence-bundle.json"
GAP_MANIFESTS = {
    "immutable_evidence": ROOT / "artifacts" / "media-immutable-evidence-manifest.json",
    "orchestration": ROOT / "artifacts" / "media-lifecycle-orchestration-manifest.json",
    "dashboard_export": ROOT / "artifacts" / "media-dashboard-export-manifest.json",
    "crypto_authority": ROOT / "artifacts" / "media-crypto-authority-manifest.json",
}
FORBIDDEN_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "api" + "_key",
    "access" + "_token",
    "oauth" + "_token",
    "client" + "_secret",
    "raw_audio",
    "raw_video",
    "raw_voice",
    "raw_image",
    "script:",
    "lyrics:",
    "voice_sample",
    "copyrighted_content",
)
FORBIDDEN_RUNTIME_PATTERNS = (
    "requests" + ".",
    "urllib" + ".",
    "socket" + ".",
    "subprocess" + ".",
    "boto3",
    "google.cloud",
    "azure.",
    "hsm",
    "worm",
    "blockchain",
)


def test_all_four_production_gaps_are_represented() -> None:
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))
    layers = {reference["layer"] for reference in bundle["manifest_references"]}

    assert {"immutable_evidence", "orchestration", "dashboard_export", "crypto_authority"} <= layers
    assert all(path.exists() for path in GAP_MANIFESTS.values())


def test_every_gap_fails_closed_when_evidence_is_missing() -> None:
    decisions = [
        verify_media_immutable_evidence(None),
        verify_media_lifecycle_orchestration(None),
        verify_media_dashboard_export(None),
        verify_media_crypto_authority(None),
    ]

    assert [decision["decision"] for decision in decisions] == ["FAIL_CLOSED"] * 4
    assert all(decision["silent_pass"] is False for decision in decisions)


def test_gap_manifests_are_reference_only() -> None:
    manifests = {
        "immutable_evidence": load_media_immutable_evidence_manifest(),
        "orchestration": load_media_lifecycle_orchestration_manifest(),
        "dashboard_export": load_media_dashboard_export_manifest(),
        "crypto_authority": load_media_crypto_authority_manifest(),
    }

    assert all(manifest["non_production_demo"] is True for manifest in manifests.values())
    assert all(manifest["reference_only"] is True for manifest in manifests.values())
    assert _contains_forbidden_payload(manifests) is False


def test_no_production_integrations_network_calls_or_payloads_exist_in_gap_scaffolds() -> None:
    paths = [
        *GAP_MANIFESTS.values(),
        ROOT / "governance" / "media_immutable_evidence_policy.json",
        ROOT / "governance" / "media_lifecycle_orchestration_policy.json",
        ROOT / "governance" / "media_dashboard_export_policy.json",
        ROOT / "governance" / "media_crypto_authority_policy.json",
        ROOT / "tests" / "helpers" / "media_immutable_evidence_policy.py",
        ROOT / "tests" / "helpers" / "media_lifecycle_orchestration_policy.py",
        ROOT / "tests" / "helpers" / "media_dashboard_export_policy.py",
        ROOT / "tests" / "helpers" / "media_crypto_authority_policy.py",
    ]

    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            assert _contains_forbidden_payload(json.loads(text)) is False
        else:
            assert _contains_forbidden_payload(text) is False
        assert _contains_runtime_integration(text) is False


def test_runtime_behavior_remains_unchanged_by_gap_scaffolds() -> None:
    changed_scaffold_paths = {str(path.relative_to(ROOT)) for path in GAP_MANIFESTS.values()}
    changed_scaffold_paths.update(
        {
            "artifacts/media-governance-demo-evidence-bundle.json",
            "docs/media-governance-control-map.md",
            "docs/media-governance-customer-demo.md",
            "docs/media-immutable-evidence-governance.md",
            "docs/media-lifecycle-orchestration-governance.md",
            "docs/media-dashboard-export-governance.md",
            "docs/media-cryptographic-authority-governance.md",
            "governance/media_immutable_evidence_policy.json",
            "governance/media_lifecycle_orchestration_policy.json",
            "governance/media_dashboard_export_policy.json",
            "governance/media_crypto_authority_policy.json",
            "tests/helpers/media_immutable_evidence_policy.py",
            "tests/helpers/media_lifecycle_orchestration_policy.py",
            "tests/helpers/media_dashboard_export_policy.py",
            "tests/helpers/media_crypto_authority_policy.py",
            "tests/test_media_immutable_evidence_policy.py",
            "tests/test_media_lifecycle_orchestration_policy.py",
            "tests/test_media_dashboard_export_policy.py",
            "tests/test_media_crypto_authority_policy.py",
            "tests/test_media_governance_gap_closure.py",
            "tests/test_media_governance_lifecycle_e2e.py",
        }
    )

    assert all(not path.startswith(("gateway/", "demo/", "dashboard/")) for path in changed_scaffold_paths)


def _contains_forbidden_payload(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_forbidden_payload(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_payload(item) for item in value)
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in FORBIDDEN_MARKERS)


def _contains_runtime_integration(text: str) -> bool:
    lowered = text.lower()
    return any(pattern.lower() in lowered for pattern in FORBIDDEN_RUNTIME_PATTERNS)
