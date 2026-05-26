from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.helpers.media_audit_export_policy import (
    load_media_audit_export_manifest,
    verify_media_audit_export_manifest,
)
from tests.helpers.media_distribution_gateway_policy import (
    valid_distribution_authorization,
    verify_distribution_authorization,
)
from tests.helpers.media_crypto_authority_policy import valid_crypto_authority_manifest, verify_media_crypto_authority
from tests.helpers.media_dashboard_export_policy import valid_dashboard_export_manifest, verify_media_dashboard_export
from tests.helpers.media_governance_watchtower_policy import (
    valid_watchtower_metrics,
    verify_governance_watchtower,
)
from tests.helpers.media_human_escalation_policy import (
    valid_human_escalation_evidence,
    verify_human_escalation,
)
from tests.helpers.media_immutable_evidence_policy import (
    valid_immutable_evidence_manifest,
    verify_media_immutable_evidence,
)
from tests.helpers.media_jurisdiction_policy import valid_jurisdiction_evidence, verify_media_jurisdiction
from tests.helpers.media_lifecycle_orchestration_policy import (
    valid_lifecycle_orchestration_manifest,
    verify_media_lifecycle_orchestration,
)
from tests.helpers.media_model_drift_policy import valid_drift_evidence, verify_media_model_drift
from tests.helpers.media_recovery_policy import valid_recovery_evidence, verify_media_recovery
from tests.helpers.media_redteam_policy import valid_redteam_evidence, verify_media_redteam
from tests.helpers.media_release_token_policy import valid_release_token, verify_media_release_token
from tests.helpers.media_revocation_policy import valid_revocation_state, verify_media_revocation_state
from tests.helpers.media_rights_consent_policy import valid_rights_consent_evidence, verify_media_rights_consent
from tests.test_media_governance_demo import _approval_evidence, _manifest, _release_decision, _timestamp_evidence


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_PATH = ROOT / "artifacts" / "media-governance-demo-evidence-bundle.json"
FAST_PR_WORKFLOW = ROOT / ".github" / "workflows" / "production-readiness.yml"
FORBIDDEN_PAYLOAD_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "api" + "_key",
    "access" + "_token",
    "oauth" + "_token",
    "client" + "_secret",
    "credentials",
    "legal_contract",
    "personal_data",
    "raw_audio",
    "raw_video",
    "raw_voice",
    "raw_image",
    "script:",
    "lyrics:",
    "voice_sample",
    "copyrighted_content",
)
REFERENCE_ONLY_SUFFIXES = (".json", ".md", ".py")


def test_full_media_governance_lifecycle_passes_then_redteam_override_fails_closed() -> None:
    manifest = _manifest(release_status="VERIFIED_RELEASE")
    media_asset_id = manifest["media_asset_id"]
    platform = "spotify"

    provenance = _provenance_decision(manifest, manifest["provenance_hash_placeholder"])
    approval = _approval_decision(_approval_evidence())
    timestamp = _timestamp_decision(_timestamp_evidence())
    rights = verify_media_rights_consent(valid_rights_consent_evidence())
    release_token = verify_media_release_token(valid_release_token(media_asset_id), media_asset_id=media_asset_id)
    distribution = verify_distribution_authorization(
        valid_distribution_authorization(media_asset_id, platform),
        media_asset_id=media_asset_id,
        platform=platform,
    )
    revocation = verify_media_revocation_state(valid_revocation_state(media_asset_id), media_asset_id=media_asset_id)
    jurisdiction = verify_media_jurisdiction(
        valid_jurisdiction_evidence(media_asset_id, platform=platform),
        media_asset_id=media_asset_id,
        platform=platform,
        export_required=True,
    )
    audit_export = verify_media_audit_export_manifest(load_media_audit_export_manifest())
    drift = verify_media_model_drift(valid_drift_evidence(media_asset_id), media_asset_id=media_asset_id)
    watchtower = verify_governance_watchtower(valid_watchtower_metrics())
    escalation = verify_human_escalation(valid_human_escalation_evidence())
    recovery = verify_media_recovery(valid_recovery_evidence())
    redteam_clear = verify_media_redteam(valid_redteam_evidence())
    immutable_evidence = verify_media_immutable_evidence(valid_immutable_evidence_manifest())
    orchestration = verify_media_lifecycle_orchestration(valid_lifecycle_orchestration_manifest())
    dashboard_export = verify_media_dashboard_export(valid_dashboard_export_manifest())
    crypto_authority = verify_media_crypto_authority(valid_crypto_authority_manifest())

    chain = (
        provenance,
        approval,
        timestamp,
        rights,
        release_token,
        distribution,
        revocation,
        jurisdiction,
        audit_export,
        drift,
        watchtower,
        escalation,
        recovery,
        redteam_clear,
        immutable_evidence,
        orchestration,
        dashboard_export,
        crypto_authority,
    )
    assert [decision["decision"] for decision in chain] == ["PASS"] * len(chain)

    release = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(media_asset_id),
        distribution_authorization=valid_distribution_authorization(media_asset_id, platform),
        revocation_state=valid_revocation_state(media_asset_id),
        jurisdiction_evidence=valid_jurisdiction_evidence(media_asset_id, platform=platform),
        drift_evidence=valid_drift_evidence(media_asset_id),
        watchtower_metrics=valid_watchtower_metrics(),
        human_escalation=valid_human_escalation_evidence(),
        recovery_evidence=valid_recovery_evidence(),
        redteam_evidence=valid_redteam_evidence(),
        platform=platform,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )
    assert release["decision"] == "PASS"
    assert release["adversarial_governance_clear"] is True
    assert release["raw_media_stored"] is False

    redteam_attack = valid_redteam_evidence()
    redteam_attack["governance_attack_state"] = "GOVERNANCE_BYPASS_ATTEMPT"
    blocked = _release_decision(
        manifest,
        approval=_approval_evidence(),
        timestamp=_timestamp_evidence(),
        rights_consent=valid_rights_consent_evidence(),
        release_token=valid_release_token(media_asset_id),
        distribution_authorization=valid_distribution_authorization(media_asset_id, platform),
        revocation_state=valid_revocation_state(media_asset_id),
        jurisdiction_evidence=valid_jurisdiction_evidence(media_asset_id, platform=platform),
        drift_evidence=valid_drift_evidence(media_asset_id),
        watchtower_metrics=valid_watchtower_metrics(),
        human_escalation=valid_human_escalation_evidence(),
        recovery_evidence=valid_recovery_evidence(),
        redteam_evidence=redteam_attack,
        platform=platform,
        observed_provenance_hash=manifest["provenance_hash_placeholder"],
    )

    assert blocked["decision"] == "FAIL_CLOSED"
    assert blocked["reason"] == "MEDIA_GOVERNANCE_BYPASS_ATTEMPT"
    assert blocked["adversarial_governance_audit_visible"] is True
    assert blocked["silent_pass"] is False


def test_media_evidence_bundle_is_reference_only_and_non_production() -> None:
    bundle = json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))

    assert bundle["bundle_name"] == "USBAY Media Governance Demo Evidence Bundle"
    assert bundle["non_production_demo"] is True
    assert bundle["reference_only"] is True
    assert bundle["contains_raw_media"] is False
    assert bundle["contains_personal_data"] is False
    assert bundle["contains_copyrighted_payloads"] is False
    assert bundle["contains_contract_payloads"] is False
    assert bundle["contains_credentials"] is False
    assert bundle["network_calls_required"] is False

    references = bundle["manifest_references"]
    assert len(references) == 18
    assert all(reference["path"].endswith(".json") for reference in references)
    assert all(reference["reference_only"] is True for reference in references)
    assert all((ROOT / reference["path"]).exists() for reference in references)
    assert _contains_forbidden_payload(bundle) is False


def test_media_demo_hygiene_blocks_payloads_credentials_network_and_runtime_mutation() -> None:
    governed_paths = [
        ROOT / "artifacts" / "media-governance-demo-evidence-bundle.json",
        ROOT / "artifacts" / "media-redteam-governance-manifest.json",
        ROOT / "artifacts" / "media-immutable-evidence-manifest.json",
        ROOT / "artifacts" / "media-lifecycle-orchestration-manifest.json",
        ROOT / "artifacts" / "media-dashboard-export-manifest.json",
        ROOT / "artifacts" / "media-crypto-authority-manifest.json",
        ROOT / "docs" / "media-governance-demo-evidence-bundle.md",
        ROOT / "docs" / "media-governance-customer-demo.md",
        ROOT / "docs" / "media-governance-control-map.md",
        ROOT / "docs" / "media-redteam-governance.md",
        ROOT / "docs" / "media-immutable-evidence-governance.md",
        ROOT / "docs" / "media-lifecycle-orchestration-governance.md",
        ROOT / "docs" / "media-dashboard-export-governance.md",
        ROOT / "docs" / "media-cryptographic-authority-governance.md",
    ]

    for path in governed_paths:
        assert path.exists(), path
        if path.suffix == ".json":
            assert _contains_forbidden_payload(json.loads(path.read_text(encoding="utf-8"))) is False
        else:
            assert _contains_forbidden_payload(path.read_text(encoding="utf-8")) is False

    lifecycle_test = (ROOT / "tests" / "test_media_governance_lifecycle_e2e.py").read_text(encoding="utf-8")
    assert ("requests" + ".") not in lifecycle_test
    assert ("urllib" + ".") not in lifecycle_test
    assert ("socket" + ".") not in lifecycle_test
    assert ("subprocess" + ".") not in lifecycle_test
    assert "gateway/" not in json.loads(BUNDLE_PATH.read_text(encoding="utf-8"))["runtime_mutation_scope"]


def test_media_demo_tests_are_not_in_fast_production_readiness_path() -> None:
    workflow = FAST_PR_WORKFLOW.read_text(encoding="utf-8")

    assert "tests/test_media_governance_demo.py" not in workflow
    assert "tests/test_media_redteam_policy.py" not in workflow
    assert "tests/test_media_governance_lifecycle_e2e.py" not in workflow


def _provenance_decision(manifest: dict[str, Any], observed_hash: str) -> dict[str, Any]:
    if observed_hash != manifest.get("provenance_hash_placeholder"):
        return _fail_closed("MEDIA_PROVENANCE_HASH_MISMATCH")
    return {"decision": "PASS", "reason": "MEDIA_PROVENANCE_HASH_MATCH"}


def _approval_decision(approval: dict[str, Any]) -> dict[str, Any]:
    if approval.get("approved") is not True or approval.get("approver_count", 0) < 2:
        return _fail_closed("MEDIA_APPROVAL_MISSING")
    return {"decision": "PASS", "reason": "MEDIA_APPROVAL_CHAIN_VALID"}


def _timestamp_decision(timestamp: dict[str, Any]) -> dict[str, Any]:
    if timestamp.get("timestamp_verified") is not True:
        return _fail_closed("MEDIA_TIMESTAMP_MISSING")
    return {"decision": "PASS", "reason": "MEDIA_TIMESTAMP_VALID"}


def _contains_forbidden_payload(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_forbidden_payload(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_payload(item) for item in value)
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in FORBIDDEN_PAYLOAD_MARKERS)


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
